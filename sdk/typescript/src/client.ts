/**
 * A client for the `signetd` control socket.
 *
 * What a Node agent, a VS Code extension, or a CI step uses to *ask* for an
 * approval. It holds no key and makes no decisions — if it were compromised the
 * worst it could do is ask for approvals a human would then see and refuse.
 *
 * # Hold one connection
 *
 * The daemon keys its requester-continuity check on the connection, because
 * that is the only thing about a caller it can verify. A client that reconnects
 * per call looks like a new requester every time and makes the operator
 * acknowledge a change on every single approval — the fatigue the check exists
 * to avoid. So: construct one of these per session and keep it.
 */

import { connect, type Socket } from "node:net";

import type { ApprovalEnvelope, Decision } from "./request.ts";

export interface ApprovalRequestInput {
  action: string;
  /**
   * The connection URI. Fingerprinted by the daemon on arrival and then
   * dropped — never stored, logged, or written to the audit trail.
   *
   * Send `uriFingerprint` instead if you can compute it, and keep the
   * credential on your side of the socket entirely.
   */
  targetUri?: string;
  uriFingerprint?: string;
  targetKind?: string;
  statement: string;
  advisory?: unknown;
  requesterId?: string;
  requesterInstance?: string;
  ttlMs?: number;
}

export interface ApprovalResponse {
  decision: Decision;
  request_digest: string;
  /** The grouped 12 characters. **Show these to the user** — spec §6.1. */
  digest_short: string;
  environment: string;
  tier: string;
  severity: string;
  explanation: string;
  warnings: string[];
  /** Present only on `approved`. Hand this, whole, to a verifier. */
  envelope?: ApprovalEnvelope;
}

export interface DeviceStatusResponse {
  attached: boolean;
  device_id: string;
  kind: string;
  is_test_key: boolean;
  counter: number;
  environments: number;
}

export class ClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClientError";
  }
}

/** The default socket path, honouring the same env vars the Rust tools do. */
export function socketPath(): string {
  if (process.env.COUNTERSIGN_SOCK) return process.env.COUNTERSIGN_SOCK;
  const runtime = process.env.COUNTERSIGN_RUNTIME_DIR ?? process.env.XDG_RUNTIME_DIR;
  if (runtime) return `${runtime}/countersign.sock`;
  const home = process.env.HOME ?? ".";
  return `${home}/.config/countersign/run/countersign.sock`;
}

export class Client {
  private socket: Socket | null = null;
  private buffer = "";
  private nextId = 1;
  private readonly waiting = new Map<number, (line: unknown) => void>();
  private readonly path: string;

  constructor(path: string = socketPath()) {
    this.path = path;
  }

  private async ensure(): Promise<Socket> {
    if (this.socket && !this.socket.destroyed) return this.socket;

    return new Promise<Socket>((resolve, reject) => {
      const socket = connect(this.path);
      socket.setEncoding("utf8");

      socket.once("error", (e) =>
        reject(
          new ClientError(
            `cannot reach signetd at ${this.path} (${e.message}) — is it running? ` +
              `try \`signetd run\``,
          ),
        ),
      );

      socket.once("connect", () => {
        socket.removeAllListeners("error");
        socket.on("error", () => this.fail("connection error"));
        socket.on("close", () => this.fail("daemon closed the connection"));
        socket.on("data", (chunk: string) => this.onData(chunk));
        this.socket = socket;
        resolve(socket);
      });
    });
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    let newline: number;
    while ((newline = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      if (line.trim().length === 0) continue;

      let message: { id?: number; result?: unknown; error?: { message?: string } };
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      const resolve = message.id !== undefined ? this.waiting.get(message.id) : undefined;
      if (resolve) {
        this.waiting.delete(message.id!);
        resolve(message);
      }
    }
  }

  private fail(reason: string): void {
    for (const [, resolve] of this.waiting) {
      resolve({ error: { message: reason } });
    }
    this.waiting.clear();
    this.socket = null;
  }

  private async call(method: string, params: unknown): Promise<unknown> {
    const socket = await this.ensure();
    const id = this.nextId++;

    const answer = new Promise<{ result?: unknown; error?: { message?: string } }>((resolve) => {
      this.waiting.set(id, resolve as (v: unknown) => void);
    });

    socket.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    const message = await answer;

    if (message.error) {
      throw new ClientError(message.error.message ?? "unknown daemon error");
    }
    return message.result;
  }

  /**
   * Ask for a countersignature. Resolves when a human acts or the request
   * expires — which may be a while, because a person has to read something.
   *
   * A non-`approved` decision is a normal answer, not an exception. Check
   * `decision`; do not assume a resolved promise means yes.
   */
  async requestApproval(input: ApprovalRequestInput): Promise<ApprovalResponse> {
    return (await this.call("approval.request", {
      action: input.action,
      target_uri: input.targetUri,
      uri_fingerprint: input.uriFingerprint,
      target_kind: input.targetKind ?? "database",
      statement: input.statement,
      advisory: input.advisory,
      requester_id: input.requesterId ?? "countersign-sdk-ts",
      requester_instance: input.requesterInstance ?? "",
      ttl_ms: input.ttlMs,
    })) as ApprovalResponse;
  }

  async deviceStatus(): Promise<DeviceStatusResponse> {
    return (await this.call("device.status", null)) as DeviceStatusResponse;
  }

  async auditSummary(): Promise<{ entries: number; head: string }> {
    return (await this.call("audit.summary", null)) as { entries: number; head: string };
  }

  close(): void {
    this.socket?.end();
    this.socket = null;
  }
}
