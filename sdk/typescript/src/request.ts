/**
 * The approval request, its digest, and target fingerprinting.
 *
 * See `spec/countersign-v1.md` §2 and §3.
 */

import { createHash } from "node:crypto";

import { hexEncode } from "./encoding.ts";
import { canonicalize, canonicalizeText } from "./jcs.ts";

/** The protocol version this SDK speaks. */
export const VERSION = 1;

/**
 * Who is asking. Every field is a **claim** — a requester can say it is
 * anything, so nothing here should ever relax a policy.
 */
export interface Requester {
  id: string;
  instance: string;
  pid?: number;
}

/**
 * What is being acted on.
 *
 * Note the absence of a label. The environment is assigned by the daemon from
 * local config, so a requester cannot claim it is talking to dev. Do not add
 * one — see spec §2.1.
 */
export interface Target {
  kind: string;
  /** Lowercase hex SHA-256 of the normalized target URI. */
  uri_fingerprint: string;
}

export interface Request {
  v: number;
  /** 32 CSPRNG bytes, base64url unpadded. Single use. */
  nonce: string;
  requester: Requester;
  /** A namespaced verb: `sql.execute`, `terraform.apply`, `npm.publish`. */
  action: string;
  target: Target;
  /** The **full** statement text. Never truncated. */
  statement: string;
  /** Requester-supplied and unverified. An agent can lie about row counts. */
  advisory?: unknown;
  ttl_ms: number;
}

export type Decision = "approved" | "aborted" | "expired" | "refused" | "no_device";

export interface DeviceSignature {
  device_id: string;
  counter: number;
  device_unix_ms: number;
  /** base64url unpadded, `r || s`. */
  signature: string;
  /**
   * How long the human held before the detent committed.
   *
   * **Telemetry only.** A servo produces any dwell time you ask it for, so this
   * is not evidence a human was present. Nothing may branch on it.
   */
  dwell_ms?: number;
}

export interface Bundle {
  v: number;
  decision: Decision;
  request_digest: string;
  signatures: DeviceSignature[];
}

/**
 * A bundle together with the request it covers.
 *
 * The request travels as **raw JSON, exactly as sent**. Re-serializing through
 * your own types drops any field this version does not know about, and a digest
 * over a different field set will not match.
 */
export interface ApprovalEnvelope {
  request_json: string;
  bundle: Bundle;
}

function sha256(bytes: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

/** `SHA-256(jcs(value))`, lowercase hex. */
export function digestOfValue(value: unknown): string {
  return hexEncode(sha256(canonicalize(value)));
}

/**
 * `SHA-256(jcs(json))`, lowercase hex, from the request **as received**.
 *
 * Prefer this in a verifier. Re-serializing through your own types silently
 * drops fields, and a digest over a field set that differs from the sender's is
 * a digest that will not match.
 */
export function digestOfJson(json: string): string {
  return hexEncode(sha256(canonicalizeText(json)));
}

/** The first 12 hex characters — what the device shows and the client must too. */
export function digestShort(digestHex: string): string {
  return digestHex.slice(0, 12);
}

/**
 * Group the first 12 characters into three blocks of four, as the device
 * renders them: `a91f 4c2e 7b03`.
 *
 * The grouping is not decoration. A human comparing two 12-character hex runs
 * character by character gives up; comparing three short blocks is a glance.
 */
export function digestDisplay(digestHex: string): string {
  const short = digestShort(digestHex);
  return [short.slice(0, 4), short.slice(4, 8), short.slice(8, 12)].join(" ");
}

/** Default ports, so omitting one does not create a second identity. */
const DEFAULT_PORTS: Record<string, number> = {
  postgres: 5432,
  postgresql: 5432,
  mysql: 3306,
  mariadb: 3306,
  mongodb: 27017,
  redis: 6379,
  rediss: 6379,
  mssql: 1433,
  sqlserver: 1433,
  oracle: 1521,
  clickhouse: 8123,
  cassandra: 9042,
  cql: 9042,
  neo4j: 7687,
  bolt: 7687,
  elasticsearch: 9200,
  elastic: 9200,
  influxdb: 8086,
  influx: 8086,
  cockroachdb: 26257,
  cockroach: 26257,
  https: 443,
  http: 80,
};

/**
 * The canonical form {@link fingerprintUri} hashes.
 *
 * Exposed for diagnostics — "why do these two fingerprints differ" is otherwise
 * unanswerable. Must stay byte-identical to the Rust implementation, which is
 * what the shared vectors check.
 */
export function normalizeUri(uri: string): string {
  const split = uri.indexOf("://");
  if (split < 0) {
    // No scheme: nothing to normalize confidently, so hash it as given rather
    // than guessing a shape and merging two distinct targets.
    return uri.trim();
  }

  const scheme = uri.slice(0, split).toLowerCase();
  const rest = uri.slice(split + 3);

  const authorityEnd = ((): number => {
    const candidates = [rest.indexOf("/"), rest.indexOf("?"), rest.indexOf("#")].filter(
      (i) => i >= 0,
    );
    return candidates.length > 0 ? Math.min(...candidates) : rest.length;
  })();

  const authority = rest.slice(0, authorityEnd);
  const after = rest.slice(authorityEnd);

  // Userinfo is everything before the LAST '@' — a password may contain one.
  const at = authority.lastIndexOf("@");
  const hostport = at >= 0 ? authority.slice(at + 1) : authority;

  const [host, port] = splitHostPort(hostport);
  const effectivePort = port ?? String(DEFAULT_PORTS[scheme] ?? 0);

  const pathEnd = ((): number => {
    const candidates = [after.indexOf("?"), after.indexOf("#")].filter((i) => i >= 0);
    return candidates.length > 0 ? Math.min(...candidates) : after.length;
  })();
  const path = after.slice(0, pathEnd).replace(/\/+$/, "");

  return `${scheme}://${host.toLowerCase()}:${effectivePort}${path}`;
}

function splitHostPort(value: string): [string, string | null] {
  if (value.startsWith("[")) {
    const close = value.indexOf("]");
    if (close >= 0) {
      const host = value.slice(0, close + 1);
      const rest = value.slice(close + 1);
      const port = rest.startsWith(":") ? rest.slice(1) : "";
      return [host, port.length > 0 ? port : null];
    }
  }
  const colon = value.lastIndexOf(":");
  if (colon >= 0) {
    const port = value.slice(colon + 1);
    if (port.length > 0 && /^[0-9]+$/.test(port)) {
      return [value.slice(0, colon), port];
    }
  }
  return [value, null];
}

/**
 * Normalize a connection URI and return its lowercase-hex SHA-256.
 *
 * Credentials are stripped **before** hashing, which is the point: the daemon
 * recognises "the database I labelled prod" without ever receiving a password.
 */
export function fingerprintUri(uri: string): string {
  return hexEncode(sha256(normalizeUri(uri)));
}
