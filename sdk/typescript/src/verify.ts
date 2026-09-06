/**
 * Verification: registry, policy, replay defence, and the execution binding.
 *
 * Nothing here talks to a daemon, a USB device, or a network. That is what lets
 * a GitHub Action, a Vault plugin or a Node service check an approval against a
 * registered public key without linking any of the rest of this.
 */

import { createHash, createPublicKey, verify as nodeVerify } from "node:crypto";
import { writeFileSync, readFileSync, mkdirSync, renameSync, existsSync } from "node:fs";
import { dirname } from "node:path";

import { b64urlDecode, b64urlEncode, hexDecode, hexEncode } from "./encoding.ts";
import type { ApprovalEnvelope, DeviceSignature } from "./request.ts";
import { digestOfJson } from "./request.ts";

/**
 * The domain separator prefixed to every signed payload, so a Countersign
 * signature can never be replayed as a signature over some other protocol's
 * bytes that happen to share a suffix.
 */
const DOMAIN = Buffer.from("countersign-v1\0", "utf8");

/** The order of the P-256 curve. */
const CURVE_ORDER = BigInt(
  "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
);
/** `n/2`. A signature with `s` above this is high-S. */
const HALF_ORDER = CURVE_ORDER >> 1n;

export type VerifyErrorKind =
  | "not_approved"
  | "digest_mismatch"
  | "statement_mismatch"
  | "target_mismatch"
  | "action_mismatch"
  | "unknown_device"
  | "test_key_rejected"
  | "class_rejected"
  | "class_mismatch"
  | "enclave_without_proof"
  | "device_id_mismatch"
  | "device_revoked"
  | "bad_signature"
  | "high_s"
  | "counter_regression"
  | "stale"
  | "threshold"
  | "operator_threshold"
  | "unknown_operator"
  | "duplicate_device"
  | "store"
  | "malformed";

export class VerifyError extends Error {
  readonly kind: VerifyErrorKind;

  constructor(message: string, kind: VerifyErrorKind) {
    super(message);
    this.name = "VerifyError";
    this.kind = kind;
  }
}

export interface Operator {
  subject: string;
  display?: string;
}

export type DeviceStatus =
  | { state: "active" }
  | { state: "revoked"; at_unix_ms: number; at_counter?: number; reason?: string };

/**
 * What kind of thing holds the key — and therefore how much its signature
 * proves. See `spec/device-classes-v1.md`.
 *
 * `signet` is the hardware: the full claim. `enclave` is a platform secure
 * enclave behind a biometric check on every use — a real approval with a
 * smaller claim. `test` is a published key and proves nothing.
 *
 * The class is a property of the **enrollment**, never of the signature. A
 * verifier learns it from a record it already trusts, and from nowhere else.
 */
export type DeviceClass = "signet" | "enclave" | "test";

export interface EnrolledDevice {
  device_id: string;
  /** SEC1 uncompressed, 65 bytes. */
  public_key: Uint8Array;
  /** Whether this is a **published** test key. Refused unless opted into. */
  is_test_key: boolean;
  /** What kind of thing holds the key. Always agrees with `is_test_key`. */
  class: DeviceClass;
  operator?: Operator;
  status: DeviceStatus;
}

/**
 * An enrollment record as it appears in a roster (`spec/enrollment-v1.md` §3,
 * `spec/device-classes-v1.md` §4). Only the fields a verifier reads.
 */
export interface EnrollmentRecord {
  device_id?: string;
  /** SEC1 uncompressed, lowercase hex. */
  public_key_hex: string;
  /** Absent on rosters issued before classes existed; resolved from `is_test_key`. */
  class?: DeviceClass;
  is_test_key?: boolean;
  operator?: Operator;
  status?: DeviceStatus;
  /** The countersigned ceremony. Mandatory for an `enclave` record. */
  proof?: unknown;
}

function deviceIdOf(publicKey: Uint8Array): string {
  return hexEncode(new Uint8Array(createHash("sha256").update(publicKey).digest()));
}

/**
 * Resolve a record's class and test flag together, refusing disagreement.
 *
 * A record with no class reads as `test` when flagged and `signet` otherwise,
 * so nothing already issued changes meaning. A record that says both is lying
 * in one of two places, and a verifier cannot tell which.
 */
function resolveClass(
  cls: DeviceClass | undefined,
  isTestKey: boolean | undefined,
): { class: DeviceClass; is_test_key: boolean } {
  const resolved: DeviceClass = cls ?? (isTestKey ? "test" : "signet");
  const flag = isTestKey ?? resolved === "test";
  if ((resolved === "test") !== flag) {
    throw new VerifyError(
      `record says class ${resolved} but is_test_key is ${flag}; one of them is wrong and a ` +
        `verifier cannot tell which`,
      "class_mismatch",
    );
  }
  return { class: resolved, is_test_key: flag };
}

/** The set of keys a verifier will accept. */
export class Registry {
  private readonly devices = new Map<string, EnrolledDevice>();

  /**
   * Enroll a key. `device_id` is derived, never supplied.
   *
   * The class defaults to `signet`, or `test` when `is_test_key` is set. Give
   * a phone or laptop key `class: "enclave"`.
   */
  enroll(publicKey: Uint8Array, options: Partial<Omit<EnrolledDevice, "public_key">> = {}): this {
    const deviceId = deviceIdOf(publicKey);
    const { class: cls, is_test_key } = resolveClass(options.class, options.is_test_key);
    this.devices.set(deviceId, {
      device_id: deviceId,
      public_key: publicKey,
      is_test_key,
      class: cls,
      operator: options.operator,
      status: options.status ?? { state: "active" },
    });
    return this;
  }

  /**
   * Enroll from a roster record, carrying its owner, class and status across.
   *
   * Refuses a record whose `device_id` is not the digest of its own key, whose
   * `class` and `is_test_key` disagree, or which is `enclave` with no proof —
   * the proof is the only evidence the key signs under a presence check at all.
   * This does not verify the proof's signature; a roster is verified as a
   * whole before its records are trusted.
   */
  enrollRecord(record: EnrollmentRecord): this {
    const publicKey = hexDecode(record.public_key_hex);
    const derived = deviceIdOf(publicKey);
    if (record.device_id !== undefined && record.device_id !== derived) {
      throw new VerifyError(
        `record claims device_id ${record.device_id} but its key derives ${derived}`,
        "device_id_mismatch",
      );
    }
    const { class: cls } = resolveClass(record.class, record.is_test_key);
    if (cls === "enclave" && record.proof === undefined) {
      throw new VerifyError(
        "an enclave record must carry its enrollment proof — without it nothing shows the key " +
          "can sign under a presence check",
        "enclave_without_proof",
      );
    }
    return this.enroll(publicKey, {
      class: cls,
      is_test_key: cls === "test",
      operator: record.operator,
      status: record.status,
    });
  }

  get(deviceId: string): EnrolledDevice | undefined {
    return this.devices.get(deviceId);
  }

  get size(): number {
    return this.devices.size;
  }

  /** Every device enrolled to one person, in a stable order. */
  devicesFor(subject: string): EnrolledDevice[] {
    return [...this.devices.values()]
      .filter((d) => d.operator?.subject === subject)
      .sort((a, b) => (a.device_id < b.device_id ? -1 : 1));
  }
}

/**
 * Why this verifier is checking — which decides how a revoked device is read.
 *
 * `now` refuses a revoked device outright. `{ asOf }` accepts one revoked after
 * that instant, because it was trusted when it signed. Conflating them costs
 * one of two things: either revoking a lost device fails to stop it, or it
 * silently invalidates years of legitimate approvals.
 */
export type Acceptance = { mode: "now" } | { mode: "as_of"; unixMs: number };

export interface VerifyPolicy {
  requiredSignatures: number;
  /**
   * Whether signatures from **published test keys** count.
   *
   * `false` by default, and that default is the safety mechanism that makes a
   * software mock acceptable at all: a mock left enabled fails loudly here
   * rather than silently passing.
   */
  acceptTestKeys: boolean;
  /**
   * Which kinds of device may authorize something here.
   *
   * Defaults to `["signet", "enclave"]`. Including `enclave` is the product
   * decision `spec/device-classes-v1.md` makes: a biometric-gated enclave key
   * is a real approval with a smaller claim. An operator who wants hardware
   * only passes `["signet"]` and nothing else changes.
   *
   * `test` is never in the default. Listing it is equivalent to
   * `acceptTestKeys`; a test key counts if either says so.
   */
  acceptClasses: DeviceClass[];
  /**
   * Whether the threshold counts distinct **people** rather than devices.
   *
   * Set this for any genuine dual-control rule. Two signatures alone means two
   * devices, and one person who owns two Signets satisfies it on their own.
   */
  requireDistinctOperators: boolean;
  acceptance: Acceptance;
  maxClockSkewMs?: number;
}

export function defaultPolicy(overrides: Partial<VerifyPolicy> = {}): VerifyPolicy {
  return {
    requiredSignatures: 1,
    acceptTestKeys: false,
    acceptClasses: ["signet", "enclave"],
    requireDistinctOperators: false,
    acceptance: { mode: "now" },
    ...overrides,
  };
}

/**
 * Per-device high-water marks for the monotonic counter.
 *
 * `record` may throw, and verification fails when it does. Accepting an
 * approval you cannot remember is strictly worse than refusing it, so a full
 * disk must produce a refusal rather than a silent replay window.
 */
export interface CounterStore {
  highest(deviceId: string): number | undefined;
  record(deviceId: string, counter: number): void;
}

/** In-memory. Fine for one long-lived process; forgets on restart. */
export class MemoryCounters implements CounterStore {
  private readonly marks = new Map<string, number>();
  highest(deviceId: string): number | undefined {
    return this.marks.get(deviceId);
  }
  record(deviceId: string, counter: number): void {
    this.marks.set(deviceId, Math.max(this.marks.get(deviceId) ?? counter, counter));
  }
}

/** Never remembers anything. Named for what it costs. */
export class NoCounterStore implements CounterStore {
  highest(): number | undefined {
    return undefined;
  }
  record(): void {}
}

/**
 * A file-backed store that survives a restart.
 *
 * Writes atomically — temp file, then rename — so a crash leaves either the
 * complete old state or the complete new one. A corrupt file throws rather
 * than being replaced with an empty one, which would silently reopen the replay
 * window the file exists to close.
 */
export class FileCounters implements CounterStore {
  private marks: Record<string, number>;
  private readonly path: string;

  constructor(path: string) {
    this.path = path;
    mkdirSync(dirname(path), { recursive: true });
    if (existsSync(path)) {
      const text = readFileSync(path, "utf8");
      this.marks = text.trim().length === 0 ? {} : (JSON.parse(text) as Record<string, number>);
    } else {
      this.marks = {};
    }
  }

  highest(deviceId: string): number | undefined {
    return this.marks[deviceId];
  }

  record(deviceId: string, counter: number): void {
    const current = this.marks[deviceId];
    if (current !== undefined && current >= counter) return;
    this.marks[deviceId] = Math.max(current ?? counter, counter);

    const temp = `${this.path}.tmp`;
    writeFileSync(temp, `${JSON.stringify(this.marks, null, 2)}\n`, { flush: true });
    renameSync(temp, this.path);
  }
}

export interface VerifiedSigner {
  deviceId: string;
  operator?: Operator;
  /** What kind of thing signed. A Signet and a phone are not the same approval. */
  class: DeviceClass;
  counter: number;
  deviceUnixMs: number;
}

export interface Verified {
  requestDigest: string;
  signers: VerifiedSigner[];
  /** The people behind the signatures, skipping devices with no known owner. */
  operators: string[];
}

/** What the caller is about to do, and therefore what the approval must cover. */
export interface Execution {
  statement: string;
  uriFingerprint: string;
  action?: string;
}

/** Whether a signature is well-formed and low-S. */
export function isLowS(signature: Uint8Array): boolean {
  if (signature.length !== 64) return false;
  const r = signature.subarray(0, 32);
  const s = signature.subarray(32);
  if (r.every((b) => b === 0) || s.every((b) => b === 0)) return false;
  return BigInt(`0x${hexEncode(s)}`) <= HALF_ORDER;
}

/**
 * Build the bytes a device signs: domain separator, digest, counter, time.
 *
 * The counter and timestamp are inside the signature rather than beside it, so
 * neither can be edited after the fact by anyone holding the bundle.
 */
export function signingPayload(
  requestDigestHex: string,
  counter: number,
  deviceUnixMs: number,
): Uint8Array {
  const digest = hexDecode(requestDigestHex);
  if (digest.length !== 32) {
    throw new VerifyError(`request_digest is ${digest.length} bytes, expected 32`, "malformed");
  }
  const out = Buffer.alloc(DOMAIN.length + 32 + 16);
  DOMAIN.copy(out, 0);
  Buffer.from(digest).copy(out, DOMAIN.length);
  out.writeBigUInt64BE(BigInt(counter), DOMAIN.length + 32);
  out.writeBigUInt64BE(BigInt(deviceUnixMs), DOMAIN.length + 40);
  return new Uint8Array(out);
}

/** Verify an ECDSA-P256-SHA-256 signature over `message`. */
function verifySignature(
  publicKeySec1: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKeySec1.length !== 65 || publicKeySec1[0] !== 0x04) return false;
  try {
    const key = createPublicKey({
      key: {
        kty: "EC",
        crv: "P-256",
        x: b64urlEncode(publicKeySec1.subarray(1, 33)),
        y: b64urlEncode(publicKeySec1.subarray(33, 65)),
      },
      format: "jwk",
    });
    // `ieee-p1363` is exactly the `r || s` the spec names. The default is DER.
    return nodeVerify("sha256", message, { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    return false;
  }
}

function statusPermits(status: DeviceStatus, acceptance: Acceptance, counter: number): boolean {
  if (status.state === "active") return true;
  if (acceptance.mode === "now") return false;
  // A counter comparison beats a timestamp comparison whenever one is
  // available: it survives a clock that was wrong.
  if (status.at_counter !== undefined) return counter < status.at_counter;
  return acceptance.unixMs < status.at_unix_ms;
}

/**
 * Verify signatures against a `request_digest` alone.
 *
 * The statement is not needed and not accepted. That is what lets an audit
 * trail be cryptographically checkable while carrying no query text at all.
 */
export function verifySignatures(
  requestDigest: string,
  signatures: DeviceSignature[],
  registry: Registry,
  policy: VerifyPolicy,
  counters: CounterStore,
  nowUnixMs?: number,
): Verified {
  const counted: VerifiedSigner[] = [];

  for (const sig of signatures) {
    if (counted.some((s) => s.deviceId === sig.device_id)) {
      throw new VerifyError(`device ${sig.device_id} signed more than once`, "duplicate_device");
    }

    const device = registry.get(sig.device_id);
    if (!device) {
      throw new VerifyError(`device ${sig.device_id} is not enrolled`, "unknown_device");
    }

    // Before the cryptography, and before revocation: a statement about what
    // the policy will listen to at all. A device that says "test" in either
    // field is treated as one; disagreement fails toward refusal.
    const cls: DeviceClass = device.is_test_key ? "test" : device.class;
    const accepted =
      (cls === "test" && policy.acceptTestKeys) || policy.acceptClasses.includes(cls);
    if (!accepted) {
      if (cls === "test") {
        throw new VerifyError(
          `device ${sig.device_id} is a published test key; production verification refuses these`,
          "test_key_rejected",
        );
      }
      throw new VerifyError(
        `device ${sig.device_id} is a ${cls}-class device, which this verifier's policy does ` +
          `not accept`,
        "class_rejected",
      );
    }

    // Checked before the cryptography, because a revoked device's signature is
    // perfectly valid — that is exactly the problem.
    if (!statusPermits(device.status, policy.acceptance, sig.counter)) {
      const why = device.status.state === "revoked" ? device.status.reason : undefined;
      throw new VerifyError(
        `device ${sig.device_id} was revoked${why ? `: ${why}` : ""}`,
        "device_revoked",
      );
    }

    const raw = b64urlDecode(sig.signature);
    if (raw.length !== 64) {
      throw new VerifyError(`signature from ${sig.device_id} is not 64 bytes`, "bad_signature");
    }
    if (!isLowS(raw)) {
      throw new VerifyError(`signature from ${sig.device_id} is not low-S`, "high_s");
    }

    const tbs = signingPayload(requestDigest, sig.counter, sig.device_unix_ms);
    if (!verifySignature(device.public_key, tbs, raw)) {
      throw new VerifyError(`signature from ${sig.device_id} did not verify`, "bad_signature");
    }

    const highest = counters.highest(sig.device_id);
    if (highest !== undefined && sig.counter <= highest) {
      throw new VerifyError(
        `device ${sig.device_id} counter ${sig.counter} is not above the highest seen (${highest})`,
        "counter_regression",
      );
    }

    if (policy.maxClockSkewMs !== undefined && nowUnixMs !== undefined) {
      const skew = Math.abs(nowUnixMs - sig.device_unix_ms);
      if (skew > policy.maxClockSkewMs) {
        throw new VerifyError(
          `device ${sig.device_id} clock is ${skew} ms outside the window`,
          "stale",
        );
      }
    }

    counted.push({
      deviceId: sig.device_id,
      operator: device.operator,
      class: cls,
      counter: sig.counter,
      deviceUnixMs: sig.device_unix_ms,
    });
  }

  if (policy.requireDistinctOperators) {
    const subjects = new Set<string>();
    for (const signer of counted) {
      if (!signer.operator) {
        throw new VerifyError(
          `device ${signer.deviceId} has no enrolled operator, so dual control cannot be ` +
            `established`,
          "unknown_operator",
        );
      }
      subjects.add(signer.operator.subject);
    }
    if (subjects.size < policy.requiredSignatures) {
      throw new VerifyError(
        `signatures came from ${subjects.size} distinct person(s), policy requires ` +
          `${policy.requiredSignatures}`,
        "operator_threshold",
      );
    }
  } else if (counted.length < policy.requiredSignatures) {
    throw new VerifyError(
      `${counted.length} valid signature(s), policy requires ${policy.requiredSignatures}`,
      "threshold",
    );
  }

  // Only recorded once everything has passed, so a rejected bundle cannot burn
  // a counter value and lock out the approval that follows it. A store that
  // throws here fails the verification, which is the point.
  for (const sig of signatures) {
    try {
      counters.record(sig.device_id, sig.counter);
    } catch (e) {
      throw new VerifyError(
        `refused: the replay defence could not be recorded (${(e as Error).message}). An ` +
          `approval that cannot be remembered could be replayed after a restart`,
        "store",
      );
    }
  }

  return {
    requestDigest,
    signers: counted,
    operators: counted.flatMap((s) => (s.operator ? [s.operator.subject] : [])),
  };
}

/** Verify a bundle's signatures against the request it travels with. */
export function verifyBundle(
  envelope: ApprovalEnvelope,
  registry: Registry,
  policy: VerifyPolicy,
  counters: CounterStore,
  nowUnixMs?: number,
): Verified {
  if (envelope.bundle.decision !== "approved") {
    throw new VerifyError(`not approved: ${envelope.bundle.decision}`, "not_approved");
  }

  // Recomputed from the request as received, never from a re-serialization.
  const computed = digestOfJson(envelope.request_json);
  if (computed !== envelope.bundle.request_digest) {
    throw new VerifyError(
      `bundle digest ${envelope.bundle.request_digest} does not cover this request ` +
        `(computed ${computed})`,
      "digest_mismatch",
    );
  }

  return verifySignatures(
    computed,
    envelope.bundle.signatures,
    registry,
    policy,
    counters,
    nowUnixMs,
  );
}

/**
 * Verify that an approval covers **this** execution.
 *
 * The three bindings this adds over {@link verifyBundle} are what make a
 * countersignature mean anything at the point of use: the statement about to
 * run is the one that was displayed, on the target that was displayed, for the
 * action that was approved. Without them a verifier confirms only that *some*
 * approval exists, which an agent holding one can reuse for everything after.
 */
export function verifyForExecution(
  envelope: ApprovalEnvelope,
  execution: Execution,
  registry: Registry,
  policy: VerifyPolicy,
  counters: CounterStore,
  nowUnixMs?: number,
): Verified {
  let request: { statement: string; target: { uri_fingerprint: string }; action: string };
  try {
    request = JSON.parse(envelope.request_json);
  } catch (e) {
    throw new VerifyError(`malformed: ${(e as Error).message}`, "malformed");
  }

  // Byte for byte. Normalizing before comparison here would be the whole
  // vulnerability: `DELETE FROM t WHERE id=1` approved, `DELETE FROM t` run.
  if (request.statement !== execution.statement) {
    throw new VerifyError(
      "the approved statement is not the one about to run",
      "statement_mismatch",
    );
  }

  if (request.target.uri_fingerprint !== execution.uriFingerprint) {
    throw new VerifyError(
      `approval was for target ${request.target.uri_fingerprint}, not ${execution.uriFingerprint}`,
      "target_mismatch",
    );
  }

  if (execution.action !== undefined && request.action !== execution.action) {
    throw new VerifyError(
      `approval was for action ${request.action}, not ${execution.action}`,
      "action_mismatch",
    );
  }

  return verifyBundle(envelope, registry, policy, counters, nowUnixMs);
}
