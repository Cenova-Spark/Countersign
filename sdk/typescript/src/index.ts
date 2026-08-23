/**
 * Countersign for TypeScript.
 *
 * Two halves, and most consumers want only one:
 *
 * * **Verification** — {@link verifyForExecution} and friends. No daemon, no
 *   USB, no network, no dependencies. This is what goes in a GitHub Action, a
 *   Vault plugin, or a service that checks an approval against a registered
 *   public key.
 * * **Asking** — {@link Client}. What a Node agent or a VS Code extension uses
 *   to request an approval from a local `signetd`.
 *
 * Zero runtime dependencies, on purpose. Everything is built on `node:crypto`,
 * `node:net` and `node:fs`. A library people are meant to embed in security
 * infrastructure should not drag a tree in with it.
 */

export {
  b64urlDecode,
  b64urlEncode,
  bytesEqual,
  EncodingError,
  hexDecode,
  hexEncode,
} from "./encoding.ts";

export { canonicalize, canonicalizeText, findDuplicateKey, JcsError } from "./jcs.ts";

export {
  digestDisplay,
  digestOfJson,
  digestOfValue,
  digestShort,
  fingerprintUri,
  normalizeUri,
  VERSION,
} from "./request.ts";

export type {
  ApprovalEnvelope,
  Bundle,
  Decision,
  DeviceSignature,
  Request,
  Requester,
  Target,
} from "./request.ts";

export {
  defaultPolicy,
  FileCounters,
  isLowS,
  MemoryCounters,
  NoCounterStore,
  Registry,
  signingPayload,
  verifyBundle,
  verifyForExecution,
  verifySignatures,
  VerifyError,
} from "./verify.ts";

export type {
  Acceptance,
  CounterStore,
  DeviceStatus,
  EnrolledDevice,
  Execution,
  Operator,
  Verified,
  VerifiedSigner,
  VerifyPolicy,
} from "./verify.ts";

export { Client, ClientError, socketPath } from "./client.ts";
export type {
  ApprovalRequestInput,
  ApprovalResponse,
  DeviceStatusResponse,
} from "./client.ts";
