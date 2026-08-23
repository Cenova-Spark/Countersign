/**
 * Hex and base64url, strictly.
 *
 * Node's `Buffer` does both, but leniently: it accepts padding on base64url,
 * tolerates the standard alphabet, and silently truncates junk. That leniency
 * is fine for most things and wrong here — in a protocol that hashes its own
 * fields, accepting two spellings of the same bytes is how you end up with two
 * digests for one request. So every decoder validates before it decodes.
 */

export class EncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncodingError";
  }
}

const HEX = /^[0-9a-fA-F]*$/;
const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Lowercase hex. */
export function hexEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

export function hexDecode(text: string): Uint8Array {
  if (text.length % 2 !== 0) {
    throw new EncodingError("hex string has an odd length");
  }
  if (!HEX.test(text)) {
    throw new EncodingError("not valid hex");
  }
  return new Uint8Array(Buffer.from(text, "hex"));
}

/** base64url, unpadded — the encoding the spec names for nonces and signatures. */
export function b64urlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/**
 * Decode unpadded base64url.
 *
 * Padding and the standard alphabet are rejected rather than tolerated. The
 * spec says unpadded; accepting both spellings means the same bytes have two
 * encodings.
 */
export function b64urlDecode(text: string): Uint8Array {
  if (!BASE64URL.test(text)) {
    throw new EncodingError("not valid unpadded base64url (padding and +/ are refused)");
  }
  if (text.length % 4 === 1) {
    throw new EncodingError("impossible base64url length");
  }
  const decoded = new Uint8Array(Buffer.from(text, "base64url"));
  // Round-trip check: Buffer will happily decode input it should not have.
  if (b64urlEncode(decoded) !== text) {
    throw new EncodingError("base64url did not round-trip; input has trailing bits");
  }
  return decoded;
}

/** Compare two byte arrays without leaking length-dependent timing. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}
