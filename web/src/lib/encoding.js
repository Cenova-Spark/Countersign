// ─────────────────────────────────────────────────────────────────────────
//  Hex and base64url, strictly — the browser half of the SDK's encoding.ts.
//
//  Same rule as there: every decoder validates before it decodes. In a protocol
//  that hashes its own fields, accepting two spellings of the same bytes is how
//  one request ends up with two digests.
// ─────────────────────────────────────────────────────────────────────────

export class EncodingError extends Error {
  constructor(message) {
    super(message)
    this.name = 'EncodingError'
  }
}

const HEX = /^[0-9a-fA-F]*$/
const BASE64URL = /^[A-Za-z0-9_-]*$/

/** Lowercase hex. */
export function hexEncode(bytes) {
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

export function hexDecode(text) {
  if (text.length % 2 !== 0) throw new EncodingError('hex string has an odd length')
  if (!HEX.test(text)) throw new EncodingError('not valid hex')
  const out = new Uint8Array(text.length / 2)
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** base64url, unpadded — what the spec names for nonces and signatures. */
export function b64urlEncode(bytes) {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Decode unpadded base64url. Padding and the standard alphabet are refused. */
export function b64urlDecode(text) {
  if (!BASE64URL.test(text)) {
    throw new EncodingError('not valid unpadded base64url (padding and +/ are refused)')
  }
  if (text.length % 4 === 1) throw new EncodingError('impossible base64url length')
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4)
  const binary = atob(padded)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
  // Round-trip: `atob` decodes input it should have refused.
  if (b64urlEncode(out) !== text) {
    throw new EncodingError('base64url did not round-trip; input has trailing bits')
  }
  return out
}

/** Big-endian bytes of a bigint, left-padded to `length`. */
export function bigintToBytes(value, length) {
  const out = new Uint8Array(length)
  let v = value
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  if (v !== 0n) throw new EncodingError(`value does not fit in ${length} bytes`)
  return out
}

export function bytesToBigint(bytes) {
  let v = 0n
  for (const b of bytes) v = (v << 8n) | BigInt(b)
  return v
}

export function concatBytes(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}
