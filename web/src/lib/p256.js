// ─────────────────────────────────────────────────────────────────────────
//  The two pieces of P-256 arithmetic WebCrypto will not do for us.
//
//  WebCrypto signs and verifies, and that is what actually signs here — this
//  file does not implement ECDSA. It implements exactly two things WebCrypto
//  has no API for:
//
//    1. Scalar → public key. The published test key is defined by a derivation
//       ("the SHA-256 of a string"), not by a stored keypair, and importing a
//       private key as JWK needs the public coordinates alongside it. So the
//       point multiplication has to happen somewhere.
//
//    2. Low-S normalization. Wire spec §4 makes it REQUIRED on the signing
//       side, and WebCrypto — like RustCrypto, like Node — does not do it. A
//       signer that forgets emits a high-S signature about half the time, so it
//       appears to work and then fails verification for no visible reason.
//
//  Both are checked against `spec/vectors/test-key.json` in test/. If the point
//  multiplication is wrong, the derived device_id will not match the committed
//  one and the test fails loudly.
// ─────────────────────────────────────────────────────────────────────────
import { bigintToBytes, bytesToBigint, concatBytes } from './encoding.js'

/** The NIST P-256 field prime. */
export const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn
/** The order of the base point. */
export const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
/** Signatures with `s` above this are the malleable half — spec §4. */
export const HALF_N = N >> 1n

const A = P - 3n
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n

const mod = (v, m = P) => ((v % m) + m) % m

/** Modular inverse by the extended Euclidean algorithm. */
function inverse(value, m = P) {
  let [old_r, r] = [mod(value, m), m]
  let [old_s, s] = [1n, 0n]
  while (r !== 0n) {
    const q = old_r / r
    ;[old_r, r] = [r, old_r - q * r]
    ;[old_s, s] = [s, old_s - q * s]
  }
  if (old_r !== 1n) throw new Error('value is not invertible')
  return mod(old_s, m)
}

// Points are `null` for the identity, or `{ x, y }` in affine coordinates.
// Affine costs one inversion per step, which is the slow way to do this — but
// it runs once at load to derive a single public key, and it is the version a
// reader can check against the textbook formulas.
function double(p) {
  if (p === null || p.y === 0n) return null
  const lambda = mod((3n * p.x * p.x + A) * inverse(2n * p.y))
  const x = mod(lambda * lambda - 2n * p.x)
  return { x, y: mod(lambda * (p.x - x) - p.y) }
}

function add(p, q) {
  if (p === null) return q
  if (q === null) return p
  if (p.x === q.x) return p.y === q.y ? double(p) : null
  const lambda = mod((q.y - p.y) * inverse(q.x - p.x))
  const x = mod(lambda * lambda - p.x - q.x)
  return { x, y: mod(lambda * (p.x - x) - p.y) }
}

function multiply(scalar, point) {
  let result = null
  let addend = point
  let k = mod(scalar, N)
  while (k > 0n) {
    if (k & 1n) result = add(result, addend)
    addend = double(addend)
    k >>= 1n
  }
  return result
}

/**
 * The public key for a private scalar, as SEC1 **uncompressed** bytes.
 *
 * `0x04 || X || Y`, 65 bytes. The prefix is not decoration: spec §4.2 hashes
 * this exact encoding to get `device_id`, and both plausible alternatives — the
 * 33-byte compressed form, or the bare 64-byte `X || Y` a secure element hands
 * back — produce a device_id that matches nothing, silently.
 */
export function publicKeySec1(privateScalar) {
  const point = multiply(privateScalar, { x: GX, y: GY })
  if (point === null) throw new Error('private scalar is zero mod n')
  return concatBytes(new Uint8Array([0x04]), bigintToBytes(point.x, 32), bigintToBytes(point.y, 32))
}

/**
 * Force `s` into the low half of the order.
 *
 * REQUIRED of signers by spec §4, and the half everyone forgets. ECDSA is
 * malleable — for any valid `(r, s)`, `(r, n - s)` is equally valid — and these
 * signatures are kept as evidence. Without this rule a third party can mint a
 * second, different, equally valid signature over the same approval, which is a
 * gift to anyone arguing about what an audit log shows.
 */
export function normalizeLowS(signature) {
  if (signature.length !== 64) throw new Error(`signature is ${signature.length} bytes, expected 64`)
  const s = bytesToBigint(signature.subarray(32, 64))
  if (s <= HALF_N) return signature
  return concatBytes(signature.subarray(0, 32), bigintToBytes(N - s, 32))
}

/** Whether `s` is already in the low half — what a verifier checks. */
export function isLowS(signature) {
  return bytesToBigint(signature.subarray(32, 64)) <= HALF_N
}
