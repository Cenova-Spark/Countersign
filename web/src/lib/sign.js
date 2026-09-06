// ─────────────────────────────────────────────────────────────────────────
//  What signs, in the browser.
//
//  This signs with a **published** test key — a second one, derived the same
//  way as `spec/vectors/test-key.json` but from a different string, so a remote
//  approval and a `--device=mock` approval do not collide on `device_id`. That
//  collision would matter: `counter` is per-device and must never go backwards
//  (spec §4.1), and two independent signers sharing an identity would trip a
//  verifier's replay defence for real reasons.
//
//  The key being public is the whole safety mechanism, and it is stronger than
//  a flag. A default verifier refuses anything this signs. Not "refuses unless
//  configured otherwise" — the bypass is not disabled, it is cryptographically
//  incapable of producing a production-valid approval. Wire spec §9 forbids a
//  software path to a valid signature, and this respects that by construction
//  rather than by promise.
//
//  If a phone is ever to produce a *real* approval, it does not happen here. It
//  happens with a non-extractable key in the phone's secure enclave, enrolled
//  as its own device class with its own weaker claim written down. That is a
//  spec change, not a code change.
// ─────────────────────────────────────────────────────────────────────────
import { b64urlEncode, bigintToBytes, bytesToBigint, concatBytes, hexDecode, hexEncode } from './encoding.js'
import { normalizeLowS, publicKeySec1 } from './p256.js'
import { canonicalize } from './jcs.js'

/**
 * The string this signet's private scalar is derived from.
 *
 * Deliberately shaped like `MockDevice`'s `TEST_KEY_DERIVATION` so the two are
 * recognisably the same kind of thing, and deliberately different so they are
 * not the same key.
 */
export const REMOTE_TEST_KEY_DERIVATION = 'countersign-v1 published test key · remote'

/** `"countersign-v1" || 0x00` — the domain separator from spec §4. */
const DOMAIN = new TextEncoder().encode('countersign-v1\0')

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
}

/**
 * Build the bytes a device signs: domain separator, digest, counter, time.
 *
 * The counter and timestamp live *inside* the signature rather than beside it,
 * so nobody holding the bundle can edit them afterwards.
 */
export function signingPayload(requestDigestHex, counter, deviceUnixMs) {
  const digest = hexDecode(requestDigestHex)
  if (digest.length !== 32) {
    throw new Error(`request_digest is ${digest.length} bytes, expected 32`)
  }
  return concatBytes(
    DOMAIN,
    digest,
    bigintToBytes(BigInt(counter), 8),
    bigintToBytes(BigInt(deviceUnixMs), 8),
  )
}

/** `request_digest = SHA-256(jcs(request))`, lowercase hex — spec §3. */
export async function requestDigest(request) {
  return hexEncode(await sha256(new TextEncoder().encode(canonicalize(request))))
}

/** The first 12 hex characters, grouped in fours — what the human compares. */
export function digestShort(digestHex) {
  return digestHex.slice(0, 12).replace(/(.{4})/g, '$1 ').trim()
}

let cached = null

/**
 * Load the remote signet's key.
 *
 * WebCrypto does the actual ECDSA; the only thing done by hand is deriving the
 * public point, because importing a private key as JWK needs the coordinates
 * and there is no WebCrypto API that turns a scalar into a point.
 */
export async function loadSignet() {
  if (cached) return cached

  const scalar = await sha256(new TextEncoder().encode(REMOTE_TEST_KEY_DERIVATION))
  const sec1 = publicKeySec1(bytesToBigint(scalar))
  const deviceId = hexEncode(await sha256(sec1))

  const key = await crypto.subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      d: b64urlEncode(scalar),
      x: b64urlEncode(sec1.subarray(1, 33)),
      y: b64urlEncode(sec1.subarray(33, 65)),
      ext: false,
    },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  )

  cached = { key, deviceId, publicKeySec1Hex: hexEncode(sec1), isTestKey: true }
  return cached
}

/**
 * Countersign a request digest.
 *
 * Returns the `DeviceSignature` shape from spec §2, ready to drop into a
 * bundle. `dwell_ms` travels because the daemon records it, and for no other
 * reason: it is UX telemetry, it is not evidence a human was present, and §9
 * forbids branching on it. A servo produces any dwell time you ask it for.
 */
export async function countersign({ requestDigest: digest, counter, dwellMs }) {
  const signet = await loadSignet()
  const deviceUnixMs = Date.now()
  const tbs = signingPayload(digest, counter, deviceUnixMs)

  const raw = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signet.key, tbs),
  )
  // WebCrypto emits `r || s` already — it is the DER-vs-P1363 question that
  // bites elsewhere, and WebCrypto is on the right side of it. What it does
  // *not* do is normalize `s`, and that half is required of signers.
  const signature = normalizeLowS(raw)

  return {
    device_id: signet.deviceId,
    counter,
    device_unix_ms: deviceUnixMs,
    signature: b64urlEncode(signature),
    ...(dwellMs === undefined ? {} : { dwell_ms: Math.round(dwellMs) }),
    // What this signer is, said out loud beside the signature. A phone says
    // `enclave` here and shows its enclave key; this page says `test`, and the
    // daemon refuses a test key that claims anything else. Neither is a claim
    // a verifier ever reads — the class it acts on is the enrollment record's.
    public_key_hex: signet.publicKeySec1Hex,
    class: 'test',
  }
}

export { bytesToBigint, hexEncode }
