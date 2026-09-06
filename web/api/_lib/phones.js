// ─────────────────────────────────────────────────────────────────────────
//  Phones: the keys the relay knows belong to an account.
//
//  A phone registers its enclave public key here so that, when a signature
//  comes back through /api/approve saying `enclave`, the relay can confirm the
//  key is one the signed-in person put on their own account. That is the whole
//  of what the relay checks, and it is worth being exact about why it is so
//  little.
//
//  The relay does not verify signatures, hold a roster, or decide which keys
//  may approve. `signetd` does all three, against the enrollment record it
//  wrote when the operator ran the ceremony on the phone — device-class spec
//  §6, "pairing is not enrolling". What a registration stops is narrower and
//  still worth stopping: a signed-in person cannot post a signature under a
//  key that was never theirs, and a key cannot sit on two accounts at once
//  (enrollment spec §6, one device, one human).
//
//  What is stored is a public key, a name, and later an APNs token. Never a
//  private half, never anything that could sign.
// ─────────────────────────────────────────────────────────────────────────
import { RelayError } from './relay.js'
import { keys, redis, sha256Hex } from './store.js'

/** The classes a signature may say it is. Only `enclave` may register. */
export const CLASSES = ['enclave', 'test']

const HEX = /^[0-9a-f]+$/

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/**
 * Check a public key the way the daemon does (`app.rs`, `relay.rs`): 65 bytes,
 * SEC1 uncompressed (`0x04 || X || Y`), and a point on P-256 — WebCrypto's raw
 * import refuses anything off the curve. Returns the key's `device_id`.
 */
export async function checkPublicKey(publicKeyHex) {
  if (typeof publicKeyHex !== 'string' || publicKeyHex.length !== 130 || !HEX.test(publicKeyHex)) {
    throw new RelayError(
      400,
      'bad_public_key',
      'public_key_hex must be 130 lowercase hex characters — the 65-byte SEC1 uncompressed encoding',
    )
  }
  const bytes = hexToBytes(publicKeyHex)
  if (bytes[0] !== 0x04) {
    throw new RelayError(400, 'bad_public_key', 'public_key_hex must be uncompressed (start with 04)')
  }
  try {
    await crypto.subtle.importKey('raw', bytes, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])
  } catch {
    throw new RelayError(400, 'bad_public_key', 'public_key_hex is not a point on P-256')
  }
  // `device_id` is the SHA-256 of the key bytes — wire spec §4.2. Derived
  // here and compared, never accepted.
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** Validate a registration body, without trusting any of it. */
export async function parseRegistration(body) {
  if (!body || typeof body !== 'object') {
    throw new RelayError(400, 'bad_request', 'expected a JSON object')
  }
  const cls = body.class ?? 'enclave'
  if (cls !== 'enclave') {
    // The browser demo's test key is derived and needs no registration; a
    // Signet reaches a daemon over a cable, not through here. A phone is an
    // enclave or it is not a phone (device-class spec §2).
    throw new RelayError(400, 'bad_class', 'a phone registers as class enclave, and nothing else registers')
  }
  const deviceId = await checkPublicKey(body.public_key_hex)
  if (String(body.device_id ?? '').toLowerCase() !== deviceId) {
    throw new RelayError(
      400,
      'bad_device_id',
      `device_id must be the SHA-256 of the key (${deviceId}); wire spec §4.2`,
    )
  }
  return {
    device_id: deviceId,
    public_key_hex: body.public_key_hex,
    class: 'enclave',
    name: String(body.name ?? 'Phone').slice(0, 64) || 'Phone',
  }
}

/** The phone with this id, if it is on this user's account. */
export async function phoneOf(userId, deviceId) {
  if (!/^[0-9a-f]{64}$/.test(deviceId)) return null
  const record = await redis().get(keys.phone(deviceId))
  return record && record.user_id === userId ? record : null
}

/** The shape the browser and the daemon receive. Never a token. */
export function publicPhone(record) {
  return {
    device_id: record.device_id,
    public_key_hex: record.public_key_hex,
    class: record.class,
    name: record.name,
    registered_at: record.registered_at,
    last_seen_at: record.last_seen_at,
    has_push: Boolean(record.apns_token),
  }
}

export { sha256Hex }
