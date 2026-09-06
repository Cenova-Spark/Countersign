// ─────────────────────────────────────────────────────────────────────────
//  POST /api/approve — the phone hands back a signature.
//
//  The relay does not verify the signature, and that is not laziness. It holds
//  no roster, and a relay that decided which signatures were good would be a
//  party you had to trust — the design goal is the opposite. `signetd` verifies
//  when it picks the outcome up, against the roster it already has, and
//  `countersign-verify` refuses a published test key unless somebody
//  deliberately configured otherwise.
//
//  So the worst a broken or hostile relay can do here is hand back a signature
//  that fails verification, which fails closed at the daemon.
//
//  The signature says what signed it: `class` and `public_key_hex`. A real
//  phone says `enclave` and shows its enclave key, and the one thing the relay
//  checks is that the key is registered to *this* account (_lib/phones.js) —
//  so a signed-in person cannot post under a key that was never theirs. The
//  browser page says `test`; its key is derived and the daemon knows it. Both
//  travel to the daemon as claims, and the daemon believes neither on the
//  relay's say-so: it checks a phone against its own roster, and it refuses a
//  test key that calls itself anything but test.
// ─────────────────────────────────────────────────────────────────────────
import { fail, json, methods, readJson } from './_lib/http.js'
import { requireUser } from './_lib/session.js'
import { keys, redis } from './_lib/store.js'
import { CLASSES, phoneOf } from './_lib/phones.js'

const B64URL = /^[A-Za-z0-9_-]+$/
const HEX130 = /^[0-9a-f]{130}$/

export default async function handler(req, res) {
  if (!methods(res, req, ['POST'])) return

  const user = await requireUser(req, res)
  if (!user) return

  let body
  try {
    body = await readJson(req)
  } catch {
    return fail(res, 400, 'bad_request', 'expected a JSON body')
  }

  const id = String(body.request_id ?? '')
  const signature = body.signature
  if (!signature || typeof signature !== 'object') {
    return fail(res, 400, 'bad_signature', 'signature is required')
  }
  if (typeof signature.signature !== 'string' || !B64URL.test(signature.signature)) {
    return fail(res, 400, 'bad_signature', 'signature must be unpadded base64url')
  }
  if (!/^[0-9a-f]{64}$/.test(String(signature.device_id ?? ''))) {
    return fail(res, 400, 'bad_signature', 'device_id must be 64 lowercase hex characters')
  }
  if (!Number.isInteger(signature.counter) || !Number.isInteger(signature.device_unix_ms)) {
    return fail(res, 400, 'bad_signature', 'counter and device_unix_ms must be integers')
  }
  // Absent is the browser page from before it said so. Everything newer says.
  const cls = signature.class ?? 'test'
  if (!CLASSES.includes(cls)) {
    return fail(res, 400, 'bad_class', `class must be one of ${CLASSES.join(', ')}`)
  }
  const publicKeyHex = signature.public_key_hex
  if (publicKeyHex !== undefined && !HEX130.test(String(publicKeyHex))) {
    return fail(res, 400, 'bad_public_key', 'public_key_hex must be 130 lowercase hex characters')
  }

  const r = redis()
  const request = await r.get(keys.request(id))
  if (!request) return fail(res, 404, 'no_such_request', 'that request is gone or has expired')

  const signet = await r.get(keys.signet(request.signet_id))
  if (!signet || signet.user_id !== user.id) {
    return fail(res, 403, 'not_yours', 'that signet is not on your account')
  }

  // A phone has to be one of this account's phones, under the key it says it
  // is. Not verification — the daemon does that — but it closes the one door
  // the relay is positioned to close: a signature under somebody else's key.
  let phone = null
  if (cls === 'enclave') {
    if (!publicKeyHex) {
      return fail(res, 400, 'bad_public_key', 'an enclave signature must carry public_key_hex')
    }
    phone = await phoneOf(user.id, signature.device_id)
    if (!phone) {
      return fail(res, 403, 'unknown_phone', 'register this phone on your account before it approves')
    }
    if (phone.public_key_hex !== publicKeyHex) {
      return fail(res, 400, 'key_mismatch', 'public_key_hex is not the key this phone registered')
    }
  }

  // The acknowledgement is not optional and not something the client can skip
  // by posting straight here — §6.3.2, and see the note in claim.js about why
  // this path asks for one every time.
  if (!request.acknowledged_at) {
    return fail(res, 409, 'not_acknowledged', 'acknowledge the request before approving it')
  }
  // The counter came from the relay at claim time; a client-chosen counter
  // would let the phone replay an old one.
  if (signature.counter !== request.counter) {
    return fail(res, 409, 'stale_claim', 'this approval used a counter the relay did not issue')
  }

  // Only the fields the daemon reads travel. Whatever else the client put in
  // the object stays here.
  const carried = {
    device_id: signature.device_id,
    counter: signature.counter,
    device_unix_ms: signature.device_unix_ms,
    signature: signature.signature,
    ...(Number.isInteger(signature.dwell_ms) ? { dwell_ms: signature.dwell_ms } : {}),
    ...(publicKeyHex ? { public_key_hex: publicKeyHex } : {}),
    class: cls,
  }

  const ttlS = Math.max(1, Math.ceil((request.created_at + request.ttl_ms - Date.now()) / 1000))
  await Promise.all([
    r.set(
      keys.outcome(id),
      {
        decision: 'approved',
        // The bundle signetd needs, in the shape spec §5 names. It verifies
        // this against its own copy of the request before acting on it.
        bundle: {
          v: 1,
          decision: 'approved',
          request_digest: request.request_digest,
          signatures: [carried],
        },
        approved_by: { user_id: user.id, email: user.user.email },
        approved_at: Date.now(),
        via: 'remote',
      },
      { ex: ttlS },
    ),
    phone ? r.set(keys.phone(phone.device_id), { ...phone, last_seen_at: Date.now() }) : null,
  ])

  json(res, 200, { ok: true })
}
