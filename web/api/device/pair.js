// ─────────────────────────────────────────────────────────────────────────
//  POST /api/device/pair — signetd redeems a pairing code for a device token.
//
//  The code is minted in the browser by a signed-in user and read off the
//  screen, so redeeming one is how a daemon comes to belong to a person. It is
//  single-use and short-lived: a code that stays valid is a standing invitation
//  to bind someone else's daemon to your account.
// ─────────────────────────────────────────────────────────────────────────
import { fail, json, methods, readJson } from '../_lib/http.js'
import { keys, randomToken, redis, sha256Hex, SIGNET_TTL_S } from '../_lib/store.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['POST'])) return

  let body
  try {
    body = await readJson(req)
  } catch {
    return fail(res, 400, 'bad_request', 'expected a JSON body')
  }

  const code = String(body.code ?? '').trim().toUpperCase()
  const deviceId = String(body.device_id ?? '')
  if (!/^[0-9a-f]{64}$/.test(deviceId)) {
    return fail(res, 400, 'bad_device_id', 'device_id must be 64 lowercase hex characters')
  }

  const r = redis()

  // Single use: take the code out of the store before acting on it, so two
  // daemons racing on the same code cannot both win.
  const claim = await r.getdel(keys.pairCode(code))
  if (!claim) return fail(res, 404, 'unknown_code', 'that pairing code is unknown or has expired')

  const id = randomToken(12)
  const token = randomToken(32)

  const signet = {
    id,
    user_id: claim.user_id,
    name: String(body.name ?? 'Signet').slice(0, 64),
    // Straight from the daemon, and surfaced everywhere it can be: a demo that
    // looks identical to production is how a demo ends up in production.
    kind: String(body.kind ?? 'mock').slice(0, 32),
    is_test_key: body.is_test_key !== false,
    device_id: deviceId,
    hostname: String(body.hostname ?? '').slice(0, 128),
    paired_at: Date.now(),
    last_seen_at: Date.now(),
  }

  await Promise.all([
    r.set(keys.signet(id), signet, { ex: SIGNET_TTL_S }),
    // Only the token's digest is stored. A dump of this store does not let
    // anyone impersonate a daemon.
    r.set(keys.deviceToken(await sha256Hex(token)), id, { ex: SIGNET_TTL_S }),
    r.sadd(keys.userSignets(claim.user_id), id),
    r.expire(keys.userSignets(claim.user_id), SIGNET_TTL_S),
  ])

  json(res, 200, { signet_id: id, token, name: signet.name })
}
