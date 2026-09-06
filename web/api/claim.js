// ─────────────────────────────────────────────────────────────────────────
//  POST /api/claim — acknowledge a request and reserve a counter for it.
//
//  This is the acknowledgement of spec §6.3.2, and it is worth being precise
//  about what it is not: **acknowledging is not approving.** It signs nothing,
//  produces no bundle, and authorizes nothing. It states only "I have noticed
//  what is being asked."
//
//  §6.3.2 requires it when the requester has changed. This path asks for it
//  every single time, which is stricter than the spec requires and deliberate:
//  the premise of remote approval is that you were not at the desk and did not
//  watch the request arrive, so there is no continuity to have noticed a break
//  in. Every remote request is a requester you have not been watching.
//
//  It also allocates the `counter`. That has to happen server-side: the counter
//  is inside the signature, so the phone needs it before it can sign, and a
//  counter must never repeat for a `device_id` (§4.1). A browser is not a place
//  to keep state you are relying on for that. Counters may *skip* — an
//  abandoned hold burns one — and skipping is fine. Going backwards is not.
// ─────────────────────────────────────────────────────────────────────────
import { fail, json, methods, readJson } from './_lib/http.js'
import { requireUser } from './_lib/session.js'
import { keys, redis } from './_lib/store.js'

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
  const r = redis()
  const request = await r.get(keys.request(id))
  if (!request) return fail(res, 404, 'no_such_request', 'that request is gone or has expired')

  const signet = await r.get(keys.signet(request.signet_id))
  if (!signet || signet.user_id !== user.id) {
    return fail(res, 403, 'not_yours', 'that signet is not on your account')
  }

  const counter = await r.incr(keys.counter(request.signet_id))

  await r.set(
    keys.request(id),
    { ...request, acknowledged_at: Date.now(), counter },
    // Keep whatever life the request had left; acknowledging does not extend
    // a TTL. A window you can refresh is a window that never closes.
    { ex: Math.max(1, Math.ceil((request.created_at + request.ttl_ms - Date.now()) / 1000)) },
  )

  json(res, 200, { counter, hold_ms: request.hold_ms, arm_delay_ms: request.arm_delay_ms })
}
