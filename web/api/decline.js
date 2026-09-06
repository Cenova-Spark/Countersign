// ─────────────────────────────────────────────────────────────────────────
//  POST /api/decline — the NO button.
//
//  A decline is a real decision and travels as one. `aborted` is a decision the
//  daemon records in the audit trail, distinct from `expired`, because "someone
//  looked at this and said no" and "nobody was there" are different facts and a
//  trail that conflates them is less useful than one that does not.
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

  const ttlS = Math.max(1, Math.ceil((request.created_at + request.ttl_ms - Date.now()) / 1000))
  await r.set(
    keys.outcome(id),
    {
      decision: 'aborted',
      declined_by: { user_id: user.id, email: user.user.email },
      declined_at: Date.now(),
      via: 'remote',
    },
    { ex: ttlS },
  )

  json(res, 200, { ok: true })
}
