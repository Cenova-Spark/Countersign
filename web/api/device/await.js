// ─────────────────────────────────────────────────────────────────────────
//  GET /api/device/await?request_id=… — signetd waits for the human.
//
//  Long-polls: holds for a few seconds looking for an outcome, then answers
//  `pending` so the caller can come straight back. Bounded well inside any
//  platform execution limit, because a function killed mid-wait would look to
//  signetd exactly like a refusal.
// ─────────────────────────────────────────────────────────────────────────
import { fail, json, methods } from '../_lib/http.js'
import { keys, redis, signetForToken } from '../_lib/store.js'

/** How long one call holds before answering `pending`. */
const WINDOW_MS = 9000
const INTERVAL_MS = 400

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

export default async function handler(req, res) {
  if (!methods(res, req, ['GET'])) return

  const signet = await signetForToken(req.headers.authorization)
  if (!signet) return fail(res, 401, 'unknown_device', 'pair this daemon first')

  const id = String(req.query?.request_id ?? '')
  if (!id) return fail(res, 400, 'missing_request_id', 'request_id is required')

  const r = redis()
  const deadline = Date.now() + WINDOW_MS

  for (;;) {
    const outcome = await r.getdel(keys.outcome(id))
    if (outcome) {
      // The request is finished either way; stop it showing anywhere else.
      await Promise.all([r.del(keys.request(id)), r.del(keys.pending(signet.id))])
      return json(res, 200, { status: 'settled', outcome })
    }

    // Gone without an outcome means the TTL ran out. That is `expired`, and it
    // is a real decision the daemon has to record — not an error.
    if (!(await r.exists(keys.request(id)))) {
      await r.del(keys.pending(signet.id))
      return json(res, 200, { status: 'settled', outcome: { decision: 'expired' } })
    }

    if (Date.now() + INTERVAL_MS >= deadline) {
      return json(res, 200, { status: 'pending' })
    }
    await sleep(INTERVAL_MS)
  }
}
