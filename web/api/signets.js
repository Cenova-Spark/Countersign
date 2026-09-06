// ─────────────────────────────────────────────────────────────────────────
//  GET /api/signets — the dashboard: your signets, and which want you.
// ─────────────────────────────────────────────────────────────────────────
import { json, methods } from './_lib/http.js'
import { requireUser } from './_lib/session.js'
import { keys, redis } from './_lib/store.js'
import { publicRequest } from './_lib/relay.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['GET'])) return

  const user = await requireUser(req, res)
  if (!user) return

  const r = redis()
  const ids = await r.smembers(keys.userSignets(user.id))
  if (!ids.length) return json(res, 200, { signets: [] })

  const signets = await Promise.all(
    ids.map(async (id) => {
      const record = await r.get(keys.signet(id))
      // A signet whose record aged out is gone; drop it from the set rather
      // than showing a tile that cannot do anything.
      if (!record) {
        await r.srem(keys.userSignets(user.id), id)
        return null
      }

      const pendingId = await r.get(keys.pending(id))
      const pending = pendingId ? await r.get(keys.request(pendingId)) : null

      return {
        id,
        name: record.name,
        kind: record.kind,
        is_test_key: record.is_test_key,
        device_id: record.device_id,
        hostname: record.hostname,
        paired_at: record.paired_at,
        last_seen_at: record.last_seen_at,
        pending: pending ? publicRequest(pendingId, pending, pending.created_at) : null,
      }
    }),
  )

  const live = signets.filter(Boolean)
  // Anything waiting on a human sorts first — that is the whole reason to open
  // this page.
  live.sort((a, b) => (b.pending ? 1 : 0) - (a.pending ? 1 : 0) || b.last_seen_at - a.last_seen_at)
  json(res, 200, { signets: live })
}
