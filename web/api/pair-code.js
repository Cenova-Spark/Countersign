// POST /api/pair-code — mint a short-lived code for `signetd pair` to redeem.
import { json, methods } from './_lib/http.js'
import { requireUser } from './_lib/session.js'
import { keys, PAIR_CODE_TTL_S, pairingCode, redis } from './_lib/store.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['POST'])) return

  const user = await requireUser(req, res)
  if (!user) return

  const code = pairingCode()
  await redis().set(
    keys.pairCode(code),
    { user_id: user.id, created_at: Date.now() },
    { ex: PAIR_CODE_TTL_S },
  )

  json(res, 200, {
    code,
    expires_in_s: PAIR_CODE_TTL_S,
    command: `signetd pair --relay https://signet.addisdb.com --code ${code}`,
  })
}
