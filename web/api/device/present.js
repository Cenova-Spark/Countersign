// ─────────────────────────────────────────────────────────────────────────
//  POST /api/device/present — signetd puts a payload on the remote screen.
//
//  Returns immediately with a request id; signetd then polls /api/device/await.
//  Split in two because a serverless function cannot hold a socket open for the
//  60 seconds a `ttl_ms` allows, and because a daemon that has to reconnect
//  anyway is a daemon that survives the relay restarting.
// ─────────────────────────────────────────────────────────────────────────
import { fail, json, methods, readJson } from '../_lib/http.js'
import { keys, randomToken, redis, signetForToken, SIGNET_TTL_S } from '../_lib/store.js'
import { parsePresentation, publicRequest, RelayError } from '../_lib/relay.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['POST'])) return

  const signet = await signetForToken(req.headers.authorization)
  if (!signet) return fail(res, 401, 'unknown_device', 'pair this daemon first')

  let presentation
  try {
    presentation = parsePresentation(await readJson(req))
  } catch (e) {
    if (e instanceof RelayError) return fail(res, e.status, e.code, e.message)
    return fail(res, 400, 'bad_request', 'expected a JSON body')
  }

  const r = redis()

  // One at a time. §9 refuses batch approval, so a queue here would be
  // building the thing the protocol says no to — a second request while one is
  // live is refused, and signetd surfaces that rather than stacking it.
  const existing = await r.get(keys.pending(signet.id))
  if (existing) {
    return fail(res, 409, 'already_pending', 'this signet is already showing a request')
  }

  const id = randomToken(12)
  const createdAt = Date.now()
  const ttlS = Math.ceil(presentation.ttl_ms / 1000)

  await Promise.all([
    // The request expires itself. An approval request nobody answered inside
    // its TTL is not a request any more, and nothing should have to sweep it.
    r.set(keys.request(id), { ...presentation, created_at: createdAt, signet_id: signet.id }, { ex: ttlS }),
    r.set(keys.pending(signet.id), id, { ex: ttlS }),
    r.set(keys.signet(signet.id), { ...signet, last_seen_at: createdAt }, { ex: SIGNET_TTL_S }),
  ])

  json(res, 200, {
    request: publicRequest(id, presentation, createdAt),
    // Everything the daemon needs to know without re-deriving it.
    poll_url: `/api/device/await?request_id=${id}`,
  })
}
