// ─────────────────────────────────────────────────────────────────────────
//  Serve api/ locally, the way the platform serves it in production.
//
//  The handlers in api/ are written against the Vercel Node signature. This
//  gives them the same `req`/`res` shape on a plain node:http server, so the
//  same files run in both places and there is no second implementation of the
//  relay to keep in step.
//
//    SIGNET_DEV_RELAY=1 node scripts/dev-api.mjs
// ─────────────────────────────────────────────────────────────────────────
import { createServer } from 'node:http'
import { existsSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { dirname, join, normalize } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const PORT = Number(process.env.PORT || 3000)

/** Map /api/device/present → api/device/present.js, refusing anything else. */
function resolveHandler(pathname) {
  if (!pathname.startsWith('/api/')) return null
  const rel = normalize(pathname.slice(1))
  // `_lib` is shared code, not routes — the platform does not expose files
  // whose name starts with an underscore and neither does this.
  if (rel.includes('..') || rel.split('/').some((p) => p.startsWith('_'))) return null
  const file = join(root, `${rel}.js`)
  return existsSync(file) ? file : null
}

/** The response helpers the handlers expect. */
function decorate(res) {
  res.status = (code) => {
    res.statusCode = code
    return res
  }
  res.send = (body) => {
    res.end(body)
    return res
  }
  res.json = (body) => {
    res.setHeader('Content-Type', 'application/json; charset=utf-8')
    res.end(JSON.stringify(body))
    return res
  }
  res.redirect = (code, location) => {
    res.statusCode = typeof code === 'number' ? code : 302
    res.setHeader('Location', typeof code === 'number' ? location : code)
    res.end()
    return res
  }
  return res
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`)
  const file = resolveHandler(url.pathname)

  if (!file) {
    res.statusCode = 404
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ error: 'not_found', message: `no handler for ${url.pathname}` }))
    return
  }

  req.query = Object.fromEntries(url.searchParams)
  decorate(res)

  try {
    // Re-imported per request with a cache-buster so editing a handler does not
    // need a restart.
    const mod = await import(`${pathToFileURL(file).href}?t=${Date.now()}`)
    await mod.default(req, res)
  } catch (e) {
    console.error(`[signet] ${url.pathname}:`, e)
    if (!res.headersSent) {
      res.statusCode = 500
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ error: 'handler_failed', message: e.message }))
    }
  }
})

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[signet] relay API on http://127.0.0.1:${PORT}`)
  if (process.env.SIGNET_DEV_RELAY === '1') {
    console.log('[signet] dev relay: state is in memory, and there is no sign-in step.')
  }
})
