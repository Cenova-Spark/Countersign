// Small helpers shared by every function. Nothing clever — just one place for
// the response shape, so an error from the relay always looks the same.

export function json(res, status, body) {
  res.status(status)
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.setHeader('Cache-Control', 'no-store')
  res.send(JSON.stringify(body))
}

export function fail(res, status, code, message) {
  json(res, status, { error: code, message })
}

/** Guard a handler to one method, answering OPTIONS for the browser. */
export function methods(res, req, allowed) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Allow', allowed.join(', '))
    res.status(204).end()
    return false
  }
  if (!allowed.includes(req.method)) {
    res.setHeader('Allow', allowed.join(', '))
    fail(res, 405, 'method_not_allowed', `${req.method} is not allowed here`)
    return false
  }
  return true
}

/** Parse a JSON body whether or not the platform already did. */
export async function readJson(req) {
  if (req.body && typeof req.body === 'object') return req.body
  if (typeof req.body === 'string') return JSON.parse(req.body || '{}')
  const chunks = []
  for await (const chunk of req) chunks.push(chunk)
  const text = Buffer.concat(chunks).toString('utf8')
  return text ? JSON.parse(text) : {}
}

export function readCookies(req) {
  const header = req.headers.cookie
  if (!header) return {}
  return Object.fromEntries(
    header.split(';').map((part) => {
      const at = part.indexOf('=')
      return at === -1
        ? [part.trim(), '']
        : [part.slice(0, at).trim(), decodeURIComponent(part.slice(at + 1).trim())]
    }),
  )
}

export function setCookie(res, name, value, { maxAge, httpOnly = true } = {}) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'SameSite=Lax',
    'Secure',
    ...(httpOnly ? ['HttpOnly'] : []),
    ...(maxAge === undefined ? [] : [`Max-Age=${maxAge}`]),
  ]
  const existing = res.getHeader('Set-Cookie')
  const all = existing ? [].concat(existing, parts.join('; ')) : [parts.join('; ')]
  res.setHeader('Set-Cookie', all)
}

/** The site's own origin, for redirect URIs that must match WorkOS config. */
export function origin(req) {
  if (process.env.SIGNET_ORIGIN) return process.env.SIGNET_ORIGIN
  const host = req.headers['x-forwarded-host'] || req.headers.host
  const proto = req.headers['x-forwarded-proto'] || 'https'
  return `${proto}://${host}`
}
