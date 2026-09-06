// GET /api/auth/login — hand off to AuthKit.
import { workos } from '../_lib/session.js'
import { fail, methods, origin, setCookie } from '../_lib/http.js'
import { randomToken } from '../_lib/store.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['GET'])) return

  try {
    // `state` is a nonce the callback checks against its own cookie, so a
    // callback that did not start here is refused.
    const state = randomToken(16)
    setCookie(res, 'signet_oauth_state', state, { maxAge: 600 })

    const returnTo = typeof req.query?.next === 'string' && req.query.next.startsWith('/')
      ? req.query.next
      : '/signets'
    setCookie(res, 'signet_after_login', returnTo, { maxAge: 600 })

    res.redirect(
      302,
      workos().userManagement.getAuthorizationUrl({
        provider: 'authkit',
        redirectUri: `${origin(req)}/api/auth/callback`,
        state,
      }),
    )
  } catch (e) {
    fail(res, 500, 'auth_unconfigured', e.message)
  }
}
