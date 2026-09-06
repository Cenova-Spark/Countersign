// GET /api/auth/callback — exchange the code and seal a session.
import { cookiePassword, SESSION_COOKIE, workos } from '../_lib/session.js'
import { fail, methods, readCookies, setCookie } from '../_lib/http.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['GET'])) return

  const { code, state, error, error_description: description } = req.query ?? {}
  if (error) return fail(res, 400, String(error), String(description ?? 'sign-in was refused'))
  if (!code) return fail(res, 400, 'missing_code', 'no authorization code came back')

  const cookies = readCookies(req)
  // A callback whose state does not match the one login set did not start here.
  if (!cookies.signet_oauth_state || cookies.signet_oauth_state !== state) {
    return fail(res, 400, 'bad_state', 'this sign-in did not start on this site')
  }

  try {
    const result = await workos().userManagement.authenticateWithCode({
      code: String(code),
      session: { sealSession: true, cookiePassword: cookiePassword() },
    })

    setCookie(res, SESSION_COOKIE, result.sealedSession, { maxAge: 60 * 60 * 24 * 14 })
    setCookie(res, 'signet_oauth_state', '', { maxAge: 0 })

    const next = cookies.signet_after_login?.startsWith('/') ? cookies.signet_after_login : '/signets'
    setCookie(res, 'signet_after_login', '', { maxAge: 0 })
    res.redirect(302, next)
  } catch (e) {
    fail(res, 401, 'exchange_failed', e.message)
  }
}
