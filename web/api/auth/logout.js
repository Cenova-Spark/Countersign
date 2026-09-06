// POST /api/auth/logout — end the WorkOS session, then clear the cookie.
import { cookiePassword, SESSION_COOKIE, workos } from '../_lib/session.js'
import { json, methods, origin, readCookies, setCookie } from '../_lib/http.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['POST'])) return

  const sealed = readCookies(req)[SESSION_COOKIE]
  let logoutUrl = origin(req)

  if (sealed) {
    try {
      const session = workos().userManagement.loadSealedSession({
        sessionData: sealed,
        cookiePassword: cookiePassword(),
      })
      // Revoke at WorkOS too. Clearing the cookie alone leaves the session
      // live for anyone who kept a copy of it.
      logoutUrl = await session.getLogoutUrl({ returnTo: origin(req) })
    } catch {
      // Already invalid; clearing the cookie is all that is left to do.
    }
  }

  setCookie(res, SESSION_COOKIE, '', { maxAge: 0 })
  json(res, 200, { logout_url: logoutUrl })
}
