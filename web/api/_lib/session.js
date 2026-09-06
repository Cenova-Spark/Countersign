// ─────────────────────────────────────────────────────────────────────────
//  WorkOS AuthKit, as a sealed session cookie.
//
//  The session is sealed by WorkOS and stored in an HttpOnly cookie, so this
//  app holds no session table and no user database — the roster of who may see
//  which signet is the WorkOS user id and nothing else.
// ─────────────────────────────────────────────────────────────────────────
import { WorkOS } from '@workos-inc/node'
import { fail, readCookies } from './http.js'
import { devRelayEnabled } from './dev-store.js'

export const SESSION_COOKIE = 'signet_session'

let cached = null

export function workos() {
  if (cached) return cached
  const apiKey = process.env.WORKOS_API_KEY
  const clientId = process.env.WORKOS_CLIENT_ID
  if (!apiKey || !clientId) {
    throw new Error('auth is not configured: set WORKOS_API_KEY and WORKOS_CLIENT_ID')
  }
  cached = new WorkOS(apiKey, { clientId })
  return cached
}

export function cookiePassword() {
  const password = process.env.WORKOS_COOKIE_PASSWORD
  // WorkOS seals with AES-256; a short password silently weakens that, so
  // refuse rather than accept one.
  if (!password || password.length < 32) {
    throw new Error('set WORKOS_COOKIE_PASSWORD to at least 32 characters')
  }
  return password
}

/**
 * The signed-in user, or `null`.
 *
 * Refreshes the sealed session when the access token has aged out, so a phone
 * left on the approval screen for an hour does not silently stop being able to
 * approve.
 */
/**
 * The single local user, when running without WorkOS.
 *
 * Behind the same two locks as the dev store: an explicit opt-in, and a hard
 * refusal on a production deployment. There is no sign-in step, so this is a
 * relay anyone who can reach it owns — fine on a laptop, catastrophic anywhere
 * else, which is why it cannot be reached by accident.
 */
function devUser() {
  const email = process.env.SIGNET_DEV_USER || 'dev@localhost'
  return {
    id: `dev_${email}`,
    user: { id: `dev_${email}`, email, firstName: 'Local', lastName: 'Developer' },
    sessionId: 'dev',
  }
}

export async function currentUser(req, res) {
  if (!process.env.WORKOS_API_KEY && devRelayEnabled()) return devUser()

  const sealed = readCookies(req)[SESSION_COOKIE]
  if (!sealed) return null

  const session = workos().userManagement.loadSealedSession({
    sessionData: sealed,
    cookiePassword: cookiePassword(),
  })

  let result
  try {
    result = await session.authenticate()
  } catch {
    return null
  }

  if (result.authenticated) {
    return { id: result.user.id, user: result.user, sessionId: result.sessionId }
  }

  try {
    const refreshed = await session.refresh()
    if (!refreshed.authenticated) return null
    if (refreshed.sealedSession && res) {
      const { setCookie } = await import('./http.js')
      setCookie(res, SESSION_COOKIE, refreshed.sealedSession, { maxAge: 60 * 60 * 24 * 14 })
    }
    return { id: refreshed.user.id, user: refreshed.user, sessionId: refreshed.sessionId }
  } catch {
    return null
  }
}

/** Guard a handler behind a session, answering 401 itself when there is none. */
export async function requireUser(req, res) {
  const user = await currentUser(req, res)
  if (!user) {
    fail(res, 401, 'unauthenticated', 'sign in to reach your signets')
    return null
  }
  return user
}
