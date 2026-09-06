// GET /api/auth/me — who is signed in, if anyone.
import { currentUser } from '../_lib/session.js'
import { json, methods } from '../_lib/http.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['GET'])) return

  try {
    const session = await currentUser(req, res)
    if (!session) return json(res, 200, { user: null })
    json(res, 200, {
      user: {
        id: session.user.id,
        email: session.user.email,
        first_name: session.user.firstName ?? null,
        last_name: session.user.lastName ?? null,
        profile_picture_url: session.user.profilePictureUrl ?? null,
      },
    })
  } catch (e) {
    json(res, 200, { user: null, unconfigured: e.message })
  }
}
