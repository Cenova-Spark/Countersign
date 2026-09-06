// ─────────────────────────────────────────────────────────────────────────
//  /api/phones — the signed-in person's phones, and their keys.
//
//    GET     list them
//    POST    register one: { device_id, public_key_hex, class: "enclave", name }
//    DELETE  forget one:   { device_id }
//
//  Registering a phone here is not enrolling it. It tells the relay which
//  enclave keys belong to this account so that /api/approve can refuse a
//  signature under a key that was never the account's. The daemon that will
//  act on the phone's signatures still has to enroll it — `signetd enroll` with
//  the phone held on the ceremony — and verifies every approval against its
//  own roster, not against this list. See _lib/phones.js.
// ─────────────────────────────────────────────────────────────────────────
import { fail, json, methods, readJson } from './_lib/http.js'
import { requireUser } from './_lib/session.js'
import { keys, redis } from './_lib/store.js'
import { RelayError } from './_lib/relay.js'
import { parseRegistration, publicPhone } from './_lib/phones.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['GET', 'POST', 'DELETE'])) return

  const user = await requireUser(req, res)
  if (!user) return
  const r = redis()

  if (req.method === 'GET') {
    const ids = await r.smembers(keys.userPhones(user.id))
    const phones = await Promise.all(
      ids.map(async (id) => {
        const record = await r.get(keys.phone(id))
        // A record that is gone, or that moved accounts, is not this user's.
        if (!record || record.user_id !== user.id) {
          await r.srem(keys.userPhones(user.id), id)
          return null
        }
        return publicPhone(record)
      }),
    )
    return json(res, 200, { phones: phones.filter(Boolean) })
  }

  let body
  try {
    body = await readJson(req)
  } catch {
    return fail(res, 400, 'bad_request', 'expected a JSON body')
  }

  if (req.method === 'DELETE') {
    const id = String(body.device_id ?? '')
    const record = /^[0-9a-f]{64}$/.test(id) ? await r.get(keys.phone(id)) : null
    if (!record || record.user_id !== user.id) {
      return fail(res, 404, 'unknown_phone', 'that phone is not on your account')
    }
    await Promise.all([r.del(keys.phone(id)), r.srem(keys.userPhones(user.id), id)])
    // Forgetting a phone here stops the relay accepting its approvals. It does
    // not revoke it: that is the daemon's roster, and a revocation there is
    // what an audit of last year reads. Say so, so nobody thinks this was that.
    return json(res, 200, { forgotten: id, note: 'revoke it in the daemon roster too' })
  }

  let registration
  try {
    registration = await parseRegistration(body)
  } catch (e) {
    if (e instanceof RelayError) return fail(res, e.status, e.code, e.message)
    throw e
  }

  const existing = await r.get(keys.phone(registration.device_id))
  if (existing && existing.user_id !== user.id) {
    // One key, one human. A key on somebody else's account does not move
    // here by being asserted; enrollment spec §6.
    return fail(res, 409, 'not_yours', 'that key is registered to a different account')
  }

  const now = Date.now()
  const record = {
    ...registration,
    user_id: user.id,
    registered_at: existing?.registered_at ?? now,
    last_seen_at: now,
    // Set by the phone once it has one — HANDOFF, M5 step 4. Never the
    // payload's destination: a push carries an id and a digest, not a statement.
    apns_token: existing?.apns_token ?? null,
  }
  await Promise.all([
    r.set(keys.phone(record.device_id), record),
    r.sadd(keys.userPhones(user.id), record.device_id),
  ])

  json(res, existing ? 200 : 201, {
    phone: publicPhone(record),
    // The step this does not do, said where the person doing it will read it.
    next: 'enroll it: run `signetd enroll --subject you@example.com` and hold on the phone',
  })
}
