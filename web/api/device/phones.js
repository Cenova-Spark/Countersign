// ─────────────────────────────────────────────────────────────────────────
//  GET /api/device/phones — signetd asks which phones are on its account.
//
//  The daemon needs a signer's public key to write an enrollment record after
//  the phone has held on the ceremony (`Daemon::enroll` looks the signer up in
//  `Device::devices()`). This is where it finds it. It is a *lookup*, and it
//  is worth being exact that it is nothing more: a phone listed here may not
//  approve anything — the daemon's own roster decides that, and a relay that
//  padded this list could add a name and could not get a signature accepted.
//  Device-class spec §6.
//
//  Public keys only. There is nothing else here to give.
// ─────────────────────────────────────────────────────────────────────────
import { fail, json, methods } from '../_lib/http.js'
import { keys, redis, signetForToken } from '../_lib/store.js'
import { publicPhone } from '../_lib/phones.js'

export default async function handler(req, res) {
  if (!methods(res, req, ['GET'])) return

  const signet = await signetForToken(req.headers.authorization)
  if (!signet) return fail(res, 401, 'unknown_device', 'pair this daemon first')

  const r = redis()
  const ids = await r.smembers(keys.userPhones(signet.user_id))
  const phones = await Promise.all(
    ids.map(async (id) => {
      const record = await r.get(keys.phone(id))
      return record && record.user_id === signet.user_id ? publicPhone(record) : null
    }),
  )
  json(res, 200, { phones: phones.filter(Boolean) })
}
