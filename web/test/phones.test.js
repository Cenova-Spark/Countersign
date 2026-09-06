// ─────────────────────────────────────────────────────────────────────────
//  The relay learning a phone's key, and what it does — and refuses to do —
//  with it. Runs the real handlers against the in-memory dev store, the way
//  `npm run dev:api` serves them, with the single local user standing in for
//  a WorkOS session.
// ─────────────────────────────────────────────────────────────────────────
import './setup.js'
import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

process.env.SIGNET_DEV_RELAY = '1'
delete process.env.WORKOS_API_KEY
delete process.env.VERCEL_ENV

const phones = (await import('../api/phones.js')).default
const approve = (await import('../api/approve.js')).default
const claim = (await import('../api/claim.js')).default
const pairCode = (await import('../api/pair-code.js')).default
const pair = (await import('../api/device/pair.js')).default
const present = (await import('../api/device/present.js')).default
const awaitOutcome = (await import('../api/device/await.js')).default
const devicePhones = (await import('../api/device/phones.js')).default

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')

/** Call a handler the way the platform does, as `user`. */
async function call(handler, { method = 'GET', body, query, headers = {}, user = 'alice@example.com' } = {}) {
  process.env.SIGNET_DEV_USER = user
  const req = { method, body, query, headers }
  const res = {
    statusCode: 0,
    headers: {},
    body: null,
    status(code) {
      this.statusCode = code
      return this
    },
    setHeader(k, v) {
      this.headers[k] = v
    },
    getHeader(k) {
      return this.headers[k]
    },
    send(text) {
      this.body = text ? JSON.parse(text) : null
      return this
    },
    end() {
      return this
    },
  }
  await handler(req, res)
  return { status: res.statusCode, body: res.body }
}

/** A phone: a fresh P-256 key, as the iPhone app would register it. */
async function aPhone(name = 'iPhone') {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))
  assert.equal(raw.length, 65)
  assert.equal(raw[0], 0x04)
  return { device_id: sha256(raw), public_key_hex: hex(raw), class: 'enclave', name }
}

/** Pair a daemon to `user` and put a request on its screen. */
async function aPendingRequest(user = 'alice@example.com') {
  const minted = await call(pairCode, { method: 'POST', user })
  assert.equal(minted.status, 200)
  const paired = await call(pair, {
    method: 'POST',
    body: { code: minted.body.code, device_id: 'ab'.repeat(32), kind: 'relay', name: 'desk' },
  })
  assert.equal(paired.status, 200, JSON.stringify(paired.body))
  const auth = { authorization: `Bearer ${paired.body.token}` }

  const request = { v: 1, action: 'file.delete', statement: 'rm demo/scratch.txt', ttl_ms: 60000 }
  const requestJson = JSON.stringify(request)
  const presented = await call(present, {
    method: 'POST',
    headers: auth,
    body: {
      request_json: requestJson,
      request_digest: sha256(requestJson),
      render: [],
      severity: 'critical',
      requester: 'test',
      ttl_ms: 60000,
    },
  })
  assert.equal(presented.status, 200, JSON.stringify(presented.body))
  const id = presented.body.request.id

  const acknowledged = await call(claim, { method: 'POST', body: { request_id: id }, user })
  assert.equal(acknowledged.status, 200)
  return { id, counter: acknowledged.body.counter, auth }
}

const SIG = 'A'.repeat(86)

test('a phone registers its key, is listed, and can be forgotten', async () => {
  const phone = await aPhone('Alice’s iPhone')

  const registered = await call(phones, { method: 'POST', body: phone })
  assert.equal(registered.status, 201, JSON.stringify(registered.body))
  assert.equal(registered.body.phone.device_id, phone.device_id)
  assert.equal(registered.body.phone.class, 'enclave')
  assert.equal(registered.body.phone.has_push, false)
  assert.match(registered.body.next, /signetd enroll/, 'says what it did not do')

  const listed = await call(phones)
  assert.equal(listed.status, 200)
  assert.deepEqual(
    listed.body.phones.map((p) => p.device_id),
    [phone.device_id],
  )

  // Registering again is an update, not a second phone.
  const again = await call(phones, { method: 'POST', body: { ...phone, name: 'renamed' } })
  assert.equal(again.status, 200)
  assert.equal(again.body.phone.name, 'renamed')
  assert.equal((await call(phones)).body.phones.length, 1)

  const forgotten = await call(phones, { method: 'DELETE', body: { device_id: phone.device_id } })
  assert.equal(forgotten.status, 200)
  assert.match(forgotten.body.note, /roster/, 'forgetting is not revoking, and says so')
  assert.equal((await call(phones)).body.phones.length, 0)
})

test('a registration is checked the way the daemon checks an attach', async () => {
  const phone = await aPhone()

  const wrongId = await call(phones, { method: 'POST', body: { ...phone, device_id: 'ff'.repeat(32) } })
  assert.equal(wrongId.status, 400)
  assert.equal(wrongId.body.error, 'bad_device_id')

  const notHex = await call(phones, { method: 'POST', body: { ...phone, public_key_hex: 'zz'.repeat(65) } })
  assert.equal(notHex.status, 400)
  assert.equal(notHex.body.error, 'bad_public_key')

  const compressed = await call(phones, {
    method: 'POST',
    body: { ...phone, public_key_hex: `02${phone.public_key_hex.slice(2)}` },
  })
  assert.equal(compressed.status, 400)
  assert.equal(compressed.body.error, 'bad_public_key')

  // Right shape, right prefix, not on the curve: Y zeroed. The id is derived
  // from these bytes so it passes the id check and fails the point check.
  const offCurveHex = `${phone.public_key_hex.slice(0, 66)}${'00'.repeat(32)}`
  const offCurve = await call(phones, {
    method: 'POST',
    body: { ...phone, public_key_hex: offCurveHex, device_id: sha256(Buffer.from(offCurveHex, 'hex')) },
  })
  assert.equal(offCurve.status, 400)
  assert.equal(offCurve.body.error, 'bad_public_key')
  assert.match(offCurve.body.message, /point on P-256/)

  for (const cls of ['test', 'signet', 'software']) {
    const wrongClass = await call(phones, { method: 'POST', body: { ...phone, class: cls } })
    assert.equal(wrongClass.status, 400, cls)
    assert.equal(wrongClass.body.error, 'bad_class', cls)
  }

  const unknownDelete = await call(phones, { method: 'DELETE', body: { device_id: 'ee'.repeat(32) } })
  assert.equal(unknownDelete.status, 404)
})

test('one key, one account', async () => {
  const phone = await aPhone()
  assert.equal((await call(phones, { method: 'POST', body: phone, user: 'alice@example.com' })).status, 201)

  const bob = await call(phones, { method: 'POST', body: phone, user: 'bob@example.com' })
  assert.equal(bob.status, 409)
  assert.equal(bob.body.error, 'not_yours')
  assert.equal((await call(phones, { user: 'bob@example.com' })).body.phones.length, 0)
})

test('an enclave signature must come from a phone on the account, under its own key', async () => {
  const phone = await aPhone()
  const { id, counter, auth } = await aPendingRequest()
  const base = { device_id: phone.device_id, counter, device_unix_ms: Date.now(), signature: SIG }

  // Not registered: refused before anything is stored.
  const unknown = await call(approve, {
    method: 'POST',
    body: { request_id: id, signature: { ...base, class: 'enclave', public_key_hex: phone.public_key_hex } },
  })
  assert.equal(unknown.status, 403)
  assert.equal(unknown.body.error, 'unknown_phone')

  // Enclave with no key at all.
  const keyless = await call(approve, {
    method: 'POST',
    body: { request_id: id, signature: { ...base, class: 'enclave' } },
  })
  assert.equal(keyless.status, 400)
  assert.equal(keyless.body.error, 'bad_public_key')

  assert.equal((await call(phones, { method: 'POST', body: phone })).status, 201)

  // Registered, but the key beside the signature is somebody else's.
  const other = await aPhone()
  const mismatch = await call(approve, {
    method: 'POST',
    body: { request_id: id, signature: { ...base, class: 'enclave', public_key_hex: other.public_key_hex } },
  })
  assert.equal(mismatch.status, 400)
  assert.equal(mismatch.body.error, 'key_mismatch')

  // A class the relay does not know.
  const signet = await call(approve, {
    method: 'POST',
    body: { request_id: id, signature: { ...base, class: 'signet', public_key_hex: phone.public_key_hex } },
  })
  assert.equal(signet.status, 400)
  assert.equal(signet.body.error, 'bad_class')

  // The real thing. The relay stores it — it does not verify it, the daemon
  // does — and what the daemon picks up carries the class and the key.
  const ok = await call(approve, {
    method: 'POST',
    body: {
      request_id: id,
      signature: { ...base, dwell_ms: 5000, class: 'enclave', public_key_hex: phone.public_key_hex, extra: 'ignored' },
    },
  })
  assert.equal(ok.status, 200, JSON.stringify(ok.body))

  const settled = await call(awaitOutcome, { headers: auth, query: { request_id: id } })
  assert.equal(settled.status, 200)
  assert.equal(settled.body.status, 'settled')
  assert.equal(settled.body.outcome.decision, 'approved')
  const [carried] = settled.body.outcome.bundle.signatures
  assert.deepEqual(carried, {
    device_id: phone.device_id,
    counter,
    device_unix_ms: base.device_unix_ms,
    signature: SIG,
    dwell_ms: 5000,
    public_key_hex: phone.public_key_hex,
    class: 'enclave',
  })
  assert.equal('extra' in carried, false, 'only the fields the daemon reads travel')

  // The phone was seen.
  const [listed] = (await call(phones)).body.phones
  assert.ok(listed.last_seen_at >= listed.registered_at)
})

test('the browser page is the test key, and is labelled as such even when it forgets to say', async () => {
  const testKeyId = '17d53e622556ceeb05d8430817e01dc387bb0092fbe45350f20f602f3de3f11c'

  // Says `test`, as the page now does.
  {
    const { id, counter, auth } = await aPendingRequest()
    const ok = await call(approve, {
      method: 'POST',
      body: {
        request_id: id,
        signature: { device_id: testKeyId, counter, device_unix_ms: Date.now(), signature: SIG, class: 'test' },
      },
    })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    const settled = await call(awaitOutcome, { headers: auth, query: { request_id: id } })
    assert.equal(settled.body.outcome.bundle.signatures[0].class, 'test')
  }

  // Says nothing — an older page. Stamped `test`, so the daemon always sees a
  // class and applies the test-key rule to it.
  {
    const { id, counter, auth } = await aPendingRequest()
    const ok = await call(approve, {
      method: 'POST',
      body: { request_id: id, signature: { device_id: testKeyId, counter, device_unix_ms: Date.now(), signature: SIG } },
    })
    assert.equal(ok.status, 200, JSON.stringify(ok.body))
    const settled = await call(awaitOutcome, { headers: auth, query: { request_id: id } })
    assert.equal(settled.body.outcome.bundle.signatures[0].class, 'test')
    assert.equal('public_key_hex' in settled.body.outcome.bundle.signatures[0], false)
  }
})

test('a paired daemon can list the phones on its account, and nobody else can', async () => {
  const phone = await aPhone('Carol’s iPhone')
  assert.equal((await call(phones, { method: 'POST', body: phone, user: 'carol@example.com' })).status, 201)
  const { auth } = await aPendingRequest('carol@example.com')

  const listed = await call(devicePhones, { headers: auth })
  assert.equal(listed.status, 200)
  assert.deepEqual(
    listed.body.phones.map((p) => [p.device_id, p.public_key_hex, p.class, p.name]),
    [[phone.device_id, phone.public_key_hex, 'enclave', 'Carol’s iPhone']],
  )
  for (const p of listed.body.phones) {
    assert.equal('user_id' in p, false)
    assert.equal('apns_token' in p, false)
  }

  // Another account's daemon sees its own phones, which is none.
  const { auth: daveAuth } = await aPendingRequest('dave@example.com')
  assert.deepEqual((await call(devicePhones, { headers: daveAuth })).body.phones, [])

  // No token, no list.
  assert.equal((await call(devicePhones)).status, 401)
  assert.equal((await call(devicePhones, { headers: { authorization: 'Bearer nope' } })).status, 401)
})
