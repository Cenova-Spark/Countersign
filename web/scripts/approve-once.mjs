// ─────────────────────────────────────────────────────────────────────────
//  A headless stand-in for the phone, for testing the loop end to end.
//
//  Runs the same three steps the interface does, using the same modules:
//  read the pending request, check its digest against its own bytes,
//  acknowledge it, sign it. What it does not do is wait — there is no hold
//  here, because there is nobody here to hold anything.
//
//  That makes it a test tool and not a product feature, and the difference
//  matters: a headless approver that shipped would be precisely the
//  "software approval path" wire spec §9 refuses. It lives in scripts/,
//  it is never imported by the app, and it signs with the published test key
//  like everything else on this path.
//
//    node scripts/approve-once.mjs [--relay http://127.0.0.1:3000] [--decline]
// ─────────────────────────────────────────────────────────────────────────
import { webcrypto } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

globalThis.crypto ??= webcrypto
globalThis.btoa ??= (s) => Buffer.from(s, 'binary').toString('base64')
globalThis.atob ??= (s) => Buffer.from(s, 'base64').toString('binary')

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const { countersign, requestDigest } = await import(join(root, 'src/lib/sign.js'))

const args = process.argv.slice(2)
const relay = args.includes('--relay') ? args[args.indexOf('--relay') + 1] : 'http://127.0.0.1:3000'
const decline = args.includes('--decline')
const timeoutMs = Number(args.includes('--timeout') ? args[args.indexOf('--timeout') + 1] : 30000)

const call = async (path, init) => {
  const res = await fetch(`${relay}${path}`, {
    ...init,
    headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
  })
  const text = await res.text()
  const body = text ? JSON.parse(text) : null
  if (!res.ok) throw new Error(`${path} → ${res.status} ${body?.message ?? ''}`)
  return body
}

const deadline = Date.now() + timeoutMs
let pending = null
let signetName = ''

process.stdout.write('waiting for a request')
while (Date.now() < deadline && !pending) {
  const { signets } = await call('/api/signets')
  const live = signets.find((s) => s.pending)
  if (live) {
    pending = live.pending
    signetName = live.name
    break
  }
  process.stdout.write('.')
  await new Promise((r) => setTimeout(r, 400))
}
process.stdout.write('\n')

if (!pending) {
  console.error('nothing was asked inside the timeout')
  process.exit(1)
}

const statement = JSON.parse(pending.request_json).statement
console.log(`signet     ${signetName}`)
console.log(`statement  ${statement}`)
console.log(`digest     ${pending.digest_short}`)
console.log(`severity   ${pending.severity} · arm ${pending.arm_delay_ms}ms · hold ${pending.hold_ms}ms`)

// The check the interface does before it will render anything: recompute the
// digest from the bytes rather than believing the relay.
const recomputed = await requestDigest(JSON.parse(pending.request_json))
if (recomputed !== pending.request_digest) {
  console.error(`REFUSING — the payload does not match its digest (${recomputed})`)
  process.exit(2)
}
console.log('digest ok  recomputed from the request bytes')

if (decline) {
  await call('/api/decline', { method: 'POST', body: JSON.stringify({ request_id: pending.id }) })
  console.log('declined')
  process.exit(0)
}

const claim = await call('/api/claim', {
  method: 'POST',
  body: JSON.stringify({ request_id: pending.id }),
})
console.log(`acknowledged, counter ${claim.counter}`)

const signature = await countersign({
  requestDigest: pending.request_digest,
  counter: claim.counter,
  dwellMs: pending.hold_ms,
})
await call('/api/approve', {
  method: 'POST',
  body: JSON.stringify({ request_id: pending.id, signature }),
})
console.log(`countersigned by ${signature.device_id.slice(0, 12)}`)
