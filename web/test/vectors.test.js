// ─────────────────────────────────────────────────────────────────────────
//  The browser crypto, against `spec/vectors/` — not against the Rust or the
//  TypeScript code.
//
//  Same rule the TypeScript SDK follows: a port is checked against the
//  committed vectors, because two implementations agreeing with each other and
//  both being wrong is the failure this is meant to catch. Canonicalization is
//  where implementations disagree silently and a valid approval mysteriously
//  fails to verify.
// ─────────────────────────────────────────────────────────────────────────
import './setup.js'
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { canonicalize, canonicalizeText, JcsError } from '../src/lib/jcs.js'
import { hexEncode, hexDecode, b64urlEncode, b64urlDecode, bytesToBigint } from '../src/lib/encoding.js'
import { publicKeySec1, isLowS, normalizeLowS, HALF_N, N } from '../src/lib/p256.js'
import { countersign, loadSignet, requestDigest, signingPayload, digestShort } from '../src/lib/sign.js'

const vectors = join(dirname(fileURLToPath(import.meta.url)), '../../spec/vectors')
const read = (name) => JSON.parse(readFileSync(join(vectors, name), 'utf8'))

test('canonicalization matches the committed vectors', async () => {
  const { accept, reject } = read('canonicalization.json')

  for (const c of accept) {
    assert.equal(canonicalizeText(c.input), c.canonical, c.name)
    // The digest is the field that actually travels, so check it too rather
    // than trusting that equal strings hash equally.
    const digest = hexEncode(new Uint8Array(createHash('sha256').update(c.canonical).digest()))
    assert.equal(digest, c.digest_sha256, `${c.name}: digest`)
  }

  for (const c of reject) {
    assert.throws(
      () => canonicalizeText(c.input),
      (e) => e instanceof JcsError && e.kind === c.reason,
      `${c.name} must be refused as ${c.reason}`,
    )
  }

  assert.equal(accept.length, 10, 'vector count changed; re-read the file')
  assert.equal(reject.length, 3, 'vector count changed; re-read the file')
})

test('the approval vector digests to its committed request_digest', async () => {
  const vector = read('approval.json')
  const request = JSON.parse(vector.envelope.request_json)

  // Canonicalizing the parsed request must reproduce the transmitted bytes
  // exactly — the request travels as raw JSON precisely so this holds.
  assert.equal(canonicalize(request), vector.envelope.request_json)

  const digest = await requestDigest(request)
  assert.equal(digest, vector.envelope.bundle.request_digest)
  assert.equal(digestShort(digest).replace(/ /g, ''), vector.digest_short)
})

test('the signing payload matches the committed hex', () => {
  const vector = read('approval.json')
  const sig = vector.envelope.bundle.signatures[0]
  const tbs = signingPayload(vector.envelope.bundle.request_digest, sig.counter, sig.device_unix_ms)
  assert.equal(hexEncode(tbs), vector.signing_payload_hex)
})

test('the published test key derives to its committed device_id', async () => {
  const vector = read('test-key.json')
  const scalar = new Uint8Array(createHash('sha256').update('countersign-v1 published test key').digest())
  assert.equal(hexEncode(scalar), vector.private_key_hex)

  const sec1 = publicKeySec1(bytesToBigint(scalar))
  assert.equal(hexEncode(sec1), vector.public_key_sec1_uncompressed_hex)
  // Hashed as raw bytes including the 0x04 prefix — spec §4.2. Both plausible
  // alternatives produce a device_id that matches nothing, silently.
  assert.equal(hexEncode(new Uint8Array(createHash('sha256').update(sec1).digest())), vector.device_id)
})

test('this signet is NOT the mock signet', async () => {
  // If these ever collide, two independent signers share an identity and a
  // per-device counter, which trips a verifier's replay defence for real
  // reasons. See the header of lib/sign.js.
  const signet = await loadSignet()
  assert.notEqual(signet.deviceId, read('test-key.json').device_id)
  assert.equal(signet.isTestKey, true)
})

test('every signature is low-S', async () => {
  // Spec §4 is emphatic that one low-S result proves nothing: a signer that
  // forgets to normalize emits high-S roughly half the time. 200 draws makes
  // an unnormalized signer fail with probability ~1 - 2^-200.
  const digest = read('approval.json').envelope.bundle.request_digest
  for (let counter = 1; counter <= 200; counter += 1) {
    const sig = await countersign({ requestDigest: digest, counter, dwellMs: 2000 })
    assert.ok(isLowS(b64urlDecode(sig.signature)), `counter ${counter} produced a high-S signature`)
  }
})

test('signatures verify, and carry the fields a bundle needs', async () => {
  const digest = read('approval.json').envelope.bundle.request_digest
  const signet = await loadSignet()
  const sig = await countersign({ requestDigest: digest, counter: 7, dwellMs: 5000 })

  assert.equal(sig.device_id, signet.deviceId)
  assert.equal(sig.counter, 7)
  assert.equal(sig.dwell_ms, 5000)

  const sec1 = hexDecode(signet.publicKeySec1Hex)
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: b64urlEncode(sec1.subarray(1, 33)), y: b64urlEncode(sec1.subarray(33, 65)) },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
  const tbs = signingPayload(digest, sig.counter, sig.device_unix_ms)
  assert.ok(
    await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, b64urlDecode(sig.signature), tbs),
  )
})

test('normalizeLowS flips exactly the high half', () => {
  const high = new Uint8Array(64)
  const sBytes = (v) => {
    const out = new Uint8Array(32)
    for (let i = 31; i >= 0; i -= 1) { out[i] = Number(v & 0xffn); v >>= 8n }
    return out
  }
  high.set(sBytes(HALF_N + 1n), 32)
  assert.equal(bytesToBigint(normalizeLowS(high).subarray(32)), N - (HALF_N + 1n))

  const low = new Uint8Array(64)
  low.set(sBytes(HALF_N), 32)
  assert.equal(bytesToBigint(normalizeLowS(low).subarray(32)), HALF_N, 'exactly n/2 is already low')
})

test('encoders refuse the spellings the spec does not name', () => {
  assert.throws(() => b64urlDecode('YWJj='), /base64url/, 'padding is refused')
  assert.throws(() => b64urlDecode('a+/b'), /base64url/, 'the standard alphabet is refused')
  assert.throws(() => hexDecode('abc'), /odd length/)
  assert.throws(() => hexDecode('zz'), /not valid hex/)
  assert.equal(b64urlEncode(hexDecode('deadbeef')), '3q2-7w')
})
