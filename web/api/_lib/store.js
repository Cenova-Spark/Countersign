// ─────────────────────────────────────────────────────────────────────────
//  The relay's store.
//
//  Upstash Redis, chosen because the protocol's `ttl_ms` and Redis's key
//  expiry are the same idea: an approval request that nobody answered is not a
//  request any more, and it should stop existing without anyone sweeping it.
//
//  **The relay is untrusted by design, and this is where that has to hold.**
//  It holds no signing key and can forge nothing. It can drop a request, and it
//  can see a payload — which is the honest limit of this version, and the
//  reason NEXT_STEPS §2.2 wants the payload end-to-end encrypted so a hosted
//  relay never becomes a custodian of anyone's queries. Nothing here is
//  designed in a way that would make that change harder.
// ─────────────────────────────────────────────────────────────────────────
import { Redis } from '@upstash/redis'
import { devRedis, devRelayEnabled } from './dev-store.js'

let client = null

export function redis() {
  if (client) return client

  const url = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL
  const token = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN

  if (url && token) {
    client = new Redis({ url, token })
    return client
  }

  if (devRelayEnabled()) {
    console.warn(
      '[signet] SIGNET_DEV_RELAY=1 — relay state is in process memory. ' +
        'It does not survive a restart and does not work across serverless workers.',
    )
    client = devRedis
    return client
  }

  throw new Error(
    'the relay store is not configured: set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN ' +
      '(or SIGNET_DEV_RELAY=1 to run it in process memory locally)',
  )
}

// ── Key layout ───────────────────────────────────────────────────────────
export const keys = {
  /** The set of signet ids belonging to one WorkOS user. */
  userSignets: (userId) => `u:${userId}:signets`,
  /** A signet's record. */
  signet: (id) => `s:${id}`,
  /** signetd's bearer token → signet id. Stores the token's SHA-256, not the token. */
  deviceToken: (hash) => `t:${hash}`,
  /** A short-lived pairing code a human reads off the screen. */
  pairCode: (code) => `p:${code}`,
  /**
   * The signet's monotonic counter (spec §4.1).
   *
   * Server-side because the counter must never repeat for a device_id, and the
   * browser is not a place to keep state you are relying on for that.
   */
  counter: (id) => `s:${id}:counter`,
  /**
   * The one request a signet is currently showing.
   *
   * Singular on purpose. One signature, one statement — §9 refuses batch
   * approval, so a queue here would be building the thing the protocol says no
   * to. A second request while one is pending is refused, not stacked.
   */
  pending: (id) => `s:${id}:pending`,
  /** A request's presentation, as posted by signetd. */
  request: (id) => `r:${id}`,
  /** Where the outcome lands for signetd's long poll to pick up. */
  outcome: (id) => `r:${id}:outcome`,
  /**
   * The phones registered to one WorkOS user, as a set of `device_id`s.
   *
   * A phone is not a signet. A signet is a *daemon* that pairs and presents;
   * a phone is a *signer* that registers its enclave public key so the relay
   * knows which keys belong to the account. The relay learns the key and
   * nothing else — it holds no private half, verifies nothing, and the daemon
   * on the other end checks the phone against its own roster regardless of
   * what is stored here (device-class spec §6, "pairing is not enrolling").
   */
  userPhones: (userId) => `u:${userId}:phones`,
  /**
   * One phone's record, keyed by `device_id` — the digest of its public key,
   * and therefore global. One key, one account: registering a key already on
   * another account is refused (enrollment spec §6).
   */
  phone: (deviceId) => `ph:${deviceId}`,
}

/** How long a pairing code is good for. Long enough to type, short enough to matter. */
export const PAIR_CODE_TTL_S = 300

/**
 * How long a signet record survives without being seen.
 *
 * A demo relay should not accumulate abandoned signets forever, and a signetd
 * that has been offline for a fortnight is not a signet anyone is waiting on.
 * Re-pairing is one command.
 */
export const SIGNET_TTL_S = 60 * 60 * 24 * 14

export async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/** A URL-safe random token. */
export function randomToken(bytes = 32) {
  const raw = crypto.getRandomValues(new Uint8Array(bytes))
  return btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * A pairing code a person can read aloud and type.
 *
 * Crockford's alphabet minus the characters that get misread — no I, L, O or U
 * — because this gets copied off one screen onto another by hand.
 */
export function pairingCode() {
  const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
  const raw = crypto.getRandomValues(new Uint8Array(8))
  const code = [...raw].map((b) => ALPHABET[b % ALPHABET.length]).join('')
  return `${code.slice(0, 4)}-${code.slice(4)}`
}

/** Resolve signetd's `Authorization: Bearer` to the signet it was issued for. */
export async function signetForToken(authorization) {
  const token = /^Bearer (.+)$/.exec(authorization || '')?.[1]
  if (!token) return null
  const id = await redis().get(keys.deviceToken(await sha256Hex(token)))
  if (!id) return null
  const signet = await redis().get(keys.signet(id))
  return signet ? { id, ...signet } : null
}
