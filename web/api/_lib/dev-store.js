// ─────────────────────────────────────────────────────────────────────────
//  An in-process stand-in for Redis, for running the relay on one machine.
//
//  Exists so the whole path — daemon, relay, phone — can be exercised before
//  anyone signs up for anything. It is **not** a smaller Redis: state lives in
//  one process, so it does not survive a restart and does not work at all on a
//  platform that runs each request in its own worker.
//
//  Two locks, because a dev store reached in production is an unauthenticated
//  relay: it requires SIGNET_DEV_RELAY=1 to exist at all, and refuses outright
//  when the platform says this is a production deployment. Neither is a
//  default, and the process says loudly which one it is using.
// ─────────────────────────────────────────────────────────────────────────

const store = new Map()

function live(key) {
  const entry = store.get(key)
  if (!entry) return null
  if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
    store.delete(key)
    return null
  }
  return entry
}

const expiry = (options) =>
  options?.ex === undefined ? null : Date.now() + options.ex * 1000

/** The subset of the Upstash client this relay actually uses. */
export const devRedis = {
  async get(key) {
    return live(key)?.value ?? null
  },
  async set(key, value, options) {
    store.set(key, { value, expiresAt: expiry(options) })
    return 'OK'
  },
  async getdel(key) {
    const entry = live(key)
    store.delete(key)
    return entry?.value ?? null
  },
  async del(key) {
    return store.delete(key) ? 1 : 0
  },
  async exists(key) {
    return live(key) ? 1 : 0
  },
  async incr(key) {
    const entry = live(key)
    const next = (entry?.value ?? 0) + 1
    store.set(key, { value: next, expiresAt: entry?.expiresAt ?? null })
    return next
  },
  async sadd(key, member) {
    const entry = live(key)
    const set = entry?.value instanceof Set ? entry.value : new Set()
    set.add(member)
    store.set(key, { value: set, expiresAt: entry?.expiresAt ?? null })
    return 1
  },
  async srem(key, member) {
    const set = live(key)?.value
    return set instanceof Set && set.delete(member) ? 1 : 0
  },
  async smembers(key) {
    const set = live(key)?.value
    return set instanceof Set ? [...set] : []
  },
  async expire(key, seconds) {
    const entry = live(key)
    if (!entry) return 0
    entry.expiresAt = Date.now() + seconds * 1000
    return 1
  },
}

/**
 * Whether the dev store may be used at all.
 *
 * Deliberately not "are the Redis variables missing?" — a production deploy
 * with a typo'd variable name would sail straight through that and serve an
 * unauthenticated relay out of process memory.
 */
export function devRelayEnabled() {
  if (process.env.SIGNET_DEV_RELAY !== '1') return false
  if (process.env.VERCEL_ENV === 'production') {
    throw new Error(
      'SIGNET_DEV_RELAY=1 is set on a production deployment. Refusing to serve the ' +
        'relay out of process memory with no authentication. Configure Upstash instead.',
    )
  }
  return true
}
