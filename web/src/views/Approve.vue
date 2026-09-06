<!--
  One request, three steps: read it, acknowledge it, hold to sign it.

  The order is not a wizard for its own sake. Acknowledging and approving are
  different organs on the device — a button and the dial — because §6.3.3 says
  same-organ-different-gesture is the wrong answer for a population that is, by
  premise, not paying full attention. So they are different controls here too.
-->
<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import SignetDevice from '../components/SignetDevice.vue'
import HoldControl from '../components/HoldControl.vue'
import { api, ApiError } from '../lib/api.js'
import { useHold } from '../lib/hold.js'
import { countersign, requestDigest } from '../lib/sign.js'

const route = useRoute()

const signet = ref(null)
const request = ref(null)
const status = ref('loading') // loading · ready · approving · approved · declined · expired · gone
const error = ref(null)
const counter = ref(null)
const acknowledged = ref(false)
/** Set when the payload has been painted; the arm delay runs from here. */
const rendered = ref(false)
/** Null until checked; false means the relay and the bytes disagree. */
const digestVerified = ref(null)

let poll = null
const now = ref(Date.now())

const armDelayMs = computed(() => request.value?.arm_delay_ms ?? 2000)
const holdMs = computed(() => request.value?.hold_ms ?? 5000)

const canHold = computed(
  () => status.value === 'ready' && acknowledged.value && digestVerified.value === true,
)

const hold = useHold({
  armDelayMs,
  holdMs,
  enabled: canHold,
  onCommit: ({ dwellMs }) => approve(dwellMs),
})

const secondsLeft = computed(() => {
  if (!request.value) return 0
  return Math.max(0, Math.ceil((request.value.expires_at - now.value) / 1000))
})

/**
 * The requester, without the daemon's own "(claimed)" suffix.
 *
 * `requester.id` is a claim and both the daemon and this screen say so — but
 * saying it twice reads as a stutter, so the suffix comes off and the marker
 * beside the value carries it.
 */
const requesterText = computed(() =>
  (request.value?.requester ?? '').replace(/\s*\(claimed\)/, '').trim(),
)

const statement = computed(() => {
  if (!request.value) return ''
  try {
    return JSON.parse(request.value.request_json).statement
  } catch {
    return ''
  }
})

/**
 * Check the digest against the bytes, rather than believing the relay.
 *
 * This is the whole reason the request travels as raw JSON. The relay can drop
 * a request or read one; it must not be able to change one. If these disagree,
 * something between the daemon and this screen rewrote the payload, and the
 * only safe response is to refuse to render it at all — showing it with a
 * warning invites approving it anyway.
 */
async function verifyDigest(pending) {
  try {
    const parsed = JSON.parse(pending.request_json)
    const computed_ = await requestDigest(parsed)
    return computed_ === pending.request_digest
  } catch {
    return false
  }
}

async function load() {
  try {
    const { signets } = await api.signets()
    const found = signets.find((s) => s.id === route.params.id)
    if (!found) {
      status.value = 'gone'
      return
    }
    signet.value = found

    if (!found.pending) {
      // It settled, expired, or was answered somewhere else.
      if (status.value === 'approving' || status.value === 'approved') return
      status.value = request.value ? 'expired' : 'gone'
      return
    }

    const isNew = request.value?.id !== found.pending.id
    request.value = found.pending

    if (isNew) {
      // A new payload restarts everything: the acknowledgement, the arm delay,
      // and the rest requirement. Carrying any of them over would let a
      // request inherit attention that was paid to a different one.
      acknowledged.value = false
      counter.value = null
      rendered.value = false
      digestVerified.value = await verifyDigest(found.pending)
      status.value = 'ready'
      // Arm from the frame *after* paint — §6.2.3 measures from the last byte
      // written to the screen, not from when the payload arrived.
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          rendered.value = true
          hold.armFrom()
        })
      })
    }
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      window.location.href = `/api/auth/login?next=/signets/${route.params.id}`
      return
    }
    error.value = e.message
  }
}

/** Acknowledging notices the request. It signs nothing and authorizes nothing. */
async function acknowledge() {
  try {
    const claim = await api.claim(request.value.id)
    counter.value = claim.counter
    acknowledged.value = true
  } catch (e) {
    error.value = e.message
  }
}

async function approve(dwellMs) {
  if (status.value !== 'ready') return
  status.value = 'approving'
  try {
    const signature = await countersign({
      requestDigest: request.value.request_digest,
      counter: counter.value,
      dwellMs,
    })
    await api.approve(request.value.id, signature)
    status.value = 'approved'
  } catch (e) {
    error.value = e.message
    status.value = 'ready'
    hold.armFrom()
  }
}

async function decline() {
  try {
    await api.decline(request.value.id)
    status.value = 'declined'
  } catch (e) {
    error.value = e.message
  }
}

watch(secondsLeft, (left) => {
  if (left === 0 && status.value === 'ready') {
    status.value = 'expired'
    hold.disarm()
  }
})

onMounted(() => {
  load()
  poll = setInterval(() => {
    now.value = Date.now()
    if (status.value === 'ready' || status.value === 'loading') load()
  }, 1500)
})
onBeforeUnmount(() => clearInterval(poll))

const deviceState = computed(() => {
  if (status.value === 'approved') return 'approved'
  if (status.value === 'declined') return 'declined'
  if (status.value === 'expired') return 'expired'
  if (hold.phase.value === 'holding') return 'holding'
  if (hold.phase.value === 'arming') return 'arming'
  return status.value === 'ready' ? 'armed' : 'idle'
})
</script>

<template>
  <div class="shell">
    <RouterLink to="/signets" class="legend back">← All signets</RouterLink>

    <p v-if="status === 'loading'" class="legend">Reading the request…</p>

    <template v-else-if="status === 'gone'">
      <h2>Nothing pending</h2>
      <p class="muted">
        This signet is not waiting on anything right now. Requests live for their
        own lifetime and then stop existing.
      </p>
      <RouterLink to="/signets" class="cap">Back to the rack</RouterLink>
    </template>

    <template v-else>
      <!-- The device. Live screen, live dial. -->
      <div class="stage" :data-state="deviceState">
        <SignetDevice
          :request="request"
          :rotation="hold.rotation.value"
          :hold-progress="hold.holdProgress.value"
          :state="deviceState"
          :rendered="rendered"
        />
      </div>

      <p v-if="digestVerified === false" class="notice notice--refuse">
        <strong>Refusing to show this.</strong>
        The payload does not match the digest it arrived with, which means something
        between your machine and this screen rewrote it. Nothing here can be approved.
        Approve it at the device instead.
      </p>

      <template v-else-if="status === 'approved'">
        <h2 class="verdict">Countersigned</h2>
        <p class="muted">
          Your machine has the signature. It was signed with the published test key, so a
          default verifier will refuse it — that is what makes this safe to demonstrate.
        </p>
        <RouterLink to="/signets" class="cap">Back to the rack</RouterLink>
      </template>

      <template v-else-if="status === 'declined'">
        <h2 class="verdict verdict--no">Declined</h2>
        <p class="muted">Your machine has been told no, and the trail records that a human said so.</p>
        <RouterLink to="/signets" class="cap">Back to the rack</RouterLink>
      </template>

      <template v-else-if="status === 'expired'">
        <h2 class="verdict verdict--no">Expired</h2>
        <p class="muted">
          Nobody answered inside the request's lifetime. Your machine recorded that as
          <code>expired</code> — which is a different fact from a refusal, and the trail
          keeps them apart.
        </p>
        <RouterLink to="/signets" class="cap">Back to the rack</RouterLink>
      </template>

      <template v-else>
        <!-- What is being asked, in text, at a size a phone can read. The
             device screen above is the authority; this is the same bytes,
             legible. -->
        <dl class="facts">
          <div class="fact">
            <dt class="legend">Statement</dt>
            <dd class="fact__statement">{{ statement }}</dd>
          </div>
          <div class="fact fact--row">
            <div>
              <dt class="legend">Digest</dt>
              <dd class="fact__digest">{{ request.digest_short }}</dd>
            </div>
            <div>
              <dt class="legend">Expires</dt>
              <dd class="fact__clock">{{ secondsLeft }}s</dd>
            </div>
          </div>
          <div class="fact fact--row">
            <div>
              <dt class="legend">Asked by</dt>
              <dd class="fact__claimed">{{ requesterText }} <span class="tag">claimed</span></dd>
            </div>
            <div>
              <dt class="legend">Action</dt>
              <dd>{{ request.action }}</dd>
            </div>
          </div>
        </dl>

        <p class="compare">
          Check <span class="compare__digest">{{ request.digest_short }}</span> against the
          digest on the machine that asked. If they differ, they are not the same request.
        </p>

        <!-- Step 2. A button, not the dial. Acknowledging is not approving. -->
        <button
          v-if="!acknowledged"
          type="button"
          class="cap cap--ack"
          @click="acknowledge"
        >
          Ack — I've read what this does
        </button>

        <!-- Step 3. Only reachable once step 2 is done. -->
        <HoldControl
          v-else
          :hold="hold"
          :hold-ms="holdMs"
          :arm-delay-ms="armDelayMs"
          :busy="status === 'approving'"
        />

        <button type="button" class="cap cap--refuse decline" @click="decline">No — don't run this</button>

        <p v-if="error" class="notice notice--refuse">{{ error }}</p>
      </template>
    </template>
  </div>
</template>

<style scoped>
.back { display: inline-block; padding: 1.4rem 0 0.4rem; }
.back:hover { color: var(--amber); text-decoration: none; }

.stage { margin: 0 auto 1.25rem; max-width: 32rem; }

.muted { color: var(--ink-dim); max-width: 34rem; }

.verdict { font-size: 1.5rem; margin: 1rem 0 0.5rem; color: var(--amber); }
.verdict--no { color: var(--refuse-soft); }

.facts { margin: 0 0 1.25rem; display: grid; gap: 0.9rem; }
.fact dd { margin: 0.2rem 0 0; }
.fact--row { display: grid; grid-template-columns: 1fr auto; gap: 1rem; align-items: start; }

.fact__statement {
  font-family: var(--mono);
  color: var(--ink);
  font-size: 1rem;
  font-weight: 600;
  word-break: break-word;
}
.fact__digest { font-family: var(--mono); color: #9fb3c4; letter-spacing: 0.06em; }
.fact__clock { font-family: var(--mono); color: var(--amber); font-variant-numeric: tabular-nums; }
.fact__claimed { font-family: var(--mono); color: var(--ink-soft); font-size: 0.9rem; }

/* `requester.id` is a claim and the protocol says so; the interface says so
   too, in the same breath as the value. */
.tag {
  font-family: var(--label);
  text-transform: uppercase;
  letter-spacing: 0.12em;
  font-size: 0.6rem;
  color: var(--caution);
  border: 1px solid color-mix(in srgb, var(--caution) 45%, transparent);
  border-radius: 2px;
  padding: 0.05rem 0.3rem;
  margin-left: 0.35rem;
  vertical-align: 1px;
}

.compare {
  font-size: 0.82rem;
  color: var(--ink-dim);
  border-top: 1px solid var(--hairline);
  padding-top: 0.9rem;
  margin: 0 0 1.25rem;
}
.compare__digest { font-family: var(--mono); color: #9fb3c4; }

.decline { margin-top: 0.6rem; }
</style>
