<!--
  The hero is the device, and it works.

  Not a screenshot and not a video: the real component, the real gesture, the
  real timings for a `critical` payload — a 2 s arm delay and a 5 s hold. The
  thing being sold is a physical feeling, so the page hands you the feeling
  before it asks you for anything.

  This one signs nothing. It has no counter, no relay and no bundle; it exists
  to be turned.
-->
<script setup>
import { computed, inject, onMounted, ref } from 'vue'
import SignetDevice from '../components/SignetDevice.vue'
import HoldControl from '../components/HoldControl.vue'
import { useHold } from '../lib/hold.js'
import { digestShort, requestDigest } from '../lib/sign.js'

const { user } = inject('session')

const demo = ref(null)
const turned = ref(false)
const rendered = ref(false)

/** The wire spec's own example request, §2. */
const SAMPLE = {
  v: 1,
  nonce: 'Y291bnRlcnNpZ24tdGVzdC12ZWN0b3Itbm9uY2UtMDE',
  requester: { id: 'claude-code', instance: 'vector-session' },
  action: 'sql.execute',
  target: {
    kind: 'database',
    uri_fingerprint: '860e238e58a1004aaf5fdcfd236fecb87cb5641653a276374e1492b92dfde478',
  },
  statement: 'DROP TABLE users;',
  advisory: { rows_affected: 4200000, dependents: 3, reversible: false },
  ttl_ms: 60000,
}

const armDelayMs = computed(() => 2000)
const holdMs = computed(() => 5000)
const enabled = computed(() => !turned.value)

const hold = useHold({
  armDelayMs,
  holdMs,
  enabled,
  onCommit: () => {
    turned.value = true
  },
})

function again() {
  turned.value = false
  hold.armFrom()
}

onMounted(async () => {
  // The digest is computed here, not hard-coded, so the landing page is
  // demonstrating the same canonicalization everything else uses.
  const digest = await requestDigest(SAMPLE)
  demo.value = {
    id: 'demo',
    request_json: JSON.stringify(SAMPLE),
    request_digest: digest,
    digest_short: digestShort(digest),
    render: [
      { role: 'label', text: 'prod-us-east-1' },
      { role: 'advisory', text: '~4,200,000 rows · 3 deps' },
      { role: 'advisory', text: 'not reversible' },
    ],
    severity: 'critical',
    action: 'sql.execute',
    requester: 'claude-code',
  }
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      rendered.value = true
      hold.armFrom()
    })
  })
})

const deviceState = computed(() => {
  if (turned.value) return 'approved'
  if (hold.phase.value === 'holding') return 'holding'
  if (hold.phase.value === 'arming') return 'arming'
  return 'armed'
})
</script>

<template>
  <div class="shell">
    <section class="hero">
      <p class="legend hero__eyebrow">Remote countersignature</p>
      <h1 class="hero__title">
        The one confirmation<br />an agent can't click.
      </h1>
      <p class="hero__sub">
        Your Signet asks for a physical turn before something consequential runs. When
        you're away from the desk, it asks here instead — with the same payload, the same
        digest, and the same hold.
      </p>
    </section>

    <div class="stage">
      <SignetDevice
        :request="demo"
        :rotation="hold.rotation.value"
        :hold-progress="hold.holdProgress.value"
        :state="deviceState"
        :rendered="rendered"
      />
    </div>

    <div class="try">
      <template v-if="!turned">
        <HoldControl :hold="hold" :hold-ms="5000" :arm-delay-ms="2000" />
        <p class="try__note">
          A <code>critical</code> payload arms after 2 seconds and needs a 5-second hold.
          Let go early and it gives the whole thing back.
        </p>
      </template>
      <template v-else>
        <div class="done">
          <p class="done__title legend legend--lit">Turned</p>
          <p class="done__body">
            On a real request that would be a signature over these exact bytes — and over
            nothing else. Nothing was signed here.
          </p>
          <button type="button" class="cap" @click="again">Try it again</button>
        </div>
      </template>
    </div>

    <hr class="rule" />

    <section class="points">
      <div class="point">
        <h3 class="legend">It renders what it signs</h3>
        <p>
          The screen is drawn from the bytes the signature covers. There is no separate
          display field to disagree with them, which is the failure hardware wallets spent
          a decade learning to avoid.
        </p>
      </div>
      <div class="point">
        <h3 class="legend">The digest is yours to check</h3>
        <p>
          The same twelve characters appear on the machine that asked and on the screen you
          turn. If they differ, they are not the same request — and you are the one who
          finds out.
        </p>
      </div>
      <div class="point">
        <h3 class="legend">This page can't forge one</h3>
        <p>
          Remote approvals sign with a published test key. Every verifier refuses them by
          default. The bypass isn't switched off — it's incapable.
        </p>
      </div>
    </section>

    <div class="cta">
      <RouterLink v-if="user" to="/signets" class="cap cap--ack">Go to your signets</RouterLink>
      <a v-else href="/api/auth/login?next=/signets" class="cap cap--ack">Sign in to your signets</a>
    </div>
  </div>
</template>

<style scoped>
.hero { padding: clamp(2rem, 8vw, 4rem) 0 1.5rem; max-width: 34rem; }
.hero__eyebrow { margin: 0 0 0.9rem; }

.hero__title {
  font-size: clamp(2rem, 8vw, 3.1rem);
  line-height: 1.04;
  letter-spacing: -0.01em;
  font-weight: 600;
  color: var(--ink);
}

.hero__sub { color: var(--ink-dim); margin: 1.1rem 0 0; max-width: 32rem; }

/* The device is the hero, but a hero that pushes the control it is
   demonstrating below the fold has stopped being one. Capped so both are in
   view on a laptop; full width on a phone, where the fold is lower anyway. */
.stage { margin: 0 -0.5rem; max-width: 34rem; margin-inline: auto; }

.try { max-width: 30rem; margin: 0 auto 3rem; }
.try__note { font-size: 0.8rem; color: var(--ink-faint); margin: 0.8rem 0 0; text-align: center; }
.try__note code { color: var(--caution); }

.done { text-align: center; }
.done__title { font-size: 0.8rem; margin: 0 0 0.5rem; }
.done__body { color: var(--ink-dim); font-size: 0.88rem; margin: 0 0 1.2rem; }

.points {
  display: grid;
  gap: 1.75rem;
  padding: 2.5rem 0;
  grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr));
}
.point h3 { margin-bottom: 0.5rem; }
.point p { margin: 0; font-size: 0.88rem; color: var(--ink-dim); }

.cta { max-width: 22rem; margin: 0 auto 4rem; }
.cta .cap { text-align: center; }
</style>
