<!--
  The rack: your signets, and which of them is waiting on you.

  Sorted so that anything wanting a human is first, because that is the only
  reason to have opened this page from a phone.
-->
<script setup>
import { computed, inject, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, ApiError } from '../lib/api.js'

const router = useRouter()
const { user } = inject('session')

const signets = ref([])
const error = ref(null)
const loading = ref(true)
let timer = null

const waiting = computed(() => signets.value.filter((s) => s.pending))
const idle = computed(() => signets.value.filter((s) => !s.pending))

async function load() {
  try {
    signets.value = (await api.signets()).signets
    error.value = null
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      window.location.href = '/api/auth/login?next=/signets'
      return
    }
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function remaining(pending) {
  return Math.max(0, Math.round((pending.expires_at - Date.now()) / 1000))
}

const now = ref(Date.now())

onMounted(() => {
  load()
  // A request lives for its ttl_ms and then stops existing, so the list has to
  // be live. Two seconds is fast enough to feel immediate and slow enough not
  // to be a load generator.
  timer = setInterval(() => {
    now.value = Date.now()
    load()
  }, 2000)
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div class="shell">
    <p v-if="loading" class="legend pad">Reading the rack…</p>

    <p v-else-if="error" class="notice notice--refuse pad">{{ error }}</p>

    <template v-else>
      <section v-if="waiting.length" class="group">
        <h2 class="legend legend--lit group__head">
          <span class="pip" aria-hidden="true" />
          Waiting on you
        </h2>

        <button
          v-for="signet in waiting"
          :key="signet.id"
          type="button"
          class="tile tile--live"
          @click="router.push(`/signets/${signet.id}`)"
        >
          <span class="tile__bar" :data-tier="signet.pending.severity" />
          <span class="tile__body">
            <span class="tile__label">
              {{ signet.pending.render.find((l) => l.role === 'label')?.text ?? 'unclassified' }}
            </span>
            <span class="tile__statement">{{ JSON.parse(signet.pending.request_json).statement }}</span>
            <span class="tile__meta">
              <span class="tile__digest">{{ signet.pending.digest_short }}</span>
              <span class="tile__sep">·</span>
              <span>{{ signet.name }}</span>
              <span class="tile__sep">·</span>
              <span class="tile__clock">{{ remaining(signet.pending) }}s</span>
            </span>
          </span>
        </button>
      </section>

      <section v-if="idle.length" class="group">
        <h2 class="legend group__head">{{ waiting.length ? 'Idle' : 'Your signets' }}</h2>
        <div v-for="signet in idle" :key="signet.id" class="tile tile--idle">
          <span class="tile__body">
            <span class="tile__name">{{ signet.name }}</span>
            <span class="tile__meta">
              <span>{{ signet.hostname || signet.kind }}</span>
              <span class="tile__sep">·</span>
              <span class="tile__id">{{ signet.device_id.slice(0, 12) }}</span>
              <template v-if="signet.is_test_key">
                <span class="tile__sep">·</span>
                <span class="tile__test">test key</span>
              </template>
            </span>
          </span>
        </div>
      </section>

      <section v-if="!signets.length" class="empty">
        <h2>No signets yet</h2>
        <p class="empty__body">
          Pair the daemon on your machine and it will show up here, along with anything it
          is waiting on a human for.
        </p>
        <RouterLink to="/pair" class="cap cap--ack empty__cta">Pair a signet</RouterLink>
      </section>

      <p v-else class="foot">
        <RouterLink to="/pair" class="legend">Pair another signet</RouterLink>
      </p>
    </template>
  </div>
</template>

<style scoped>
.pad { padding-top: 2.5rem; }

.group { margin-top: 2.25rem; }

.group__head { display: flex; align-items: center; gap: 0.55rem; margin-bottom: 0.7rem; }

/* The one piece of motion on this page. It marks the thing that is actually
   asking for you, and nothing else moves. */
.pip {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--amber);
  box-shadow: 0 0 0 0 color-mix(in srgb, var(--amber) 60%, transparent);
  animation: pulse 2s ease-out infinite;
}
@keyframes pulse {
  70% { box-shadow: 0 0 0 7px transparent; }
  100% { box-shadow: 0 0 0 0 transparent; }
}

.tile {
  display: flex;
  width: 100%;
  text-align: left;
  gap: 0;
  border: 1px solid var(--hairline);
  border-radius: var(--radius);
  background: var(--ground-lift);
  overflow: hidden;
  margin-bottom: 0.55rem;
}

.tile--live { cursor: pointer; transition: border-color 140ms ease, transform 140ms ease; }
.tile--live:hover { border-color: var(--steel-dark); }
.tile--live:active { transform: translateY(1px); }

/* The stripe carries severity, which is the daemon's assessment — the same
   thing the device colour-codes across the top of its screen. */
.tile__bar { width: 3px; flex: none; background: var(--steel-dark); }
.tile__bar[data-tier='critical'] { background: var(--refuse); }
.tile__bar[data-tier='high'] { background: var(--caution); }
.tile__bar[data-tier='moderate'] { background: var(--amber); }

.tile__body { display: block; padding: 0.85rem 1rem; min-width: 0; flex: 1; }

.tile__label {
  display: block;
  font-family: var(--label);
  text-transform: uppercase;
  letter-spacing: 0.14em;
  font-size: 0.66rem;
  color: var(--ink-dim);
  margin-bottom: 0.3rem;
}

.tile__statement {
  display: block;
  font-family: var(--mono);
  color: var(--ink);
  font-weight: 600;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  margin-bottom: 0.35rem;
}

.tile__name { display: block; color: var(--ink-soft); margin-bottom: 0.2rem; }

.tile__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 0.4rem;
  font-size: 0.76rem;
  color: var(--ink-faint);
}

.tile__sep { opacity: 0.5; }
.tile__digest { font-family: var(--mono); color: #9fb3c4; }
.tile__clock { font-family: var(--mono); color: var(--amber); font-variant-numeric: tabular-nums; }
.tile__id { font-family: var(--mono); opacity: 0.75; }
.tile__test { color: var(--caution); }

.empty { padding-top: 3.5rem; max-width: 30rem; }
.empty__body { color: var(--ink-dim); margin: 0.6rem 0 1.6rem; }
.empty__cta { text-align: center; }

.foot { margin-top: 2rem; }
</style>
