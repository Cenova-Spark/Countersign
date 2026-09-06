<!--
  Pairing: a code you read off this screen and give to the daemon.

  Short-lived and single-use, because a code that stays valid is a standing
  invitation to bind somebody else's daemon to your account.
-->
<script setup>
import { inject, onBeforeUnmount, onMounted, ref } from 'vue'
import { api, ApiError } from '../lib/api.js'

const { user } = inject('session')

const code = ref(null)
const command = ref('')
const secondsLeft = ref(0)
const error = ref(null)
const copied = ref(false)
let timer = null

async function mint() {
  try {
    const result = await api.pairCode()
    code.value = result.code
    command.value = result.command
    secondsLeft.value = result.expires_in_s
    error.value = null
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      window.location.href = '/api/auth/login?next=/pair'
      return
    }
    error.value = e.message
  }
}

async function copy() {
  try {
    await navigator.clipboard.writeText(command.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 1800)
  } catch {
    error.value = 'Could not reach the clipboard — select the command and copy it by hand.'
  }
}

onMounted(() => {
  mint()
  timer = setInterval(() => {
    if (secondsLeft.value > 0) secondsLeft.value -= 1
  }, 1000)
})
onBeforeUnmount(() => clearInterval(timer))
</script>

<template>
  <div class="shell pair">
    <RouterLink to="/signets" class="legend back">← All signets</RouterLink>

    <h1>Pair a signet</h1>
    <p class="muted">
      Run this where your daemon runs. The code is good once, for five minutes.
    </p>

    <template v-if="code">
      <p class="code" :data-dead="secondsLeft === 0 || null">{{ code }}</p>
      <p class="legend expiry">
        <template v-if="secondsLeft > 0">Expires in {{ secondsLeft }}s</template>
        <template v-else>Expired</template>
      </p>

      <pre class="command"><code>{{ command }}</code></pre>

      <button type="button" class="cap" @click="copy">
        {{ copied ? 'Copied' : 'Copy the command' }}
      </button>
      <button type="button" class="cap fresh" @click="mint">New code</button>
    </template>

    <p v-if="error" class="notice notice--refuse">{{ error }}</p>
  </div>
</template>

<style scoped>
.pair { max-width: 34rem; }
.back { display: inline-block; padding: 1.4rem 0 0.4rem; }
.muted { color: var(--ink-dim); margin: 0.5rem 0 2rem; }

.code {
  font-family: var(--mono);
  font-size: clamp(2rem, 11vw, 3rem);
  letter-spacing: 0.14em;
  color: var(--amber);
  margin: 0;
  font-variant-numeric: tabular-nums;
}
.code[data-dead] { color: var(--ink-faint); text-decoration: line-through; }

.expiry { margin: 0.4rem 0 1.75rem; }

.command {
  background: var(--screen);
  border: 1px solid var(--screen-edge);
  border-radius: var(--radius);
  padding: 0.9rem 1rem;
  overflow-x: auto;
  font-size: 0.8rem;
  color: var(--ink-soft);
  margin: 0 0 1rem;
}

.fresh { margin-top: 0.6rem; }
</style>
