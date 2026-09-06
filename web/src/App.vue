<script setup>
import { onMounted, provide, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api } from './lib/api.js'

const route = useRoute()
const router = useRouter()

const user = ref(null)
const loaded = ref(false)

async function refresh() {
  try {
    user.value = (await api.me()).user
  } catch {
    user.value = null
  } finally {
    loaded.value = true
  }
}

async function signOut() {
  const { logout_url: url } = await api.logout()
  user.value = null
  window.location.href = url
}

provide('session', { user, loaded, refresh, signOut })
onMounted(refresh)
</script>

<template>
  <header class="bar">
    <div class="bar__inner shell">
      <RouterLink to="/" class="wordmark">SIGNET</RouterLink>
      <nav v-if="loaded && user" class="bar__nav">
        <RouterLink v-if="route.name !== 'signets'" to="/signets" class="legend">Signets</RouterLink>
        <span class="legend bar__who">{{ user.email }}</span>
        <button class="legend bar__out" type="button" @click="signOut">Sign out</button>
      </nav>
    </div>
  </header>

  <main>
    <RouterView v-if="loaded" />
    <p v-else class="shell legend loading">Connecting…</p>
  </main>
</template>

<style scoped>
.bar {
  border-bottom: 1px solid var(--hairline);
  background: color-mix(in srgb, var(--ground) 88%, transparent);
  backdrop-filter: blur(8px);
  position: sticky;
  top: 0;
  z-index: 10;
}

.bar__inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding-top: 0.85rem;
  padding-bottom: 0.85rem;
}

/* The wordmark is silkscreened on the deck of the device; it is silkscreened
   here too, at the same tracking. */
.wordmark {
  font-family: var(--label);
  font-weight: 700;
  letter-spacing: 0.38em;
  font-size: 0.95rem;
  color: var(--steel-lit);
  text-decoration: none;
}
.wordmark:hover { color: var(--ink); text-decoration: none; }

.bar__nav { display: flex; align-items: center; gap: 1.1rem; }
.bar__who { color: var(--ink-faint); font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0; text-transform: none; }
.bar__out { color: var(--ink-faint); }
.bar__out:hover { color: var(--amber); }

.loading { padding-top: 3rem; }

@media (max-width: 30rem) {
  .bar__who { display: none; }
}
</style>
