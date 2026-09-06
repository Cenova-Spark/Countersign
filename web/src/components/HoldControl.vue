<!--
  The approving actuation, as a control a thumb can reach.

  The dial is at the top of the device in this projection, which is the wrong
  end of a phone, so the gesture lives down here in the thumb zone and the dial
  above answers to it. Same actuation, reachable.

  What this control refuses to do is as important as what it does. Before the
  payload has been readable it accepts nothing — not a shorter hold, nothing.
  If a thumb was already down when the payload rendered, it waits for the thumb
  to lift first. Let go early and the accumulated hold is discarded, and the
  dial visibly springs back to give it away.
-->
<script setup>
import { computed } from 'vue'

const props = defineProps({
  hold: { type: Object, required: true },
  holdMs: { type: Number, required: true },
  armDelayMs: { type: Number, required: true },
  busy: { type: Boolean, default: false },
})

const phase = computed(() => props.hold.phase.value)
const progress = computed(() => props.hold.holdProgress.value)
const armProgress = computed(() => props.hold.armProgress.value)

const seconds = computed(() => (props.holdMs / 1000).toFixed(props.holdMs % 1000 ? 1 : 0))

const caption = computed(() => {
  if (props.busy) return 'Signing…'
  switch (phase.value) {
    case 'arming':
      return 'Read it first'
    case 'rest':
      // §6.2.3's rest transition, in the interface's own words.
      return 'Lift your thumb, then hold'
    case 'holding':
      return `Keep holding — ${seconds.value}s`
    case 'committed':
      return 'Signing…'
    default:
      return `Hold for ${seconds.value}s to approve`
  }
})

const fill = computed(() => (phase.value === 'arming' ? armProgress.value : progress.value))

function down(event) {
  // Only a primary press, and never the browser's own text-selection gesture.
  if (event.button !== undefined && event.button !== 0) return
  event.preventDefault()
  event.currentTarget.setPointerCapture?.(event.pointerId)
  props.hold.press()
}

function up() {
  props.hold.release()
}

function keyDown(event) {
  if (event.key !== ' ' && event.key !== 'Enter') return
  event.preventDefault()
  // Auto-repeat fires keydown over and over; a hold must not be restarted by
  // it, and must not be satisfiable by it either.
  if (event.repeat) return
  props.hold.press()
}

function keyUp(event) {
  if (event.key !== ' ' && event.key !== 'Enter') return
  props.hold.release()
}
</script>

<template>
  <div
    class="hold"
    :data-phase="phase"
    :data-busy="busy || null"
    role="button"
    tabindex="0"
    :aria-label="caption"
    :aria-disabled="busy || phase === 'arming' || phase === 'rest'"
    @pointerdown="down"
    @pointerup="up"
    @pointercancel="up"
    @pointerleave="up"
    @keydown="keyDown"
    @keyup="keyUp"
    @contextmenu.prevent
  >
    <div class="hold__fill" :style="{ transform: `scaleX(${fill})` }" />
    <span class="hold__caption">{{ caption }}</span>
  </div>
</template>

<style scoped>
.hold {
  position: relative;
  display: grid;
  place-items: center;
  height: 4rem;
  border-radius: var(--radius);
  border: 1px solid var(--amber);
  background: color-mix(in srgb, var(--amber) 8%, transparent);
  overflow: hidden;
  user-select: none;
  -webkit-user-select: none;
  touch-action: none;
  cursor: pointer;
}

/* Not yet approvable: the control is visibly not the amber one. */
.hold[data-phase='arming'],
.hold[data-phase='rest'] {
  border-color: var(--hairline);
  background: var(--ground-lift);
  cursor: default;
}
.hold[data-phase='arming'] .hold__fill { background: var(--steel-dark); opacity: 0.5; }
.hold[data-phase='rest'] .hold__fill { display: none; }

.hold[data-busy] { cursor: progress; }

.hold__fill {
  position: absolute;
  inset: 0;
  transform-origin: left center;
  background: var(--amber);
  opacity: 0.9;
  /* No transition: the fill is driven frame by frame from the real accumulated
     hold, so anything easing it would be lying about how much has been held. */
}

.hold__caption {
  position: relative;
  font-family: var(--label);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.18em;
  font-size: 0.8rem;
  color: var(--amber);
  mix-blend-mode: difference;
}

.hold[data-phase='arming'] .hold__caption,
.hold[data-phase='rest'] .hold__caption {
  color: var(--ink-faint);
  mix-blend-mode: normal;
}
</style>
