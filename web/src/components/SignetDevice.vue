<!--
  The Signet, drawn from the Phase 1 form study.

  The chassis is the study's own geometry, verbatim. Three things are live:

    · the dial, which turns — see lib/dial.js for why only the ribs and the
      index mark move;
    · the screen, which renders the real payload;
    · the HOLD pill, which fills as the hold accumulates.

  The screen renders **from the request's own bytes**, never from a summary the
  relay handed over. That is spec §6 — the device renders from what it will
  sign — and here it is also what keeps an untrusted relay honest, since a relay
  that rewrote the statement could not also move the digest the human is
  comparing against their terminal.
-->
<script setup>
import { computed } from 'vue'
import { CHASSIS_DEFS, CHASSIS_BODY } from '../assets/chassis.svg.js'
import { indexMark, ribs } from '../lib/dial.js'

const props = defineProps({
  /** The pending request, or null for a dark screen. */
  request: { type: Object, default: null },
  /** Dial rotation in degrees. */
  rotation: { type: Number, default: 0 },
  /** 0..1 — how much of the required hold has accumulated. */
  holdProgress: { type: Number, default: 0 },
  /** idle · arming · armed · holding · approved · declined · expired */
  state: { type: String, default: 'idle' },
  /** Whether the screen has finished rendering (the arm delay runs from here). */
  rendered: { type: Boolean, default: true },
})

// ── The screen's own coordinate space, straight off the study ────────────
const SCREEN = 'matrix(4.89406,1.17539,-2.06804,4.24156,-60.814,-334.358)'
const W = 73.4
const PAD = 3.2

/** Monospace advance as a fraction of font size, measured off the study. */
const ADVANCE = 0.6

function fit(text, fontSize, width = W - PAD * 2) {
  const max = Math.floor(width / (fontSize * ADVANCE))
  if (text.length <= max) return [text]
  return [text.slice(0, Math.max(1, max - 1)) + '…']
}

/**
 * Lay the statement out, dropping to a second line and a smaller face rather
 * than truncating early.
 *
 * §6 allows truncation on screen — the signature covers the full text either
 * way — but a screen that gives up after nineteen characters shows the verb and
 * hides the object, which is the half that matters. Two lines at a smaller size
 * roughly doubles what survives before the ellipsis.
 */
function layOutStatement(text) {
  const perLine = (size) => Math.floor((W - PAD * 2) / (size * ADVANCE))

  if (text.length <= perLine(5.6)) {
    return { size: 5.6, lines: [text], advisoryTop: 25.6 }
  }

  const size = 4.6
  const max = perLine(size)
  const head = text.slice(0, max)
  const rest = text.slice(max)
  return {
    size,
    lines: [head, rest.length <= max ? rest : rest.slice(0, Math.max(1, max - 1)) + '…'],
    // Pushed clear of the second line, and still above the divider at 34.2.
    advisoryTop: 27,
  }
}

const dialRibs = computed(() => ribs(props.rotation))
const mark = computed(() => indexMark(props.rotation))

const labelLine = computed(() => props.request?.render?.find((l) => l.role === 'label')?.text ?? null)

const advisoryLines = computed(() =>
  (props.request?.render ?? []).filter((l) => l.role === 'advisory').map((l) => l.text).slice(0, 2),
)

/** The statement, taken from the request's own bytes. */
const statement = computed(() => {
  if (!props.request) return null
  try {
    return JSON.parse(props.request.request_json).statement
  } catch {
    return null
  }
})

const layout = computed(() =>
  statement.value ? layOutStatement(statement.value) : { size: 5.6, lines: [], advisoryTop: 25.6 },
)

/** The label bar's colour. Production is the study's red; anything else is quieter. */
const labelFill = computed(() => {
  const text = (labelLine.value ?? '').toLowerCase()
  if (!labelLine.value) return '#4a4f57'
  if (/(prod|live)/.test(text)) return '#b0261b'
  if (/(stag|pre-?prod|uat)/.test(text)) return '#8a6320'
  return '#2f4a35'
})

const screenLit = computed(() => props.request !== null && props.rendered)

/** How far the HOLD pill has filled. The study draws it 5.2 of 14.7 wide. */
const holdFill = computed(() => Math.max(0.6, 14.7 * Math.min(1, Math.max(0, props.holdProgress))))

const holdLabel = computed(() => {
  switch (props.state) {
    case 'arming': return 'READ'
    case 'holding': return 'HOLD'
    case 'approved': return 'DONE'
    case 'declined': return 'NO'
    case 'expired': return 'GONE'
    default: return 'HOLD'
  }
})
</script>

<template>
  <svg
    class="device"
    viewBox="-348 -721 1043 828"
    role="img"
    :aria-label="request ? `Signet showing ${statement}` : 'Signet, idle'"
  >
    <!-- eslint-disable-next-line vue/no-v-html -- generated from the form study -->
    <defs v-html="CHASSIS_DEFS.replace(/<\/?defs>/g, '')" />

    <!-- The chassis: the study's polygons, unchanged. -->
    <!-- eslint-disable-next-line vue/no-v-html -->
    <g v-html="CHASSIS_BODY" />

    <!-- The dial's knurl ribs, at the current rotation. -->
    <g>
      <line
        v-for="rib in dialRibs"
        :key="rib.key"
        :x1="rib.x" :y1="rib.y1" :x2="rib.x" :y2="rib.y2"
        :stroke="rib.colour"
        :opacity="rib.opacity"
        stroke-width="1.5"
        stroke-linecap="round"
      />
    </g>

    <!-- The index mark: the one thing on the dial you can watch move. -->
    <line
      :x1="mark.x1" :y1="mark.y1" :x2="mark.x2" :y2="mark.y2"
      :stroke="mark.colour" :opacity="mark.opacity"
      :stroke-width="mark.width"
      stroke-linecap="round"
    />

    <!-- The screen. -->
    <g :transform="SCREEN">
      <rect :width="W" height="48.9" fill="#07080a" />

      <template v-if="screenLit">
        <!-- label — the daemon's, from local config. A requester never gets to
             claim which environment it is talking to. -->
        <rect :width="W" height="9" :fill="labelFill" />
        <text
          v-if="labelLine"
          :x="PAD" y="6.4"
          class="s-label"
          font-size="4.6"
        >{{ fit(labelLine, 4.6)[0] }}</text>

        <!-- primary — the statement, verbatim from the signed bytes. -->
        <text
          v-for="(line, i) in layout.lines"
          :key="i"
          :x="PAD"
          :y="layout.lines.length > 1 ? 15.8 + i * 5.6 : 18.4"
          class="s-primary"
          :font-size="layout.size"
        >{{ line }}</text>

        <!-- advisory — requester-supplied and unverified, and the screen says
             so. Nothing here may relax anything. -->
        <template v-if="advisoryLines.length">
          <text
            v-for="(line, i) in advisoryLines"
            :key="`adv-${i}`"
            :x="PAD"
            :y="layout.advisoryTop + i * 4.6"
            class="s-advisory"
            font-size="3.4"
            :opacity="i === 0 ? 1 : 0.78"
          >{{ fit(line, 3.4, 50)[0] }}</text>
          <!-- The unverified marker §2.4 requires: advisory content must be
               visibly distinguishable from the statement and the label. -->
          <rect x="55.5" :y="layout.advisoryTop - 3.7" width="14.7" height="4.9" rx="1.1"
                fill="none" stroke="#d9a441" stroke-width="0.4" opacity="0.9" />
          <text x="56.9" :y="layout.advisoryTop - 0.1" class="s-advisory" font-size="3" font-weight="700">UNVER</text>
        </template>

        <line :x1="PAD" y1="34.2" :x2="W - PAD" y2="34.2" stroke="#262c33" stroke-width="0.4" />

        <!-- digest — the human's cross-check, and the daemon's to write. -->
        <text :x="PAD" y="41.8" class="s-dim" font-size="2.8">DIGEST</text>
        <text x="16" y="42.2" class="s-digest" font-size="4.2">{{ request.digest_short }}</text>

        <!-- The hold pill: the study drew it part-filled; here it means it. -->
        <rect x="55.5" y="37.6" width="14.7" height="5.6" rx="2.8" fill="#161b21" />
        <rect
          x="55.5" y="37.6" :width="holdFill" height="5.6" rx="2.8"
          :fill="state === 'declined' ? '#9d5250' : '#e08a4c'"
        />
        <text x="57.6" y="41.4" class="s-pill" font-size="2.8">{{ holdLabel }}</text>
      </template>

      <!-- Nothing pending: the screen is off, not blank-with-a-message. -->
      <text v-else :x="PAD" y="26" class="s-dim" font-size="4.2">
        {{ request ? '' : 'no request' }}
      </text>
    </g>
  </svg>
</template>

<style scoped>
.device {
  display: block;
  width: 100%;
  height: auto;
  /* The study's own drop shadow is baked into the artwork; this is only the
     lift that keeps the object from sitting flat on the page. */
  filter: drop-shadow(0 18px 40px rgb(0 0 0 / 0.55));
}

.device text {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}

.s-label { fill: #fff; font-weight: 700; }
.s-primary { fill: #f2f5f8; font-weight: 700; }
.s-advisory { fill: #d9a441; }
.s-dim { fill: #5d666f; }
.s-digest { fill: #9fb3c4; }
.s-pill { fill: #c9d1d9; font-weight: 700; }
</style>
