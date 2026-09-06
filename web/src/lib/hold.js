// ─────────────────────────────────────────────────────────────────────────
//  The approving actuation.
//
//  Wire spec §6.2.3 and §6.3.4 name three requirements, and they are three
//  because each defends something the others do not:
//
//    Arm delay        elapsed since the payload finished rendering
//                     → you cannot approve what you have not had time to read
//    Rest transition  the actuator was observed at rest *after* that
//                     → you cannot approve with a movement that began before
//                       the payload existed
//    Hold             continuous engagement for the whole duration
//                     → you cannot approve something while reaching for
//                       something else
//
//  All three are implemented here rather than collapsed into one timer,
//  because collapsing them is exactly the shortcut the spec spends a section
//  warning about. Elapsed time can be spent looking away. A hold cannot.
//  Neither one establishes that the hand moved at all once the payload was on
//  screen — only the rest transition does that, and it is the one that catches
//  the ordinary case: a thumb still pressed from the previous request when the
//  next one renders.
//
//  What this is **not** is an anti-automation measure, and §9 is emphatic on
//  the point. A script can produce any hold you ask it for. This is friction
//  for a cooperating human protecting themselves from their own tools, which is
//  the entire threat model.
// ─────────────────────────────────────────────────────────────────────────
import { computed, getCurrentInstance, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { COMMIT_DEG, DETENT_DEG } from './dial.js'

/**
 * The longest gap between frames that still counts as continuous engagement.
 *
 * Generous next to a 60 Hz frame, tight next to a tab switch.
 */
const LAPSE_MS = 400

export function useHold({ armDelayMs, holdMs, onCommit, enabled }) {
  /** idle · arming · rest · armed · holding · committed */
  const phase = ref('idle')
  const rotation = ref(0)
  const holdProgress = ref(0)

  const engaged = ref(false)
  const armProgress = ref(0)
  const armedAt = shallowRef(null)
  const holdStartedAt = shallowRef(null)
  const restSeen = ref(false)
  const dwellMs = ref(0)

  let frame = null
  let springFrom = 0
  let springStartedAt = null
  let lastFrameAt = null

  const requiredHold = computed(() => holdMs.value ?? 5000)
  const requiredArm = computed(() => armDelayMs.value ?? 2000)

  /**
   * Begin the arm delay.
   *
   * Called when the payload has finished rendering — *not* when it arrived.
   * The gap between those two is precisely the time the payload was not
   * readable, so measuring from arrival would hand that time back.
   *
   * Any new payload restarts everything, including the rest requirement: if a
   * finger is already down, it counts as never having been at rest.
   */
  function armFrom(now = performance.now()) {
    armedAt.value = now
    armProgress.value = 0
    holdStartedAt.value = null
    holdProgress.value = 0
    dwellMs.value = 0
    rotation.value = 0
    // A hand already on the control when the payload appeared has not been at
    // rest since the payload appeared. This is the whole point of §6.2.3's
    // second requirement, and it is why this is not simply `true`.
    restSeen.value = !engaged.value
    phase.value = 'arming'
    tick()
  }

  function disarm() {
    phase.value = 'idle'
    armedAt.value = null
    holdStartedAt.value = null
    holdProgress.value = 0
    rotation.value = 0
    stop()
  }

  function stop() {
    if (frame !== null) cancelAnimationFrame(frame)
    frame = null
  }

  /** Give back an accumulated hold, exactly as an early release would. */
  function lapse() {
    if (holdStartedAt.value === null) return
    springFrom = rotation.value
    springStartedAt = performance.now()
    holdStartedAt.value = null
    holdProgress.value = 0
    // Engagement across the gap cannot be established, so rest cannot be
    // assumed either — require a fresh press from a lifted thumb.
    restSeen.value = !engaged.value
  }

  function tick() {
    stop()
    lastFrameAt = null
    const step = () => {
      frame = null
      const now = performance.now()

      if (phase.value === 'committed' || phase.value === 'idle') return

      const armElapsed = armedAt.value === null ? 0 : now - armedAt.value
      const armReady = armElapsed >= requiredArm.value
      armProgress.value = Math.min(1, armElapsed / requiredArm.value)

      // A gap this long means the page stopped being animated — backgrounded,
      // screen off, another app in front. Whatever the cause, nobody's thumb
      // was verifiably on the control across it, so the accumulated hold is
      // discarded rather than credited. Without this, a hold measured as
      // `now - holdStartedAt` would come back from a 30-second sleep already
      // satisfied, and the page would approve on wake.
      const gap = lastFrameAt === null ? 0 : now - lastFrameAt
      lastFrameAt = now
      if (gap > LAPSE_MS && holdStartedAt.value !== null) {
        lapse()
        frame = requestAnimationFrame(step)
        return
      }

      if (holdStartedAt.value !== null) {
        // Engaged: accumulate.
        const held = now - holdStartedAt.value
        dwellMs.value = held
        holdProgress.value = Math.min(1, held / requiredHold.value)
        rotation.value = holdProgress.value * COMMIT_DEG

        if (holdProgress.value >= 1) {
          phase.value = 'committed'
          // Land on the detent rather than wherever the frame happened to fall.
          rotation.value = COMMIT_DEG
          onCommit?.({ dwellMs: held })
          return
        }
        phase.value = 'holding'
      } else {
        // Not engaged. Spring back to the detent the dial started from —
        // §6.3.4: an accumulated hold is discarded if engagement lapses, and
        // the dial visibly giving it all back is the honest way to show that.
        if (springStartedAt !== null) {
          const t = Math.min(1, (now - springStartedAt) / 260)
          // Slight overshoot, then settle. A detented encoder does this.
          const eased = 1 - Math.pow(1 - t, 3)
          const overshoot = Math.sin(t * Math.PI) * DETENT_DEG * 0.18
          rotation.value = springFrom * (1 - eased) - overshoot * (springFrom > 0 ? 1 : 0)
          holdProgress.value = 0
          if (t >= 1) {
            rotation.value = 0
            springStartedAt = null
          }
        }
        phase.value = armReady ? (restSeen.value ? 'armed' : 'rest') : 'arming'

        // Armed and settled with nothing to animate: stop the loop rather than
        // burn a phone's battery waiting for a thumb. `press()` restarts it.
        if (armReady && springStartedAt === null) return
      }

      frame = requestAnimationFrame(step)
    }
    frame = requestAnimationFrame(step)
  }

  function press() {
    if (!enabled.value) return
    engaged.value = true
    if (phase.value === 'committed' || phase.value === 'idle') return

    const now = performance.now()
    const armReady = armedAt.value !== null && now - armedAt.value >= requiredArm.value

    // Pressing before the payload has been readable, or without having been at
    // rest since it appeared, does nothing at all. Not "starts a shorter hold"
    // — nothing. The press is simply not an actuation yet.
    if (!armReady || !restSeen.value) return

    springStartedAt = null
    holdStartedAt.value = now
    phase.value = 'holding'
    tick()
  }

  function release() {
    engaged.value = false
    // Lifting is what satisfies the rest requirement: the control has now been
    // observed at rest *since* the payload appeared.
    restSeen.value = true

    if (phase.value === 'committed') return
    if (holdStartedAt.value !== null) {
      springFrom = rotation.value
      springStartedAt = performance.now()
      holdStartedAt.value = null
      holdProgress.value = 0
    }
    tick()
  }

  watch(enabled, (on) => {
    if (!on && phase.value !== 'committed') release()
  })

  // Leaving the page is an unambiguous lapse and does not need to be inferred
  // from frame timing. A blurred-but-visible window needs no separate handler:
  // the browser throttles its frames, and the gap check above catches that.
  function onVisibility() {
    if (document.visibilityState !== 'hidden') return
    engaged.value = false
    lapse()
  }
  document.addEventListener('visibilitychange', onVisibility)

  function teardown() {
    stop()
    document.removeEventListener('visibilitychange', onVisibility)
  }

  // Usable outside a component — the gesture rules are tested on their own,
  // with a fake clock, and that harness has no instance to hang a hook on.
  if (getCurrentInstance()) onBeforeUnmount(teardown)

  return {
    phase,
    rotation,
    holdProgress,
    armProgress,
    dwellMs,
    /** True once the payload has been readable AND the control has been at rest. */
    ready: computed(() => phase.value === 'armed' || phase.value === 'holding'),
    /** Armed, but a hand was already down when the payload appeared. */
    awaitingRest: computed(() => phase.value === 'rest'),
    armFrom,
    disarm,
    press,
    release,
    teardown,
  }
}
