// ─────────────────────────────────────────────────────────────────────────
//  The three rules of §6.2.3 and §6.3.4, on a clock we control.
//
//  These are the rules the product is actually made of, and each of them is
//  easy to implement in a way that looks right and is not. Driven here by a
//  fake clock and a fake animation loop so the failures show up as assertions
//  rather than as "it felt wrong on my phone".
// ─────────────────────────────────────────────────────────────────────────
import './setup.js'
import test from 'node:test'
import assert from 'node:assert/strict'
import { computed, effectScope } from 'vue'

// A clock and an animation loop that only move when told to.
let clock = 0
const pending = new Map()
let nextHandle = 1

globalThis.performance = { now: () => clock }
globalThis.requestAnimationFrame = (fn) => {
  const handle = nextHandle++
  pending.set(handle, fn)
  return handle
}
globalThis.cancelAnimationFrame = (handle) => pending.delete(handle)
globalThis.document = { visibilityState: 'visible', addEventListener() {}, removeEventListener() {} }

/** Advance the clock in frame-sized steps, running the loop each time. */
function advance(ms, stepMs = 16) {
  const target = clock + ms
  while (clock < target) {
    clock = Math.min(target, clock + stepMs)
    const due = [...pending.entries()]
    pending.clear()
    for (const [, fn] of due) fn()
  }
}

/** Jump the clock without running frames — a backgrounded tab. */
function freeze(ms) {
  clock += ms
  const due = [...pending.entries()]
  pending.clear()
  for (const [, fn] of due) fn()
}

const { useHold } = await import('../src/lib/hold.js')

function harness({ armDelayMs = 2000, holdMs = 5000 } = {}) {
  const scope = effectScope()
  let committed = null
  const hold = scope.run(() =>
    useHold({
      armDelayMs: computed(() => armDelayMs),
      holdMs: computed(() => holdMs),
      enabled: computed(() => true),
      onCommit: (info) => {
        committed = info
      },
    }),
  )
  return {
    hold,
    committed: () => committed,
    stop: () => {
      hold.teardown()
      scope.stop()
    },
  }
}

test('a press before the arm delay does nothing at all', () => {
  clock = 0
  const { hold, committed, stop } = harness()
  hold.armFrom(clock)

  advance(500)
  assert.equal(hold.phase.value, 'arming')

  // Not "starts a shorter hold" — nothing. The press is not an actuation yet.
  hold.press()
  advance(1000)
  assert.equal(hold.phase.value, 'arming')
  assert.equal(hold.holdProgress.value, 0)
  assert.equal(committed(), null)
  stop()
})

test('a full hold after the arm delay commits, and only then', () => {
  clock = 0
  const { hold, committed, stop } = harness()
  hold.armFrom(clock)

  advance(2100)
  assert.equal(hold.phase.value, 'armed')

  hold.press()
  advance(4800)
  assert.equal(hold.phase.value, 'holding', 'not yet — 5s means 5s')
  assert.equal(committed(), null)
  assert.ok(hold.holdProgress.value > 0.9)

  advance(300)
  assert.equal(hold.phase.value, 'committed')
  assert.ok(committed().dwellMs >= 5000)
  stop()
})

test('letting go early gives the whole hold back', () => {
  clock = 0
  const { hold, committed, stop } = harness()
  hold.armFrom(clock)
  advance(2100)

  hold.press()
  advance(4000)
  assert.ok(hold.holdProgress.value > 0.75, 'most of the way there')

  hold.release()
  advance(400)
  // §6.3.4: an accumulated hold is discarded if engagement lapses. Not paused,
  // not banked — discarded.
  assert.equal(hold.holdProgress.value, 0)

  hold.press()
  advance(4000)
  assert.equal(committed(), null, 'a second 4s hold must not finish the first one')
  stop()
})

test('a thumb already down when the payload renders must lift first', () => {
  clock = 0
  const { hold, committed, stop } = harness()

  // Engaged before the payload exists — the ordinary case: the previous
  // request has just committed and the hand has not come back yet.
  hold.press()
  hold.armFrom(clock)

  advance(2500)
  // The arm delay has passed, but the control has not been at rest since the
  // payload appeared, so it is not approvable. This is the case the arm delay
  // alone does not catch, which is why §6.2.3 states it separately.
  assert.equal(hold.phase.value, 'rest')

  hold.press()
  advance(6000)
  assert.equal(committed(), null, 'a hold that began before the payload cannot approve it')

  // Lifting is what satisfies it.
  hold.release()
  advance(50)
  assert.equal(hold.phase.value, 'armed')

  hold.press()
  advance(5100)
  assert.ok(committed(), 'a fresh press from rest approves normally')
  stop()
})

test('a backgrounded tab discards the hold instead of banking it', () => {
  clock = 0
  const { hold, committed, stop } = harness()
  hold.armFrom(clock)
  advance(2100)

  hold.press()
  advance(1000)
  assert.ok(hold.holdProgress.value > 0.15)

  // The screen slept for half a minute. Nobody's thumb was verifiably on the
  // control across that, and `now - holdStartedAt` would happily call it a
  // 31-second hold.
  freeze(30_000)
  assert.equal(hold.holdProgress.value, 0)
  assert.equal(committed(), null, 'waking up must not approve anything')

  // And rest has to be re-established, because engagement across the gap
  // cannot be established either.
  advance(100)
  assert.equal(hold.phase.value, 'rest')
  stop()
})

test('a new payload restarts the arm delay', () => {
  clock = 0
  const { hold, committed, stop } = harness()
  hold.armFrom(clock)
  advance(1900)

  // Another request arrives 100ms before this one was approvable.
  hold.armFrom(clock)
  advance(1000)
  hold.press()
  advance(6000)
  assert.equal(committed(), null, 'the new payload gets its own full arm delay')
  stop()
})

test('severity scales the friction', () => {
  clock = 0
  // A `low` action gets a beat; `critical` gets long enough to be a decision.
  const low = harness({ armDelayMs: 400, holdMs: 300 })
  low.hold.armFrom(clock)
  advance(500)
  low.hold.press()
  advance(350)
  assert.ok(low.committed(), 'low severity commits quickly')
  low.stop()
})
