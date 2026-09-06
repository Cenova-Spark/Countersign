// ─────────────────────────────────────────────────────────────────────────
//  Drawing the dial at an arbitrary rotation.
//
//  The dial is an isometric cylinder. Its wall is rotationally symmetric, so
//  turning it does not change the wall, the top face or the centre cap at all —
//  it moves exactly two things: the knurl ribs around the wall, and the amber
//  index mark on the face. Everything else in the artwork is static, which is
//  why `chassis.svg.js` can be emitted once and never re-rendered.
//
//  Geometry constants come from `assets/dial.js`, fitted to the form study by
//  `scripts/build-chassis.mjs`. Nothing here is a magic number.
// ─────────────────────────────────────────────────────────────────────────
import {
  WALL, WALL_HEIGHT, FACE, CAP,
  RIB_COUNT, RIB_SPACING_DEG, RIB_PHASE_DEG,
  KEY_LIGHT, INDEX_MARK,
} from '../assets/dial.js'

export { WALL, FACE, CAP, INDEX_MARK }

const RAD = Math.PI / 180

/**
 * Project a point on the dial onto the study's coordinate system.
 *
 * `angle` is the position around the dial in degrees; `r` is 0 at the axis and
 * 1 at the rim. In this projection +sin(angle) is *toward the viewer*, so the
 * front half of the dial — the half you can actually see — is 0°..180°.
 */
export function project(ellipse, angle, r = 1) {
  return {
    x: ellipse.cx + ellipse.rx * r * Math.cos(angle * RAD),
    y: ellipse.cy + ellipse.ry * r * Math.sin(angle * RAD),
  }
}

/** Is this angle on the visible, viewer-facing half of the dial? */
export function isFrontFacing(angle) {
  return Math.sin(angle * RAD) > 0
}

function lerpHex(a, b, t) {
  const pa = [1, 3, 5].map((i) => parseInt(a.slice(i, i + 2), 16))
  const pb = [1, 3, 5].map((i) => parseInt(b.slice(i, i + 2), 16))
  const mix = pa.map((v, i) => Math.round(v + (pb[i] - v) * t))
  return `#${mix.map((v) => v.toString(16).padStart(2, '0')).join('')}`
}

/**
 * The colour a rib takes at a given **screen** angle.
 *
 * Keyed on where the rib currently is, never on which rib it is. The lamp is
 * fixed in the world; the dial turns under it. Get this backwards and the
 * shading rotates with the ribs, which reads as a texture sliding sideways
 * rather than as a solid object turning — the single most common way a
 * rotating knurl animation looks wrong.
 */
export function ribColour(angle) {
  const a = ((angle % 360) + 360) % 360
  // The study only measured the front half. Mirror across the 0°–180° axis for
  // anything behind, which is hidden anyway but keeps the function total.
  const sampled = a <= 180 ? a : 360 - a

  let lo = KEY_LIGHT[0]
  let hi = KEY_LIGHT[KEY_LIGHT.length - 1]
  for (let i = 0; i < KEY_LIGHT.length - 1; i += 1) {
    if (sampled >= KEY_LIGHT[i].angle && sampled <= KEY_LIGHT[i + 1].angle) {
      lo = KEY_LIGHT[i]
      hi = KEY_LIGHT[i + 1]
      break
    }
  }
  if (sampled < lo.angle) return lo.colour
  if (sampled > hi.angle) return hi.colour
  const span = hi.angle - lo.angle
  return span === 0 ? lo.colour : lerpHex(lo.colour, hi.colour, (sampled - lo.angle) / span)
}

/**
 * Every visible knurl rib, at a given rotation.
 *
 * Ribs near the silhouette are foreshortened to nothing by the projection, so
 * they are faded out rather than popping in and out at the edges — the
 * projection already compresses them, and the opacity just stops the last few
 * pixels from flickering as one crosses over.
 */
export function ribs(rotationDeg) {
  const out = []
  for (let i = 0; i < RIB_COUNT; i += 1) {
    const angle = RIB_PHASE_DEG + i * RIB_SPACING_DEG + rotationDeg
    if (!isFrontFacing(angle)) continue
    const top = project(WALL, angle)
    // How side-on the rib is: 1 facing the viewer, 0 at the silhouette.
    const facing = Math.abs(Math.sin(angle * RAD))
    out.push({
      key: i,
      x: top.x,
      y1: top.y,
      y2: top.y + WALL_HEIGHT,
      colour: ribColour(angle),
      opacity: Math.min(1, facing * 4),
    })
  }
  return out
}

/** The amber index mark, at a given rotation. */
export function indexMark(rotationDeg) {
  const angle = INDEX_MARK.angle + rotationDeg
  const outer = project(FACE, angle, INDEX_MARK.outerR)
  const inner = project(FACE, angle, INDEX_MARK.innerR)
  return {
    x1: outer.x, y1: outer.y,
    x2: inner.x, y2: inner.y,
    colour: INDEX_MARK.colour,
    width: INDEX_MARK.width,
    // The mark is on the top face, which is fully visible from this angle, so
    // it never hides — but it does foreshorten, and dimming with it keeps the
    // apparent brightness even as it sweeps.
    opacity: 0.55 + 0.45 * Math.abs(Math.sin(angle * RAD)),
  }
}

/**
 * The detent the dial rests in.
 *
 * The physical dial has 36 ribs, so it has 36 detents — one every 10°. A hold
 * that is released early springs back to the detent it started from; a
 * committed hold has advanced exactly one.
 */
export const DETENT_DEG = RIB_SPACING_DEG

/** How far the dial turns over a full approving hold. */
export const COMMIT_DEG = DETENT_DEG * 3
