// ─────────────────────────────────────────────────────────────────────────
//  Derive the app's device artwork from the Phase 1 form study.
//
//  `public/signet-form-study.svg` is the drawing of record. This script splits
//  it into the parts the app animates and the parts it does not, so the artwork
//  is never hand-copied and never drifts from the study.
//
//  What comes out:
//    src/assets/chassis.svg.js  the body, verbatim, minus the moving parts
//    src/assets/dial.js         fitted dial geometry + the measured key light
//
//  Three things move, and only three. The dial's side wall is a cylinder, so it
//  is rotationally symmetric and looks identical at every angle — rotating it
//  means moving the 18 knurl ribs and the amber index mark, and nothing else.
//  The screen is live, so its <g> is dropped and re-rendered from real payload.
//
//    node scripts/build-chassis.mjs
// ─────────────────────────────────────────────────────────────────────────
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const svg = readFileSync(join(root, 'public/signet-form-study.svg'), 'utf8')

// ── 1. The knurl ribs ────────────────────────────────────────────────────
// 1.50-wide round-capped verticals on the dial wall. Their tops trace the
// dial's top ellipse, which is how the ellipse below is fitted rather than
// eyeballed.
const KNURL = /<line x1="([-\d.]+)" y1="([-\d.]+)" x2="([-\d.]+)" y2="([-\d.]+)" stroke="(#[0-9a-fA-F]{6})" stroke-width="1\.50"[^>]*\/>/g
const knurls = [...svg.matchAll(KNURL)].map((m) => ({
  x: +m[1],
  yBottom: +m[2],
  yTop: +m[4],
  colour: m[5],
}))
if (knurls.length !== 18) throw new Error(`expected 18 knurl ribs, found ${knurls.length}`)

const wallHeight = knurls[0].yBottom - knurls[0].yTop

// ── 2. Fit the dial's top ellipse to the rib tops ────────────────────────
// ((x-cx)/rx)^2 + ((y-cy)/ry)^2 = 1, by coordinate descent. The study was
// drawn from a real projection, so this converges to ~1e-4 RMS — the fit is
// recovering the original parameters, not approximating them.
function fitEllipse(points) {
  const cost = ([cx, rx, cy, ry]) =>
    points.reduce((acc, p) => {
      const t = ((p.x - cx) / rx) ** 2 + ((p.yTop - cy) / ry) ** 2 - 1
      return acc + t * t
    }, 0)

  let best = [264.7, 124.0, -579.4, 64.0]
  for (let step = 8; step > 1e-5; step /= 2) {
    for (let moved = true; moved; ) {
      moved = false
      for (let i = 0; i < 4; i += 1) {
        for (const d of [step, -step]) {
          const cand = best.slice()
          cand[i] += d
          if (cand[1] > 1 && cand[3] > 1 && cost(cand) < cost(best)) {
            best = cand
            moved = true
          }
        }
      }
    }
  }
  return { cx: best[0], rx: best[1], cy: best[2], ry: best[3], rms: Math.sqrt(cost(best) / points.length) }
}

const wall = fitEllipse(knurls)
if (wall.rms > 0.01) throw new Error(`dial ellipse fit is too loose (rms ${wall.rms})`)

const angleOf = (p) =>
  ((Math.atan2((p.yTop - wall.cy) / wall.ry, (p.x - wall.cx) / wall.rx) * 180) / Math.PI + 360) % 360

// ── 3. The key light, sampled rather than modelled ───────────────────────
// Rib shading in the study is not a clean cosine — there is a rim lift at both
// silhouette edges on top of a key light around 147°. Rather than fit a lamp,
// carry the 18 measured samples and interpolate between them. Shading is keyed
// on screen angle, never on which rib it is, so the light stays fixed in world
// space while the dial turns under it. That is what makes rotation read as
// rotation instead of as a sliding texture.
const light = knurls
  .map((k) => ({ angle: angleOf(k), colour: k.colour }))
  .sort((a, b) => a.angle - b.angle)

// Snap to a whole number of ribs. The measured gap lands a few thousandths off
// 10° because the study's coordinates are rounded to 2dp, and an un-snapped
// spacing accumulates that error into a visible drift by the 36th rib.
const measured = light.length > 1 ? light[1].angle - light[0].angle : 10
const ribCount = Math.round(360 / measured)
const spacing = 360 / ribCount
if (Math.abs(spacing - measured) > 0.05) {
  throw new Error(`rib spacing ${measured}° is not 360/${ribCount}; the ribs are not evenly placed`)
}

// ── 4. The amber index mark ──────────────────────────────────────────────
// A radial line on the dial's top face. Recovered as (angle, inner r, outer r)
// in the top face's own normalized ellipse space so it can be redrawn at any
// rotation.
const INDEX = /<line x1="([-\d.]+)" y1="([-\d.]+)" x2="([-\d.]+)" y2="([-\d.]+)" stroke="#E08A4C" stroke-width="2\.8"[^>]*\/>/
const im = svg.match(INDEX)
if (!im) throw new Error('index mark not found')

// The top face: polygon 90, the largest ellipse above the wall.
const polygons = [...svg.matchAll(/<polygon points="([^"]+)"([^>]*)\/>/g)]
function bboxEllipse(index) {
  const pts = polygons[index][1].trim().split(/\s+/).map((p) => p.split(',').map(Number))
  const xs = pts.map((p) => p[0])
  const ys = pts.map((p) => p[1])
  return {
    cx: (Math.min(...xs) + Math.max(...xs)) / 2,
    cy: (Math.min(...ys) + Math.max(...ys)) / 2,
    rx: (Math.max(...xs) - Math.min(...xs)) / 2,
    ry: (Math.max(...ys) - Math.min(...ys)) / 2,
  }
}
const face = bboxEllipse(90)
const cap = bboxEllipse(91)

const polar = (x, y) => {
  const u = (x - face.cx) / face.rx
  const v = (y - face.cy) / face.ry
  return { r: Math.hypot(u, v), angle: ((Math.atan2(v, u) * 180) / Math.PI + 360) % 360 }
}
const outer = polar(+im[1], +im[2])
const inner = polar(+im[3], +im[4])
if (Math.abs(outer.angle - inner.angle) > 1) {
  throw new Error('index mark is not radial; the recovery above assumes it is')
}

// ── 5. The chassis: everything that does not move ────────────────────────
// Dropped: the ribs, the index mark, the live screen <g>, the study's own
// background plate and its dimension caption. Kept verbatim: every polygon of
// the body, the dial's wall and faces, and the two button caps.
let chassis = svg
  .replace(KNURL, '')
  .replace(INDEX, '')
  // The screen <g> — matched by its transform so a colour change upstream
  // cannot silently leave a dead screen baked into the chassis.
  .replace(/<g transform="matrix\(4\.89406,1\.17539,-2\.06804,4\.24156,-60\.814,-334\.358\)">[\s\S]*?<\/g>/, '')
  // The study's background plate; the app supplies its own ground.
  .replace(/<rect x="-380\.1"[^>]*\/>/, '')
  // The dimension caption; the app renders its own.
  .replace(/<text x="-350\.1"[\s\S]*?<\/text>\s*/g, '')

const body = chassis.match(/<svg[^>]*>([\s\S]*)<\/svg>/)[1].trim()
const defs = body.match(/<defs>[\s\S]*?<\/defs>/)[0]
const content = body.replace(/<defs>[\s\S]*?<\/defs>/, '').trim()

const banner = `// GENERATED by scripts/build-chassis.mjs from public/signet-form-study.svg.
// Do not edit; edit the form study and re-run the script.\n`

writeFileSync(
  join(root, 'src/assets/chassis.svg.js'),
  `${banner}export const CHASSIS_DEFS = ${JSON.stringify(defs)}\n\nexport const CHASSIS_BODY = ${JSON.stringify(content)}\n`,
)

writeFileSync(
  join(root, 'src/assets/dial.js'),
  `${banner}
/** The dial's side wall, fitted to the study's knurl ribs. */
export const WALL = ${JSON.stringify({ cx: wall.cx, cy: wall.cy, rx: wall.rx, ry: wall.ry }, null, 2)}

/** How tall the wall is, in study units. */
export const WALL_HEIGHT = ${wallHeight}

/** The dial's top face and its centre cap. */
export const FACE = ${JSON.stringify(face, null, 2)}
export const CAP = ${JSON.stringify(cap, null, 2)}

/** Ribs are every ${spacing}° all the way round; the front half is what shows. */
export const RIB_COUNT = ${ribCount}
export const RIB_SPACING_DEG = ${spacing}
export const RIB_PHASE_DEG = ${light[0].angle}

/**
 * The key light, as measured off the study.
 *
 * Keyed on screen angle, not on rib identity — the lamp does not turn with the
 * dial. Interpolate between samples; see \`ribColour\` in lib/dial.js.
 */
export const KEY_LIGHT = ${JSON.stringify(light, null, 2)}

/** The amber index mark, in the top face's normalized ellipse space. */
export const INDEX_MARK = ${JSON.stringify(
    { angle: (outer.angle + inner.angle) / 2, innerR: inner.r, outerR: outer.r, colour: '#E08A4C', width: 2.8 },
    null,
    2,
  )}
`,
)

console.log(`chassis.svg.js  ${content.length} bytes of body`)
console.log(`dial.js         wall rms=${wall.rms.toExponential(2)} ribs=${ribCount}@${spacing}° index=${((outer.angle + inner.angle) / 2).toFixed(1)}°`)
