// ─────────────────────────────────────────────────────────────────────────
//  What a pending request looks like on the wire, and what the relay checks.
//
//  The single most important thing in this file is what it *carries*: the
//  request as **raw JSON, exactly as signetd sent it**. Not a rendered summary.
//
//  Wire spec §6 says the device renders from the bytes it will sign, and §9
//  refuses a display field separate from the signed payload, because that is
//  blind signing. Those rules exist for firmware, where the threat is a
//  malicious requester. Here there is a second untrusted party — this relay —
//  and the same rule is what defends against it. The phone recomputes
//  `SHA-256(jcs(request))` from these bytes and refuses to show anything if it
//  disagrees with the digest it was handed, so a relay that swapped a
//  `SELECT 1` for a `DROP TABLE` cannot get a signature over the swap.
//
//  A relay is therefore able to *drop* a request or *see* it. It is not able to
//  change one, and it holds nothing that could sign one.
// ─────────────────────────────────────────────────────────────────────────

/** Roles the daemon owns and a pack may never write — spec §6. */
const DAEMON_ROLES = new Set(['label', 'digest'])
const ROLES = new Set(['label', 'primary', 'advisory', 'digest'])

export class RelayError extends Error {
  constructor(status, code, message) {
    super(message)
    this.status = status
    this.code = code
  }
}

const str = (v, name, max = 4096) => {
  if (typeof v !== 'string' || v.length === 0 || v.length > max) {
    throw new RelayError(400, 'bad_presentation', `${name} must be a string of 1..${max} characters`)
  }
  return v
}

const int = (v, name, min, max) => {
  if (!Number.isInteger(v) || v < min || v > max) {
    throw new RelayError(400, 'bad_presentation', `${name} must be an integer in [${min}, ${max}]`)
  }
  return v
}

export const SEVERITIES = ['none', 'low', 'moderate', 'high', 'critical']

/**
 * Arm delay and hold, mirroring `signetd::device`.
 *
 * Duplicated rather than transmitted **on purpose**. If the timings travelled
 * in the payload, a party that could edit the payload could ask for a 0 ms
 * hold, and the relay is exactly such a party. These are the reference
 * daemon's numbers; the phone applies them from severity, which is bound to
 * the request through the digest.
 */
export function timings(severity) {
  switch (severity) {
    case 'none':
    case 'low':
      return { arm_delay_ms: 400, hold_ms: 300 }
    case 'moderate':
      return { arm_delay_ms: 700, hold_ms: 800 }
    case 'high':
      return { arm_delay_ms: 1200, hold_ms: 2000 }
    default:
      // Unknown severity gets the strictest timings, not the loosest.
      return { arm_delay_ms: 2000, hold_ms: 5000 }
  }
}

/** Validate what signetd posted, without trusting any of it. */
export function parsePresentation(body) {
  if (!body || typeof body !== 'object') {
    throw new RelayError(400, 'bad_presentation', 'expected a JSON object')
  }

  const requestJson = str(body.request_json, 'request_json', 64 * 1024)
  let request
  try {
    request = JSON.parse(requestJson)
  } catch {
    throw new RelayError(400, 'bad_presentation', 'request_json is not JSON')
  }
  if (!request || typeof request !== 'object' || typeof request.statement !== 'string') {
    throw new RelayError(400, 'bad_presentation', 'request_json is not a Countersign request')
  }

  const digest = str(body.request_digest, 'request_digest', 64)
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new RelayError(400, 'bad_presentation', 'request_digest must be 64 lowercase hex characters')
  }

  const render = Array.isArray(body.render) ? body.render : []
  for (const line of render) {
    if (!line || typeof line !== 'object' || !ROLES.has(line.role) || typeof line.text !== 'string') {
      throw new RelayError(400, 'bad_presentation', 'each render line needs a known role and text')
    }
  }
  // The daemon writes `label` and `digest`; a pack may not, and a host must
  // reject a pack response containing them (spec §6). Checked again here
  // because this is a second host and the rule is cheap to hold.
  const labels = render.filter((l) => l.role === 'label')
  if (labels.length > 1) {
    throw new RelayError(400, 'bad_presentation', 'more than one label line')
  }

  const severity = SEVERITIES.includes(body.severity) ? body.severity : 'critical'

  return {
    request_json: requestJson,
    request_digest: digest,
    // The first 12 hex characters — what the human compares against their
    // terminal. Recomputed here rather than accepted, so it cannot disagree.
    digest_short: digest.slice(0, 12).replace(/(.{4})/g, '$1 ').trim(),
    render: render.filter((l) => !DAEMON_ROLES.has(l.role) || l.role === 'label'),
    severity,
    action: str(body.action ?? request.action ?? 'unknown', 'action', 128),
    requester: str(body.requester ?? 'unknown', 'requester', 256),
    requester_changed: body.requester_changed !== false,
    ttl_ms: int(body.ttl_ms ?? 60000, 'ttl_ms', 1000, 15 * 60 * 1000),
    statement: request.statement,
    ...timings(severity),
  }
}

/** The shape the browser receives. Never includes a token or a key. */
export function publicRequest(id, presentation, createdAt) {
  return {
    id,
    request_json: presentation.request_json,
    request_digest: presentation.request_digest,
    digest_short: presentation.digest_short,
    render: presentation.render,
    severity: presentation.severity,
    action: presentation.action,
    requester: presentation.requester,
    requester_changed: presentation.requester_changed,
    arm_delay_ms: presentation.arm_delay_ms,
    hold_ms: presentation.hold_ms,
    ttl_ms: presentation.ttl_ms,
    created_at: createdAt,
    expires_at: createdAt + presentation.ttl_ms,
  }
}
