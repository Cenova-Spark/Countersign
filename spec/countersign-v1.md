# Countersign v1 — wire format

Status: **draft**. Normative for the crates in this repository.
Licence: Apache-2.0.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

---

## 1. What a countersignature proves

> Proof that a specific enrolled key was physically actuated while a specific
> payload was displayed on a device the requesting software does not control.

It does **not** prove a human did it. Nothing in this document should be read as
a proof of personhood, and §9 forbids the one field people reach for when they
try to make it one.

Two properties carry the whole design:

1. **Content binding.** The bytes displayed on the device are derived from the
   bytes it signs. A verifier that recomputes the digest from its own copy of
   the request learns whether the approval covers *this* statement or a
   different one.
2. **Non-forgeability by the requester.** The requester cannot produce a
   signature, and cannot cause one to be produced without a physical actuation.

---

## 2. The request

```jsonc
{
  "v": 1,
  "nonce": "<32 random bytes, base64url unpadded>",
  "requester": {
    "id": "claude-code",
    "instance": "<opaque per-session id>",
    "pid": 48213
  },
  "action": "sql.execute",
  "target": {
    "kind": "database",
    "uri_fingerprint": "<lowercase hex SHA-256 of the connection URI>"
  },
  "statement": "DROP TABLE users;",
  "advisory": {
    "rows_affected": 4200000,
    "dependents": 3,
    "reversible": false
  },
  "ttl_ms": 60000
}
```

### 2.1 Field rules

| Field | Rule |
|---|---|
| `v` | MUST be `1`. |
| `nonce` | MUST be 32 bytes of CSPRNG output, base64url **unpadded**. Single use. |
| `requester.id` | Free-form. Advisory. A requester can claim any id. |
| `requester.pid` | OPTIONAL. The daemon MAY verify it against the peer credentials of the connection and MUST NOT trust it otherwise. |
| `action` | A namespaced verb (§2.2). |
| `target.uri_fingerprint` | SHA-256 of the connection URI, lowercase hex. Credentials MUST be stripped from the URI before hashing; see §2.3. |
| `statement` | The **full** text. MUST NOT be truncated. Truncation happens at render time only (§6). |
| `advisory` | Requester-supplied and **unverified**. See §2.4. |
| `ttl_ms` | Integer milliseconds. The daemon MAY clamp it downward. |

`target.label` is deliberately **absent from the request and MUST NOT be
added.** The environment label is assigned by the daemon from its own local
config, keyed on `uri_fingerprint`. A requester does not get to claim it is
talking to dev. This is one of the very few places the protocol can constrain a
careless or compromised agent, and it only works if the field never travels.

### 2.2 Actions are namespaced verbs, and the core never parses the payload

`sql.ddl`, `terraform.apply`, `k8s.delete`, `npm.publish`, `email.send`,
`payment.release`. The daemon routes on the namespace. It does not know what SQL
is; `statement` is an opaque string to everything in this document.

Domain knowledge lives in packs (see `pack-protocol-v1.md`), which is what keeps
this a protocol for authorizing *actions* rather than a protocol for databases.

### 2.3 Fingerprinting a target

The fingerprint exists so the daemon can recognise "the database I labelled
prod" without ever receiving a credential. Requesters MUST:

1. Remove userinfo (`user:password@`) from the URI.
2. Lowercase the scheme and host.
3. Apply the default port for the scheme when no port is given, so
   `postgres://h/db` and `postgres://h:5432/db` fingerprint identically.
4. Drop query parameters and fragments.
5. `SHA-256` the result, lowercase hex.

A verifier MUST treat an unrecognised fingerprint per policy — the reference
policy treats unknown as production, because failing toward friction is the
correct direction for this product.

### 2.4 `advisory` is unverified, and the device says so

Nothing checks `rows_affected`. An agent can claim a `DELETE` touches 3 rows
when it touches 3 million. The device MUST render advisory content with a
visible marker distinguishing it from `statement` and the environment label, and
implementations MUST NOT branch on advisory values when deciding whether
approval is required.

---

## 3. Canonicalization

`request_digest = SHA-256(jcs(request))`, lowercase hex.

Canonicalization is **RFC 8785 (JSON Canonicalization Scheme)** with one v1
profile restriction:

> **Numbers MUST be integers in the range [-(2^53 - 1), 2^53 - 1].**
> A canonicalizer MUST reject any other number rather than serialize it.

RFC 8785's number rule is ECMAScript `Number::toString`, which is a shortest-
round-trip double formatter — correct, and a reliable source of cross-language
disagreement in exactly the layer where disagreement means a valid approval
fails to verify. Every number this protocol needs is a count, a millisecond, or
a version. Within the integer subset, output is byte-identical to RFC 8785, so
this is a restriction on inputs, not a divergence in format.

The remaining rules are RFC 8785 unchanged:

- UTF-8 output, no insignificant whitespace.
- Object members sorted by key, comparing **UTF-16 code units** — not bytes and
  not code points. These differ above the BMP: `U+FFFD` sorts before `U+10000`
  by code point but after it by UTF-16 code unit, because the latter begins with
  a surrogate. Implementations MUST sort by UTF-16.
- Strings escape only `"`, `\` and C0 controls. `\b \t \n \f \r` use their short
  forms; other controls use `\u00xx` with **lowercase** hex. `/` is not escaped.
  Non-ASCII characters are emitted literally as UTF-8.
- Duplicate object keys MUST be rejected.

---

## 4. Signature

```
tbs = "countersign-v1" || 0x00
   || request_digest_bytes        (32 bytes, the raw digest, not its hex form)
   || u64_be(counter)
   || u64_be(device_unix_ms)

signature = ECDSA-P256-SHA-256(tbs)
```

`ECDSA-P256-SHA-256` is the ordinary primitive: SHA-256 is the message hash
*inside* ECDSA, applied once to `tbs`. It is what WebCrypto calls
`{name: "ECDSA", hash: "SHA-256"}`, what Go's `ecdsa` does over a
`sha256.Sum256`, and what `p256::ecdsa::SigningKey::sign` does in Rust. It is
deliberately not a bespoke construction — the point is that a verifier in any
language reaches for its standard library.

Encoding: **`r || s`, 32 bytes each, 64 bytes total, base64url unpadded.** Not
DER. Fixed width means no length-prefix parsing in firmware.

**Low-S is REQUIRED, on both sides.**

- **Signers MUST normalize `s` into the low half** before emitting a signature.
- **Verifiers MUST reject** a signature with `s > n/2`.

ECDSA is malleable — for any valid `(r, s)`, `(r, n-s)` is also valid — and
these signatures are retained as evidence. Without the rule, a third party can
produce a second, different, equally valid signature over the same approval,
which is a gift to anyone arguing about what an audit log shows.

The signer obligation is stated separately because it is the half that gets
missed, and missing it is unusually nasty. **Most ECDSA libraries do not
normalize for you** — RustCrypto's `p256` has `normalize_s()` and does not call
it on the signing path, and it is not alone. A signer that forgets emits a
high-S signature roughly half the time, so the device appears to work, then
intermittently fails verification for no visible reason. Test a signer against
*many* signatures, not one: a single low-S result proves nothing.

### 4.1 The counter

`counter` is a monotonic counter held in the device's secure element. It never
resets, including across power loss and firmware update.

It is the replay defence, and it is specified this way because it survives a
clock reset. `device_unix_ms` is *also* carried, and a verifier MAY apply a
freshness window to it, but a verifier MUST NOT rely on the timestamp alone: a
device whose clock is wrong is a support ticket, whereas a device whose counter
went backwards is a compromised device.

A verifier that keeps per-device state MUST reject a `counter` less than or
equal to the highest it has already accepted from that `device_id`.

---

## 5. The response bundle

```jsonc
{
  "v": 1,
  "decision": "approved",
  "request_digest": "<lowercase hex>",
  "signatures": [
    {
      "device_id": "<lowercase hex SHA-256 of the SEC1 uncompressed public key>",
      "counter": 41235,
      "device_unix_ms": 1755859200123,
      "signature": "<base64url unpadded, r||s>",
      "dwell_ms": 2140
    }
  ]
}
```

`decision` is one of `approved`, `aborted`, `expired`, `refused`, `no_device`.
Only `approved` carries signatures.

### 5.1 `signatures` is a list in v1, and that is not an accident

v1 implementations produce exactly one signature and verifiers MAY require
exactly one. The field is nonetheless a list from day one because N-of-M —
two devices, two humans, one action — is wanted by the financial and
infrastructure cases, and retrofitting multi-party into a signature format is
painful in a way that reserving a list is not.

All signatures in a bundle MUST cover the same `request_digest`. Each carries
its own counter and timestamp because each device has its own.

A verifier's threshold policy is `{ required: usize, keys: [...] }`. Signatures
from unregistered keys MUST NOT count toward the threshold.

### 5.2 There is no signed denial, and there must never be one

**The dial approves. It is the only input that produces a signature.**

Declining is not something the device expresses. It is what happens when nobody
turns the dial — so a refusal has no signature, and needs none. Every
enforcement point already fails closed: a proxy that sees no valid approval
refuses, so the absence of one *is* the denial. A signed "no" would be a second
thing firmware must express, a second thing every verifier must interpret, and
it would buy nothing that silence does not already provide.

A request that is not approved ends in one of these, none of them signed:

| Decision | What happened |
|---|---|
| `aborted` | A human was present and dismissed it. |
| `expired` | The TTL elapsed with nobody acting. |
| `refused` | Policy declined before the device was ever asked. |
| `no_device` | Nothing was attached to ask. |

The audit trail distinguishes them because "someone read this and declined"
is a different fact from "nobody was there", and an incident review needs both.
Neither carries a signature.

**Consequences for firmware.** The dial has one meaningful direction of
actuation. A turn the other way is at worst a no-op, never a signed statement,
and never an approval of anything. Dismissal, where a device offers it at all,
MUST come from a button and never from the dial — which is the same rule as §8's
"a button can never carry an approval", read from the other side. Between them,
the two affordances cannot be confused for each other in either direction.

**Consequences for clients.** Do not build a two-button approve/deny UI that
routes one button to the device. Declining is ordinary software: cancel the
operation, tell the agent no, close the prompt. Only the consequential half
needs hardware, and only the consequential half gets it.

### 5.3 `dwell_ms` is telemetry, not evidence

How long the human held the dial before the detent committed. It is fine to
record and fine to show in an audit view.

**Nothing may treat it as evidence of humanity, and no verifier may branch on
it.** A servo produces any dwell time you ask it for. If a verifier ever gates
on this field, someone has misunderstood what §1 says the primitive is.

---

## 6. What the device displays

The firmware renders **from the bytes it will sign**. There is no `display_text`
field, and §9 forbids adding one: a display field distinct from the signed
payload is blind signing, which is the failure mode hardware wallets spent a
decade learning to avoid.

The screen is modelled as an ordered list of `{role, text}`, where `role` is one
of:

| Role | Source | Notes |
|---|---|---|
| `label` | **daemon**, from local config | The environment. Colour-coded by tier. |
| `primary` | pack, or `statement` verbatim | Truncated with an ellipsis if long. |
| `advisory` | pack or request | MUST carry a visible unverified marker. |
| `digest` | **daemon**, from `request_digest` | First 12 hex characters. |

```
prod-us-east-1
DROP TABLE users;
~4,200,000 rows · 3 deps  (adv)
a91f 4c2e 7b03
```

Roles, not typed fields, because `{statement, rows_affected}` is SQL leaking into
firmware. Firmware renders roles; packs choose content. That is the difference
between a device that does databases and a device that does anything.

**A pack MUST NOT emit `label` or `digest` lines**, and a host MUST reject a pack
response containing them. Those two roles are precisely the ones the requester
is not allowed to influence — the label because §2.1 keeps environment
classification local, the digest because it is the human's cross-check.

### 6.1 The client must show the same digest

A client requesting approval MUST display the same first 12 hex characters of
`request_digest` that the device will show. That match is how a human detects a
disagreement between what their screen said and what the device was asked to
sign. This is mandatory in the integration guide, not a nicety — without it the
content binding in §1 is invisible to the person relying on it.

Long statements truncate on screen; the signature covers the full text.

---

## 6.2 Keeping the dial rare

A device that a person turns twenty times a day is a device they turn without
reading. That is not a usability complaint — it is the most practical attack on
this entire design, and it does not require breaking any cryptography.

The attack: wire something benign to the dial — skip a track, advance a slide,
acknowledge a notification. Let the habit form over a week. Then time a real
`DROP TABLE` request to arrive as the operator reaches for it. They turn,
because turning has meant "next song" two hundred times. Content binding did its
job perfectly and it did not matter, because nobody read the screen.

Three rules follow, and implementations MUST hold all three.

### 6.2.1 The dial is not an input device

The device exposes two HID interfaces (§8): a standard keyboard for its buttons,
and a vendor page for Countersign. **Macros, media keys and shortcuts belong to
the buttons.** They work with no software installed, which is what makes the
device saleable as a macro pad, and they cannot produce a signature.

The dial is an authorization instrument. It has exactly one meaning.

### 6.2.2 An action namespace must be enabled before it can ask

A daemon MUST NOT present an action whose namespace the operator has not
explicitly enabled. An unconfigured namespace is **refused without asking a
human** — not queued, not shown, not turned into a prompt.

This is the rule that survives an ecosystem of thousands of packs. Anyone may
write `countersign-spotify`; nobody can make it light up a dial, because
enabling a namespace is a local configuration decision and the default set is
empty. A plugin cannot enrol itself into the operator's attention.

Note the asymmetry with §2.1's unknown *target*, which is treated as
**production** — strictest. An unknown *action* is treated as **not our
business** — refused. Both fail closed; they fail closed in different
directions because the risks are different. An unclassified database is
something dangerous nobody has labelled. An unclassified action is something
that was never this daemon's to ask about, and asking would spend the operator's
attention on it.

### 6.2.3 A payload must be readable before it is approvable

Firmware MUST NOT accept an actuation until the payload has been displayed for a
minimum interval, and any new payload MUST restart that interval.

An actuation that lands 80 ms after a screen appears is a reflex, not a
decision. Restarting on every new payload is what stops a request timed to
arrive mid-gesture from borrowing a movement that was meant for something else.

The interval SHOULD scale with severity — friction is worth spending where it
buys something. The reference daemon uses 400 ms at the low end and 2 s for
anything destructive.

**This is not an anti-automation measure and MUST NOT be presented as one.** A
servo waits as long as you like. It defends a cooperating human against their
own reflexes, which is the actual threat model (§1), and it is worthless against
an adversary with physical possession of the device — as everything here is.

### 6.2.4 The corollary: never ask when you do not need to

Every unnecessary prompt trains the reflex that 6.2.3 then has to defend
against. A daemon that asks about routine reads is manufacturing the
vulnerability it is trying to mitigate.

Auto-approve generously at low severity. Reserve the dial for things that
genuinely warrant a person. **Approval fatigue is a security property of this
system, not a matter of taste.**

---

## 7. Verification

A verifier holds a registry of enrolled public keys and, given a bundle plus its
own copy of the request:

1. Canonicalize its own request copy and compute `request_digest`.
2. Compare with `bundle.request_digest`. A mismatch is a hard failure — this is
   the step that makes the countersignature about *this* statement.
3. For each signature: look up `device_id`, recompute `tbs`, check low-S, verify.
4. Reject test-key signatures unless explicitly configured otherwise (§8).
5. Check counters against per-device high-water marks.
6. Count valid signatures from distinct enrolled devices against the threshold.

Verification MUST be implementable without the daemon, without USB, and without
a network. That is what lets a wire proxy on another host, a CI runner, or a
Vault plugin verify against a registered public key — the posture that makes the
security claim real rather than advisory.

---

## 8. Test keys are cryptographically distinguishable

Software must be testable without building a bypass that could survive into
production.

The mock device signs with a **published** test keypair whose private half is in
this repository (`vectors/test-key.json`). Verifiers MUST reject signatures from
a known test key unless explicitly configured to accept them.

The property this buys: there is no code path where a software approval produces
a production-valid signature. The bypass is not "disabled by a flag" — it is
cryptographically incapable, and a mock accidentally left enabled fails loudly at
verification rather than silently passing.

---

## 9. Non-goals — refused by design

These will be asked for. They are written down here so they are not
re-litigated later by whoever has the most revenue attached to the request.

- **Batch approval.** One signature, one statement. No "approve these 40".
- **Remember for N minutes.** A time window is a software confirmation with
  extra steps.
- **Auto-approve on a pattern match.** If a regex can approve it, the agent can
  construct something that matches the regex.
- **A `display_text` field separate from the signed payload.** Blind signing.
- **A software approval path that produces production-valid signatures.** §8.
- **Approval delegated to another agent.** The human is the point.
- **Anti-automation heuristics** — turn-velocity fingerprinting, "human-like
  motion" detection, or any use of `dwell_ms` as a liveness signal. It cannot
  work: a dial is easier to actuate mechanically than a capacitive pad, and
  Cloudflare's Cryptographic Attestation of Personhood already demonstrated
  where this ends. Every hour spent here is an hour not spent on the proxy,
  which is what actually delivers the security property.

The moment any of these ships, the product is a confirmation dialog with a USB
cable.
