# Countersign enrollment v1 — the trust root

Status: **draft**. Normative for `countersign-verify`.
Licence: Apache-2.0.

Everything in Countersign reduces to "a signature from an enrolled key". If
enrollment is weak, nothing above it is strong. This document is deliberately
the most conservative in the set.

---

## 1. Three questions

| Question | Answer |
|---|---|
| What binds a key to a human? | An **enrollment record** (§3). |
| How does a verifier on another host learn it? | A signed **roster** (§4). |
| Who may register one? | Whoever holds the authority key — **and** the physical cooperation of the device (§2). |

Identity is **not** inside the device's signature. The device proves it was
actuated; the record says whose it is. That is the `authorized_keys` model, and
it is the right one: the alternative means re-flashing a device to change
someone's email address, and re-issuing hardware to correct a typo.

---

## 2. Enrollment is itself an approval

A public key is not a secret. Anyone who has seen one can claim it, so
enrollment MUST require proof that the enroller actually holds the device.

That proof is an ordinary countersignature:

- `action` MUST be `countersign.enroll`
- `statement` MUST be exactly
  `Enroll this device as an approver for {subject}`
- `target.kind` MUST be `enrollment`, and `target.uri_fingerprint` the
  lowercase-hex SHA-256 of `subject`

So the device renders *"Enroll this device as an approver for
alice@example.com"* on its own screen, and a human turns the dial.

Two properties fall out, and both are why this reuses the approval path rather
than defining a ceremony of its own:

1. **There is one signing construction in this protocol.** A separate enrollment
   ceremony would be a second thing the device signs, with its own display rules
   and its own chance to drift into blind signing.
2. **The statement is fixed text naming the subject**, so a verifier checks it
   byte-for-byte. If an enroller could write that string freely, they could show
   the human "Enroll for testing" while binding the device to an administrator.

A verifier checking a proof MUST confirm all of: the decision was `approved`;
the digest covers the request it travels with; the action is
`countersign.enroll`; the statement matches the record's own subject exactly;
and the signature verifies **against the record's own public key**.

---

## 3. The enrollment record

```jsonc
{
  "device_id": "<lowercase hex SHA-256 of the SEC1 uncompressed public key>",
  "public_key_hex": "04…",              // SEC1 uncompressed, 65 bytes
  "operator": { "subject": "alice@example.com", "display": "Alice" },
  "enrolled_at_unix_ms": 1755000000000,
  "status": { "state": "active" },
  "is_test_key": false,
  "proof": { /* an ApprovalEnvelope, §2 */ }
}
```

`device_id` MUST be **derived and re-derived**, never trusted as asserted. A
roster that listed one key under another device's id would make every lookup
keyed on that id resolve to the wrong key. Verifiers MUST recompute it.

The derivation is fixed by `countersign-v1.md` §4.2 — SHA-256 over the 65-byte
SEC1 uncompressed encoding, including the `0x04` prefix that secure elements
omit from the key material they return.

`operator.subject` SHOULD be a stable identifier — an email, an employee id, an
OIDC subject — and SHOULD NOT be a display name, which people change.

---

## 4. Rosters

```jsonc
{
  "roster_json": "{…}",     // the roster as issued, verbatim
  "signature": "<base64url unpadded, r||s>"
}
```

The roster itself:

```jsonc
{
  "v": 1,
  "issued_at_unix_ms": 1755000000000,
  "serial": 7,
  "authority_id": "<lowercase hex SHA-256 of the authority public key>",
  "records": [ /* §3 */ ]
}
```

A verifier is configured with **one authority public key**, out of band, once.
It can then load a roster from anywhere — a file, a URL, a git repository, a
config-management blob — because the roster authenticates itself and the
distribution channel does not have to be trusted.

`roster_json` is retained verbatim, for the same reason the approval envelope
retains its request text: re-serializing through a struct drops fields a future
version added, and the signature covers what was sent.

**Signing payload:** `"countersign-roster-v1" || 0x00 || roster_digest`, where
`roster_digest` is the raw 32 bytes of `SHA-256(jcs(roster))`. The domain
separator differs from the approval one so a roster signature can never be
replayed as an approval, or the reverse.

**Low-S applies here too**, on both sides, exactly as in wire spec §4 — as it
does to enrollment proofs and audit checkpoints. Every signature this protocol
produces is subject to the same rule, and a verifier that enforces it on
approvals but not on rosters has left the malleability open on the artifact that
decides who may approve.

### 4.1 Serial numbers, and why they are not optional

`serial` MUST increase. A verifier MUST reject a roster whose serial is below
the highest it has already accepted from that authority.

Without this check, revocation does not work. Someone who lost a device only
needs the verifier to keep reading the roster from before it was removed —
serving yesterday's signed file is not tampering, and every signature still
verifies. The rollback check is the entire difference between a revocation list
and a suggestion.

A verifier that restarts needs a **durable** high-water mark, or it accepts one
rollback per restart.

### 4.2 The authority key

Whoever holds it decides who may approve production changes, so it deserves the
protection that implies: hardware-backed, offline where practical, and rotated
with a deliberate ceremony rather than a script.

Nothing prevents the authority key from being a Signet, and that is the natural
end state — adding a device to a fleet would then require a physical turn by a
named human, recorded like everything else.

---

## 5. Revocation

```jsonc
"status": {
  "state": "revoked",
  "at_unix_ms": 1760000000000,
  "at_counter": 4120,
  "reason": "laptop bag left on a train"
}
```

Verifiers MUST distinguish two questions, because conflating them costs one of
two things: either revoking a lost device fails to stop it, or it silently
invalidates years of legitimate approvals.

**"May this device authorize something now?"** — a revoked device MUST be
refused, full stop.

**"Was this device trusted when it signed?"** — used when auditing. A device
revoked *after* the approval was given still counts. An audit trail that erased
a departed employee's approvals would be worse than useless.

`at_counter` SHOULD be recorded when known. A counter comparison beats a
timestamp comparison because it survives a clock that was wrong, which is the
same reason the protocol carries a counter at all.

---

## 6. One device, one human

**A Signet belongs to one person.** This is a design decision, not a limitation
to be worked around later.

The signature proves *a device was actuated*. The roster maps that device to a
person. If two people share a device, the signature proves only "someone with
physical access to that desk", and the question the whole product exists to
answer — *who approved this, and can you prove it* — has no answer.

The alternatives were considered and rejected:

- **Per-human authentication on the device** (a PIN entered on the dial) is slow,
  shoulder-surfable at exactly the shared workstation where it would be needed,
  and adds a credential to a product whose pitch is that it replaces credentials.
- **An operator field in the request** would be a requester-supplied claim, and
  §2.1 of the wire spec exists precisely to keep those out.

Devices are cheap. Issue one per person, the way security keys are issued.

### 6.1 Shared workstations

Not supported, and the reason is worth stating plainly rather than leaving to
discovery: on a shared machine, the device is still personal and travels with
the person, not the desk. `signetd` runs per user session; two people at one
machine use two devices and two sessions.

### 6.2 One person, several devices

Normal, expected, and fully supported — a work device and a home device, a desk
device and a travel device. Each gets its own record; the records share an
`operator.subject`. A verifier resolves any of them to the same person.

Nothing is keyed on the subject, so there is no limit and no conflict: records
are keyed by `device_id`, which is derived from the public key, so two devices
belonging to one person are simply two independent records.

### 6.3 Losing a device and replacing it

Revocation is **per device, never per person**, which is what makes replacement
uneventful:

1. The authority sets the lost device's record to `revoked`, bumps `serial`,
   re-signs, republishes.
2. Every other device that person holds is untouched and keeps working. They are
   not locked out while a replacement is in the post.
3. The replacement runs the ordinary §2 ceremony under the **same subject**. A
   new key means a new `device_id`, so it is a new record with no relationship
   to the revoked one.
4. The authority adds it, bumps `serial`, re-signs, republishes.
5. Approvals the lost device gave before revocation still verify under as-of
   acceptance (§5), so history is intact.

Two consequences implementations MUST get right:

- **Counters are per device.** A replacement starts near zero, far below
  whatever the lost device had reached. A verifier tracking a high-water mark
  per `device_id` handles this; one tracking it per *person* would reject every
  approval from the replacement as a replay.
- **An enrollment proof is bound to a key, not to the words.** Both of a
  person's devices sign the identical statement text, so a proof MUST be
  verified against its own record's public key. Otherwise one device's proof
  would enroll another.

### 6.4 Offboarding revokes a person, not a device

When someone leaves, **every** device they hold must be revoked. Revoking the
one that happens to be remembered leaves the others live, and the forgotten one
is the one that still works.

Authorities MUST therefore be able to revoke by subject, and an access review
MUST be able to enumerate every device for a subject. Sweeping SHOULD leave
already-revoked records alone, so that an earlier, more precise revocation —
one that recorded `at_counter` — is not coarsened into a timestamp-only one.

This has one consequence that MUST be implemented: **a threshold of N
signatures means N devices, not N people.** Alice with two Signets satisfies
"two signatures" alone, which is exactly the control that a dual-control rule
existed to prevent.

Any genuine dual-control policy MUST therefore count **distinct
`operator.subject` values**, not distinct devices. A verifier enforcing this
MUST refuse a signature from a device whose operator it does not know: without
an owner there is no way to tell two people from one, and guessing in the
permissive direction defeats the control.

---

## 7. Trust models

**Direct.** One operator, one machine. `countersign enroll` runs the ceremony in
§2 and writes the record locally. The trust root is the local filesystem. Right
for an individual; no roster needed.

**Roster.** An org. §4. The trust root is the authority key.

**Manufacturer attestation.** *Reserved, not specified.* A device shipping with
a factory certificate could prove its key lives in a genuine secure element and
was never exported. That is a different claim from "this device belongs to
Alice" and MUST NOT be conflated with it. It is out of scope until hardware
exists.

---

## 8. Non-goals

- **Self-enrollment without an authority.** In the roster model, a device MUST
  NOT be able to add itself. Proof of possession shows a device holds its key;
  it says nothing about whether that device should be trusted.
- **Enrollment by an agent.** The human is the point. An agent that could enroll
  a device could enroll its own.
- **Silent re-enrollment.** Changing the operator on an existing record MUST
  require a fresh proof, because the statement names the subject and the old
  signature covers the old name.
