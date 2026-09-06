# Countersign device classes v1 — what kind of thing signed

Status: **draft**. Normative for `countersign-verify`, for the roster `signetd`
keeps, and for any app that signs with a key it did not get from a published
vector.
Licence: Apache-2.0.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

---

## 1. Why a signature needs a class

Wire spec §1 states what a countersignature proves:

> Proof that a specific enrolled key was physically actuated while a specific
> payload was displayed on a device the requesting software does not control.

How much of that sentence is true depends on what the device is. A Signet has a
secure element, a screen only its firmware draws on, a dial with one meaning,
and a counter that survives power loss. A phone has a secure enclave and a
general-purpose operating system. A published test key has nothing.

Until now the protocol has drawn one line: a key is either real or it is a
published test key, and a verifier refuses the second by default. That line
was enough while the only real device was a Signet. It stops being enough the
moment an enclave-backed key on a phone or a laptop is allowed to produce an
approval that counts — because that approval is worth something, and it is
worth *less* than a Signet's, and a verifier that cannot tell the two apart
cannot enforce the difference.

So every enrolled key carries a **class**, the class carries a written-down
claim, and a verifier is configured with the classes it will accept. The class
is a property of the *enrollment*, never of the signature: a signer does not
get to say what kind of thing it is, for the same reason it does not get to say
what its `device_id` is (enrollment spec §3).

---

## 2. The classes

| Class | Key | Display | Actuation | Counter |
|---|---|---|---|---|
| `signet` | Secure element. Non-extractable. | A screen only the firmware draws on, rendered from the signed bytes. | The dial, with arm delay, rest transition and hold in firmware. | In the secure element. Never resets. |
| `enclave` | A platform secure enclave. Non-extractable. Every use gated by an OS-mediated user-presence check. | The app's screen on a general-purpose OS, rendered from the signed bytes. | An on-screen hold with the same three rules, then the OS presence check as the commit. | In OS-protected storage, bound to the key (§3.4). |
| `test` | A published private key. | Anything. | Anything. | Anything. |

The claim each class makes:

**`signet`** — the full wire spec §1 claim. The requesting software has no
path to the screen, the dial or the key.

**`enclave`** — *a non-extractable key was used, after an operating-system
presence check, on a device whose screen the requester cannot draw on without
compromising the OS.* Smaller than the Signet claim in two ways that are
written down rather than glossed: the screen belongs to a general-purpose OS,
so a compromised OS could overlay it; and the counter is software, so its
non-repetition rests on §3.4 rather than on silicon.

**`test`** — nothing. The private key is in a public repository. It exists so
software can be tested without a bypass that could survive into production
(wire spec §8).

There is no fourth class, and in particular there is no class for a key held in
ordinary software. A key that is not in a secure element or a secure enclave is
one an agent on the same machine can read, and a signature from a key the
requester can read proves nothing about a human. Such a key MUST NOT be
enrolled as anything but `test`, and an implementation that cannot obtain an
enclave-backed key MUST NOT approve at all — it may still display, and it may
still acknowledge.

---

## 3. What an `enclave` implementation owes

Everything in wire spec §6 (render from the signed bytes, show the digest),
§6.2.3 (arm delay, rest transition), §6.3 (acknowledge on a different control,
hold scaled by severity) and §4 (low-S, the counter inside the signature)
applies unchanged. This section adds what a general-purpose OS makes necessary.

### 3.1 The key

- MUST be generated inside the platform's secure enclave and MUST be
  non-extractable. The implementation MUST confirm the platform reports the key
  as enclave-resident before enrolling it, and MUST refuse to enroll otherwise.
- MUST require an OS-mediated user-presence check on **every** signature.
  "Every" is load-bearing: an OS feature that leaves the key usable for a
  window after one check is a software confirmation with extra steps, which
  wire spec §9 refuses.
- SHOULD be bound to the currently enrolled biometrics, so that adding a
  fingerprint or a face invalidates the key and forces re-enrollment. A key
  that survives a change to the thing that unlocks it has quietly changed
  hands.
- Where the requester may run on the **same host** as the app — a laptop
  running both the agent and the desktop app — a passcode fallback SHOULD be
  disabled. A passcode can be typed by software with the right OS permission;
  a fingerprint cannot.

Apple's Secure Enclave through CryptoKit, Android StrongBox with
strong-biometric authentication, and a TPM behind Windows Hello all satisfy
this. Note that Apple's `x963Representation` of the public key is exactly the
SEC1 uncompressed encoding wire spec §4.2 hashes for the `device_id`, and its
ECDSA `rawRepresentation` is `r || s` — the two encodings the spec pins are the
ones the platform already produces. What the platform does **not** do is
normalize `s`; the signer obligation in wire spec §4 is on the app.

### 3.2 The display and the hold

- The payload MUST be rendered by the app, from `request_json`, on the same
  screen the hold happens on. The implementation MUST recompute
  `SHA-256(jcs(request))` and MUST refuse to render a payload whose digest
  disagrees with the one it was handed — exactly as `web/` does today, and for
  the same reason: something between the daemon and this screen rewrote it.
- The OS presence check is the **commit** of the hold, not a replacement for
  it. The order is: acknowledge → arm delay from paint → rest → hold for the
  severity's duration → the OS prompt → sign. A presence check that fails or is
  cancelled discards the hold; the payload re-arms.
- A notification is not a screen. **An implementation MUST NOT offer an
  approval from a notification, a widget, a lock screen, a watch face, or any
  surface that does not display the full render and run the hold.** A
  notification MAY say that something is waiting and open the app. This is not
  a preference about interface design: an approve action on a banner is a
  one-tap approval of a payload the person has not seen, which is blind
  signing, and it is also the reflex wire spec §6.2 spends a section defending
  against.

### 3.3 The clock

`device_unix_ms` comes from a phone or a laptop clock, which is usually right.
Verifiers MAY apply a freshness window (`max_clock_skew_ms`) more readily to
`enclave` signatures than to `signet` ones, but wire spec §4.1 still holds: the
counter is the replay defence, the timestamp is not.

### 3.4 The counter

The secure enclaves this class targets do not expose a monotonic counter to
applications, so `counter` is kept by the app in storage the OS protects. That
is weaker than silicon, and the following rules are what make it acceptable.

- The counter MUST be stored in a protection class that is **never restored to
  another device** — on Apple platforms, a `ThisDeviceOnly` keychain class. A
  counter cloned by a backup restore is a counter that repeats.
- The counter and the key MUST be bound so that neither outlives the other. If
  the implementation cannot establish the counter's continuity — the store is
  missing, was reset, or is behind a value already used — it MUST discard the
  key, generate a fresh one, and require re-enrollment. A counter that could
  restart under the same `device_id` defeats wire spec §4.1; a counter that
  restarts under a **new** `device_id` is simply a new device, and every
  verifier already handles that (enrollment spec §6.3).
- The counter MUST be advanced and persisted **before** the signature is
  released. A crash between signing and persisting must lose the signature,
  never repeat the counter.

### 3.5 Delivery

When a payload reaches the app through a relay, the relay is untrusted (see
`web/`) and so is any push service in front of it. A push notification MUST
carry at most a request identifier, the environment label and the short digest
— the two things the daemon assigns and the requester cannot influence — and
MUST NOT carry the statement, the render lines, or `request_json`. The app
fetches those over an authenticated channel after the tap.

---

## 4. Where the class is recorded

In the enrollment record (enrollment spec §3), as a new field:

```jsonc
{
  "device_id": "<lowercase hex SHA-256 of the SEC1 uncompressed public key>",
  "public_key_hex": "04…",
  "class": "enclave",                        // "signet" | "enclave" | "test"
  "operator": { "subject": "alice@example.com", "display": "Alice" },
  "enrolled_at_unix_ms": 1755000000000,
  "status": { "state": "active" },
  "is_test_key": false,
  "proof": { /* an ApprovalEnvelope, enrollment spec §2 */ }
}
```

Rules:

- `class` and `is_test_key` MUST agree: `is_test_key: true` ⇔
  `class: "test"`. A verifier MUST reject a record where they disagree, because
  one of them is lying and it cannot tell which.
- A record with no `class` — every roster issued before this document — is
  read as `test` when `is_test_key` is true and `signet` otherwise. Nothing
  already issued changes meaning.
- The class MUST NOT appear in the request, in the signature, or in the
  bundle. A verifier learns it from the record it already trusts and from
  nowhere else. A signer claiming `"class": "signet"` beside its signature
  would be exactly the kind of field wire spec §2.1 keeps out of the request.
- An `enclave` record's `proof` MUST be present. It is the enrollment ceremony
  (enrollment spec §2) rendered on the app's own screen and signed by the
  enclave key: *Enroll this device as an approver for alice@example.com*.
  That is what shows the key can actually sign under a presence check, and it
  is the same single construction every other class uses — no second
  ceremony, no second thing to drift into blind signing.
- Platform attestation — Apple App Attest, Android Key Attestation — is a
  *different* claim ("this key is in a genuine enclave on a genuine device
  running this app") from "this key belongs to Alice", and MUST NOT be
  conflated with the record. It is **reserved**, alongside manufacturer
  attestation in enrollment spec §7. A future field MAY carry it and a
  verifier MAY require it; v1 does not specify it.

---

## 5. What a verifier does with it

`VerifyPolicy` gains one field:

```
accept_classes: { signet, enclave }        // the default
```

- A signature from a device whose class is not in `accept_classes` MUST be
  rejected, before the cryptography, with an error that names the class.
- `test` is never in the default set. `accept_test_keys: true` is equivalent
  to adding it, and remains the only way to.
- The default includes `enclave`. This is deliberate, and it is the product
  decision this document exists to make: an approval from a biometric-gated
  enclave key is a real approval with a smaller claim, not a demo. An operator
  who wants hardware only writes one line — `accept_classes = ["signet"]` —
  and every verifier they run becomes hardware-only the day hardware exists,
  with nothing else to change.
- A threshold policy MAY, in a future version, require a minimum per class
  ("two signatures, at least one `signet`"). v1 does not;
  `required_signatures` counts across accepted classes.
- The verified result MUST report each signer's class, so an audit view can
  show *what kind of thing* approved something and not only who.

The verification steps in wire spec §7 gain one entry, between 3 and 4:
*check the device's class against `accept_classes`.*

---

## 6. Pairing is not enrolling

The relay in `web/` **pairs**: a code read off a signed-in screen binds a
*daemon* to an *account*, so the relay knows whose phone to show a payload to.
Pairing establishes nothing about keys.

**Enrolling** binds a *key* to a *subject* with a countersigned proof
(enrollment spec §2). An `enclave` device is enrolled, not merely paired. The
daemon that will act on its signatures MUST hold its enrollment record — in the
direct trust model, a local roster of the operator's own devices — and MUST
verify every returned signature against that record's public key, its counter
high-water mark and its class, exactly as `signetd`'s relay device already
verifies against the published remote test key today. The relay holds no key,
learns no private key, and its word for an approval is worth nothing; that
does not change.

---

## 7. What this does not claim

- That a human was present. Wire spec §1 never claimed it for a Signet either.
- That the OS was uncompromised. A rooted phone can overlay a screen. An
  `enclave` approval from a compromised OS is an approval of whatever the
  compromise chose to show — which is why the class exists, why its claim is
  smaller, and why `accept_classes` lets a verifier decline it.
- That the requester was not on the same machine. A desktop app approving for
  an agent on the same laptop is permitted, is weaker than a phone, and is the
  reason §3.1 says what it says about passcodes.

---

## 8. Non-goals

- **A class asserted by the signer.** The class lives in the record. Always.
- **A software key enrolled as `enclave`.** An implementation that cannot get
  an enclave-backed key does not approve.
- **Approve from a notification.** §3.2. A banner with an Approve button is a
  confirmation dialog with a push token.
- **A grace period after a presence check.** Every signature, every time.
- **Batch approval, remember-for-N-minutes, pattern auto-approve, a display
  field separate from the signed payload.** Unchanged from wire spec §9. An
  app makes each of these easier to build and none of them acceptable.
