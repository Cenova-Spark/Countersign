# CountersignKit

The crypto and the gesture rules, shared by the Mac app and the iPhone app,
with no UI in it. Everything here is a port of something that already exists
in this repository, and it is checked against `spec/vectors/` rather than
against the Rust — two implementations agreeing with each other and both being
wrong is the failure that check exists to catch.

| What | Ported from | Spec |
|---|---|---|
| `JCS` — canonicalization with its own strict parser | `web/src/lib/jcs.js` | wire §3 |
| `Countersign.requestDigest`, `digestShort`, `deviceID` | `sign.js` | wire §3, §4.2, §6.1 |
| `Countersign.signingPayload`, `normalizeLowS`, `isLowS` | `sign.js`, `p256.js` | wire §4 |
| `HoldMachine` — arm delay, rest transition, hold, lapse | `hold.js` | wire §6.2.3, §6.3.4 |
| `Presentation`, `PresentParams`, `PresentOutcome`, `AttachRequest` | `signetd::device`, `signetd::app` | — |
| `EnclaveDevice`, `KeychainCounterStore`, `KeyContinuity` | new | device-classes §3 |

```bash
swift test
```

## The two things CryptoKit does not do for you

**It does not normalize `s`.** Neither does WebCrypto, neither does
RustCrypto. A signer that forgets emits a high-S signature about half the time,
works in the demo, and fails verification intermittently in the field.
`Countersign.normalizeLowS` is applied by every `Signer` in this package, and
the test signs two hundred messages rather than one, because one low-S result
proves nothing.

**It does not keep a counter.** The Secure Enclave has no monotonic counter an
app can read, so `KeychainCounterStore` keeps one in a `ThisDeviceOnly`
keychain item, and `Countersigner` advances and persists it *before* asking the
key to sign. A crash between the two loses a signature and never repeats a
counter.

## Key and counter live and die together

Device-class spec §3.4. `EnclaveDevice.init` follows one table, and the table
is tested on its own as `KeyContinuity`:

| Key exists | Counter exists | Then |
|---|---|---|
| yes | yes | use them |
| no | — | generate both |
| yes | **no** | delete the key, throw `.counterContinuityLost`, enroll again |

A counter that could restart under the same `device_id` defeats the replay
defence. A counter that restarts under a *new* `device_id` is simply a new
device, and every verifier already handles that.

## What the enclave key looks like

`SecureEnclave.P256.Signing.PrivateKey` with access control
`[.privateKeyUsage, .biometryCurrentSet]`. Every signature runs the biometric
prompt inside the enclave's own call; a cancelled prompt throws and nothing is
signed. There is no passcode fallback, deliberately: on a Mac the requester may
run as the same user, and a passcode can be typed by software with the right
permission. A fingerprint cannot. Adding a fingerprint or a face invalidates the
key, which forces re-enrollment — a key that survived a change to the thing
that unlocks it has quietly changed hands.

Its `publicKey.x963Representation` is the SEC1 uncompressed encoding wire spec
§4.2 hashes — `0x04 || X || Y` — and `signature.rawRepresentation` is `r || s`.
Both are pinned against the committed test key in `Tests/…/Vectors.swift`.

## `SoftwareSigner` is for tests

A P-256 key in ordinary memory is exactly what the `enclave` class forbids for
a real device (device-class spec §2). It exists so the gesture rules and the
wire format can be exercised without a Secure Enclave, and so a deterministic
key can sign the fixture the Rust verifier checks:

```bash
swift run countersign-swift-vector > ../../crates/countersign-verify/tests/fixtures/swift-approval.json
cargo test -p countersign-verify --test swift_fixture
```

Nothing that reaches a user may construct one.

## The hold, on a clock you control

`HoldMachine` takes `now` as a number. An app drives `tick(now:)` from a display
link and calls `armFrom(now:)` when the payload has **finished rendering**, not
when it arrived. The tests are the ones from `web/test/hold.test.js`, including
the one that is easy to miss: a backgrounded app discards an accumulated hold
instead of banking it, because `now − holdStartedAt` would otherwise come back
from a thirty-second sleep already satisfied and approve on wake.

The OS presence check is the **commit** of the hold, not a replacement for it.
The machine reaches `.committed`; then the app asks the enclave to sign; then
Face ID or Touch ID runs. In that order.
