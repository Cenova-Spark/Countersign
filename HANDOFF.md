# Handoff: where the product build is, and what M5 needs

Written 2026-09-05 for whoever picks this up next — a fresh session included.
Read [`PRODUCT.md`](PRODUCT.md) for the plan and
[`spec/device-classes-v1.md`](spec/device-classes-v1.md) for the decision it
rests on. This file is the state, not the plan.

## Status

| Milestone | State | Proof |
|---|---|---|
| M1 device classes in the verifiers | done | `cargo test -p countersign-verify`, `npm test` in `sdk/typescript`; vector `spec/vectors/device-classes.json` |
| M2 daemon: packs, wasm host, enroll, `--device=app`, several devices | done | `cargo test -p signetd`; demo in `crates/signetd/README.md` |
| M3 `CountersignKit` (Swift) | done | `swift test` in `swift/CountersignKit`; Rust verifies its fixture in `tests/swift_fixture.rs` |
| M4 the Mac app | done, Touch ID not exercised by a human yet | `swift test` in `swift/Signet`; `swift/Signet/build-app.sh` |
| **M5 iPhone app + relay** | **in progress — steps 1–2 of 5 done** | `cargo test -p signetd` (`--lib relay`, `--test relay_phone`); `npm test` in `web` (`test/phones.test.js`) |
| M6 plugins screen, marketplace index, `countersign-tf` | **started 2026-09-05:** `signetd pack info`, `signetd pack new`, `templates/pack` | `cargo test -p signetd` (`packs::tests::info_*`, `scaffold`); `cargo test -p countersign-pack-template` |
| M7 payment, App Store | not started | — |

**Nothing above is committed.** It sits in the working tree alongside Elijah's
own uncommitted relay work (`crates/signetd/src/relay.rs`, `web/`, and edits
to `README.md`, `NEXT_STEPS.md`, the two specs). Commit that first, then the
milestones, so the history reads in order. Suggested split:

```
1. relay work (Elijah's):  crates/signetd/src/relay.rs web/ crates/signetd/tests/fixtures/remote-approval.json README.md NEXT_STEPS.md spec/countersign-v1.md spec/enrollment-v1.md .gitignore Cargo.lock crates/countersign-hook crates/signetd/src/{daemon,device,lib,main}.rs crates/signetd/Cargo.toml
2. M1:  crates/countersign-verify sdk/typescript spec/device-classes-v1.md spec/vectors/device-classes.json spec/README.md PRODUCT.md
3. M2:  crates/countersign-pack crates/countersign-db crates/signetd crates/countersign-proxy/tests spec/pack-protocol-v1.md
4. M3:  swift/CountersignKit crates/countersign-verify/tests/{swift_fixture.rs,fixtures/}
5. M4:  swift/Signet HANDOFF.md CLAUDE.md
```

Step 1 and steps 3–4 both touch `crates/signetd/src/*.rs`; `git add -p` if the
split matters, or squash 1 and 3.

## What exists, by the thing M5 will touch

**The relay** — `web/`. Vercel functions + Vue. `api/device/{pair,present,await}.js`
are what the daemon talks to; `api/{claim,approve,decline,signets,pair-code}.js`
are what the signed-in human uses; `api/_lib/store.js` is the Upstash key
layout. The phone side today is the **browser**, signing with the *remote
published test key* (`web/src/lib/sign.js`, derivation
`"countersign-v1 published test key · remote"`). The daemon side is
`crates/signetd/src/relay.rs`: `RelayDevice::present` posts, long-polls
`await`, and `accept` verifies against that derived key with a persisted
counter. Payloads travel in the clear (`NEXT_STEPS` §2.2).

**The daemon's device model** — `crates/signetd/src/device.rs`. `Device` has
`info()`, `devices()`, `present(&Presentation, &Cancel)`. `Devices` fans out
to several and withdraws the losers; `--device=app,relay` already works.
`DeviceInfo` carries `class` and `public_key_hex`, and `DeviceOutcome::Approved`
carries `device_id`, so the daemon knows *which* device signed.

**The app as a device** — `crates/signetd/src/app.rs`. This is the template
for what the relay device must become: `AppDevices::attach` checks the id
derives from the key and the class is `enclave`; `accept` verifies signature,
counter, low-S, and — for anything but the enrollment ceremony — that the
roster holds an active record for the key. `Daemon::enroll` in `daemon.rs`
runs the ceremony and writes `roster.json` (`roster.rs`), taking the class
from the device that signed.

**The Swift side** — `swift/CountersignKit` (iOS 16+ already in its
platforms) and `swift/Signet`. `EnclaveDevice`, `HoldMachine`, `Presentation`,
`PresentParams`, `PresentOutcome`, `AttachRequest` are in the kit.
`ApprovalView`, `DeviceScreen`, `HoldDial`, `Theme` are in the **Mac app
target** and are what the iPhone screen wants; lift them into a shared
library target (say `swift/SignetUI`) with the two AppKit touches
(`ApprovalWindowController`, `NSApp`) left behind.

**Wire shapes** — a `device.present` push is
`{presentation, arm_delay_ms, hold_ms, enrollment}`; the answer is
`{outcome: approved|aborted|expired, signature?: DeviceSignature}`. The relay's
`present` body is the `Presentation` fields plus nothing; `await` returns
`{status, outcome: {decision, bundle}}`. See `relay.rs` and
`web/api/_lib/relay.js`.

## What M5 has to build

In the order that keeps each step demoable.

1. ~~**The relay learns the phone's key.**~~ **Done 2026-09-05.** The relay
   has `GET|POST|DELETE /api/phones` (`web/api/phones.js`, `_lib/phones.js`):
   a signed-in user registers `{device_id, public_key_hex, class: "enclave",
   name}`; the key is checked for shape and curve, the id for derivation, the
   class for being `enclave`, and a key already on another account is refused.
   `/api/approve` takes `public_key_hex` + `class` beside the signature; for
   `enclave` it requires the phone to be on the account under that key, for
   `test` it stamps the class on. The browser signer (`src/lib/sign.js`) now
   says `class: "test"` and shows its key. On the daemon, `RelayDevice`
   (`relay.rs`) takes the roster (`with_roster`) and keeps counters per
   signer (the old bare-integer `relay-counter` file is read as the test
   key's); `signer_key` mirrors `AppDevices::accept` — the ceremony is
   verified against the carried key, everything else against the roster
   record, refusing unenrolled, revoked, class-less, key-less, a test key
   claiming `enclave`, and an unknown key claiming `test`.
   **UI not done:** the rack has no Phones section yet; `api.js` has
   `phones`/`registerPhone`/`forgetPhone` ready for one.
2. ~~**Enrolling a phone.**~~ **Done 2026-09-05.** Bearer-authed
   `GET /api/device/phones` (`web/api/device/phones.js`) lists the account's
   phones as `publicPhone` records. `RelayDevice::devices()` fetches it,
   believes it for 5 s, drops anything not `enclave` or whose id is not its
   key's digest, and lists each phone (kind `phone · <name>`, class
   `enclave`) followed by the browser page (`test`); `info()` is the first
   phone, or the browser page when there is none. A successful signature from
   a phone not in the cached list clears the cache, so `Daemon::enroll` finds a
   phone that registered moments ago. The ceremony's advisory line now comes
   from every device that could sign — one class names it, several say "the
   class of the device that signs: enclave or test" (`enrollment_advisory` in
   `daemon.rs`). `tests/relay_phone.rs` runs a fake relay and a phone-shaped
   key through the whole thing: listed-but-unenrolled is refused; `enroll`
   writes an `enclave` record with a verifying proof; the next approval is
   accepted by a **default** verifier; the relay forgetting the phone changes
   nothing, because the roster is what is consulted.
   **Listing is a lookup, not a decision.** A relay that padded the list could
   add a name and could not get a signature accepted — `signer_key` still goes
   to the roster. Keep it that way.
3. **The iPhone app.** New SwiftPM/Xcode target `swift/SignetPhone` (an Xcode
   project will be needed for signing, capabilities and APNs; keep the code in
   SwiftPM targets and let Xcode consume `Package.swift`). Sign in to the
   relay (WorkOS — the relay's session cookie today; the app needs a token
   flow instead), register its `EnclaveDevice` key, poll or receive pushes,
   show the shared approval screen, Face ID on commit, post the signature to
   `/api/approve` (extended with `public_key_hex`/`class`). Pair by scanning a
   QR the Mac app shows (`/pair` mints the code today; render it as a QR in
   `MenuView`).
4. **Push.** APNs from the relay on `present`: payload is *only*
   `request_id`, the environment label and `digest_short` (device-classes
   §3.5). Never the statement. Needs an APNs auth key, team id and bundle id
   from Elijah. Long-poll stays as the fallback.
5. **End-to-end encryption to the phone.** Second enclave key for key
   agreement (`SecureEnclave.P256.KeyAgreement.PrivateKey`), registered with
   the relay; the daemon encrypts `request_json` and `render` to it (ECDH →
   HKDF → AES-GCM; Rust crates `p256` ecdh + `hkdf` + `aes-gcm`, network is
   available now); the relay stores ciphertext and the digest. The phone's
   digest check runs after decryption, unchanged. `PRODUCT.md` §7 leaves
   *whether this is M5 or M7* to Elijah; default to M5 unless told otherwise.

Entitlement and Stripe are **M7**, not M5.

## M6 so far

- **`signetd pack info <dir | file.wasm | name>`** — `packs::inspect` returns a
  `Report`: the manifest, the artifact's hash against the file, a module's
  imports (`countersign_pack::wasm_host::imports`), what the pack answers to
  `describe` inside the sandbox, the installed state, and where the manifest
  and the pack disagree. A native pack is never run by `info`; a swapped
  artifact is not looked at further. `main.rs` prints it.
- **`signetd pack new <name> [--namespace NS] [--dir PATH]`** — `scaffold.rs`
  embeds `templates/pack` (a workspace member, so it compiles and its tests
  run) and writes it renamed, with the dependency pointed at the repository
  and a release profile appended. **The git dependency only works once this
  work is pushed**; the scaffold's README says how to point at a checkout.
- Not done: the Plugins screen in the app (the bundled `countersign-db` runs
  without appearing there — `discover_packs` in `main.rs` spawns it beside
  the binary, outside `packs.toml`), the marketplace index, `countersign-tf`,
  and "publish a local pack as a PR".

## Decisions M5 needs from Elijah

- Apple Developer Program team, bundle identifiers (`com.addisdb.signet` is
  what the Mac app uses today), and an APNs key. Nothing pushes without them.
- Whether the hosted relay ever holds a plaintext payload (item 5 above).
- **Simulator builds.** The iOS simulator has no Secure Enclave, so
  `EnclaveDevice` throws there and the app cannot approve. For UI work a
  `#if targetEnvironment(simulator)` path using `SoftwareSigner` would help —
  but it must never attach as `enclave` to a real relay. Recommend: simulator
  builds attach only to the dev relay (`SIGNET_DEV_RELAY=1`) and are labelled
  `test`. Decide before writing it.
- Whether the web approval page stays as the test-key demo once phones are
  real, or is retired to "view only".

## Running things

```bash
cargo test --workspace && cargo clippy --workspace --all-targets   # Rust
(cd sdk/typescript && npm test)                                    # TypeScript SDK
(cd swift/CountersignKit && swift test)                            # the kit
(cd swift/Signet && swift test && ./build-app.sh)                  # the Mac app
(cd web && npm install && npm run dev:api & npm run dev)           # the relay, locally
cargo build -p countersign-db --lib --target wasm32-unknown-unknown --release   # the wasm pack
```

**A fresh start, for demos:** `signetd wipe --yes` removes everything the
daemon wrote (`crates/signetd/src/wipe.rs` is the list) and refuses while a
daemon listens; **Devices → Start over** in the Mac app stops its daemon, runs
that, forgets the enclave key (`EnclaveDevice.reset`) and comes back with a
new one. The relay's copy of a registered phone is not touched by either.

All four suites were green at handoff: 396 Rust tests, 32 TypeScript, 31 kit,
8 app. Clippy clean. After M5 steps 1–2 (2026-09-05): Rust and clippy still
green with `crates/signetd/tests/relay_phone.rs` added (3 tests), `web` at 22
tests (was 16), and `crates/signetd/tests/fixtures/remote-approval.json`
regenerated so the browser's signature carries `public_key_hex` and
`class: "test"`.

## Traps

- **This repo's Claude Code hook gates `rm`.** `.claude/settings.local.json`
  runs `countersign-hook` on every Bash call; a command containing `rm` is
  refused whole unless a daemon is listening on the *default* socket. Leave
  temp directories in `/tmp`; do not clean up with `rm` in a tool call.
- **Isolate the daemon when testing.** `XDG_CONFIG_HOME`, `COUNTERSIGN_RUNTIME_DIR`
  and `COUNTERSIGN_SOCK` (keep it short — `sun_path` is 104 bytes) put a
  daemon somewhere other than `~/.config/countersign`. The Mac app reads the
  same variables (`swift/Signet/Sources/SignetCore/Paths.swift`).
- **Swift packages are Swift 6 tools, Swift 5 language mode.** Deliberate; see
  each `Package.swift`. Strict concurrency will complain the moment that
  changes.
- **wasmi needs `portable-dispatch`.** Its tail-call dispatch overflows the
  native stack in unoptimized builds. Already set in
  `crates/countersign-pack/Cargo.toml`; do not remove it.
- **The Mac app's Secure Enclave key** lives under service `com.addisdb.signet`:
  in the data-protection keychain when the app carries an application
  identifier, in the legacy login keychain otherwise — the ad-hoc bundle from
  `build-app.sh` included. `CountersignKit.KeychainItem` decides which once
  per process, by a probe, because an unentitled *lookup* in the
  data-protection keychain says "not found" while a write says "missing
  entitlement". Deciding per call, as it did until 2026-09-05, generated a
  fresh key on every launch, and the first human enrollment did not survive a
  relaunch. A rebuilt ad-hoc binary is a different app to the legacy
  keychain, so expect a "Signet wants to use your confidential information"
  prompt after a rebuild; Always Allow is the answer.
- **`operator` is a Swift keyword.** The roster record's field is `owner` in
  Swift with a `CodingKeys` mapping; the wire stays `operator`.
- **Tests that block the main actor deadlock the app code.** The fake daemon
  in `swift/Signet/Tests` waits asynchronously for exactly this reason.
- **`$pending` fires before `pending` is set.** Combine's `@Published`
  publishes in `willSet`. The first human run of the Mac app (2026-09-05)
  opened the approval window from a `$pending` sink; the window read
  `session.pending` back, found nil, showed "Nothing pending", and closing it
  answered the enrollment `aborted`. The window now hangs off
  `AppSession.onPendingChange`, which is called from `didSet`;
  `theWindowIsToldAfterPendingIsSetNotBefore` in `SessionTests` pins the
  ordering. Do not go back to the sink.
