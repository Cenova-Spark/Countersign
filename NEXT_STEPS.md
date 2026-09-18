# Next steps

Everything outstanding, in one list. Work that is finished is not here — if you
are looking for what exists and how it behaves today, that is
[`HANDOFF.md`](HANDOFF.md), which is the state rather than the plan.

**Section 1 blocks.** Nothing in it can be resolved by writing code, and several
things below wait on it.

**Status, 2026-09-17:** 443 Rust tests and clippy clean, 32 TypeScript, 32 kit,
7 SignetUI, 11 Mac app, 22 relay. Protocol build-order steps 1–8 are done and
step 10 is half done (§5). Hardware is at Phase 0, and nothing here is blocked
on it except §7.

---

## 1. Decisions needed from Elijah

- **Bundle identifiers.** `com.addisdb.signet` is what the Mac app uses; the
  phone needs its own. Nothing signs or ships until these are settled.
- **An APNs auth key**, plus the team id (`6T9YRXK82U` has Developer ID
  certificates on this Mac already). No key, no push.
- **Simulator builds.** The iOS simulator has no Secure Enclave, so
  `EnclaveDevice` throws there and the app cannot approve at all. A
  `#if targetEnvironment(simulator)` path over `SoftwareSigner` would unblock UI
  work — but it must never attach as `enclave` to a real relay. Recommended:
  simulator builds attach only to a dev relay (`SIGNET_DEV_RELAY=1`) and are
  labelled `test`. Decide before writing it, not after.
- **May the hosted relay ever hold a plaintext payload?** This is the
  whether-it-is-M5-or-M7 question for end-to-end encryption (§2, §5).
- **Does the web approval page survive?** Once phones are real it is either a
  test-key demo that stays, or it is retired to view-only.
- **Audit sync.** `spec/audit-v1.md` §6 says the chain may sync and payloads
  should not; neither is implemented. The question underneath is whether you run
  a hosted compliance product, which is a different business with different
  privacy obligations.
- **Requester continuity for per-invocation clients.** The device asks for an
  acknowledgement when the requester changes, keyed on the control-socket
  connection — the one thing about a caller the daemon can verify. The MCP
  bridge holds one connection per session, so the check means what it says.
  `countersign-hook` is a fresh process per tool call, so it reads "changed"
  every single time and the operator types `ack` before every `turn`, which
  drains the acknowledgement of the information it exists to carry. The same
  applies to any CLI or cron job.

  Three candidates are in `crates/countersign-hook/README.md`. The one worth
  repeating: keying continuity on the *claimed* requester id is the wrong fix,
  because a check keyed on a claim is defeated by making the claim. Verified
  peer credentials plus a registered session is the only honest option, and it
  is the most machinery.

---

## 2. M5 — the iPhone app

The shared approval screen is done (`swift/SignetUI`); a phone target renders
`PendingView` and writes an `ApprovalActions`. What is left is the app around
it. [`HANDOFF.md`](HANDOFF.md) carries the detailed plan for each step; this is
the checklist.

- **`swift/SignetPhone`.** An Xcode project is needed for signing, capabilities
  and APNs — keep the code in SwiftPM targets and let Xcode consume
  `Package.swift`.
- **Sign in to the relay.** It uses a session cookie today; the app needs a
  token flow.
- **Register the `EnclaveDevice` key**, poll or receive pushes, Face ID on
  commit, post the signature to `/api/approve` (which already takes
  `public_key_hex` and `class`).
- **Pairing.** `/pair` mints a code; render it as a QR in the Mac app's
  `MenuView` and scan it.
- **Push.** APNs from the relay on `present`. The payload is *only*
  `request_id`, the environment label and `digest_short` — never the statement
  (device-classes §3.5). Long-poll stays as the fallback.
- **End-to-end encryption to the phone.** A second enclave key for key
  agreement, registered with the relay; the daemon encrypts `request_json` and
  `render` to it (ECDH → HKDF → AES-GCM). The phone's digest check runs after
  decryption, unchanged. Gated on the decision in §1.
- **The rack has no Phones section.** `web/src/lib/api.js` already has
  `phones`, `registerPhone` and `forgetPhone` waiting for one.

---

## 3. M6 leftovers

- **`countersign-tf`** — the `countersign-plugin` skill can scaffold it in
  minutes, and it is the highest-value second pack: the same blast-radius shape
  as DDL with a larger audience than DB clients. `countersign-k8s` and
  `countersign-npm` after it.
- **The marketplace as its own repository**, with CI running the pack-protocol
  §8.4 checks. `pack publish` runs them locally today.
- **Opening the pull request from the app.**
- **`pack info` in the app** before an index install.
- **Run `evals/evals.json`** (three prompts) through the skill-creator loop.

A namespace is refused rather than shown until an operator enables it (wire spec
§6.2.2). Shipping a pack does not make it reachable, and that is deliberate.

---

## 4. M7 — not started

- Payment, entitlement, Stripe.
- App Store.

---

## 5. The relay

Build-order step 10, half built. The human-away-from-the-desk direction works;
the cloud-agent direction does not exist.

- **The cloud-agent direction.** An agent with no local presence POSTs a request
  and gets an id; the user's `signetd` holds a subscription filtered to that
  user; the signature returns via the relay. Today `signetd` starts every
  conversation, which is what makes the relay a plain HTTP client needing no
  inbound anything.
- **The payload is not end-to-end encrypted.** The relay can read a statement.
  It cannot *change* one — the phone recomputes the digest and refuses to render
  a disagreement — but a hosted relay is currently a custodian of queries and
  should not have to be.
- **Long-polling, not WebSocket.** Serverless functions cannot hold a socket, so
  the daemon polls a call that holds for ~9 s. Fine for a demo, wrong for a
  fleet.
- **The roster trust model.** A phone is verified against the daemon's own
  roster, not the relay's word. What is missing is a *signed* roster from an
  authority key, for teams — enrollment spec §7, and the same gap as the proxy
  registry in §6.
- **The dev store is process memory.** It exists so the loop runs on one machine
  without an account. It is not a smaller Redis.

This is the one piece that wants to be a hosted service, and therefore the one
with a business model attached. It is also the one most likely to attract
requests for the things in §9. Hold that line.

---

## 6. Protocol and infrastructure

### Transports and reach

- **Local HTTP + WebSocket**, `127.0.0.1` only with a token file readable solely
  by the user — localhost is not an authorization boundary, and the token is
  what makes it one. Only needed for clients that cannot use a socket: a
  browser, and the relay. **Blocked offline:** no `axum` cached (§8).
- **Client integrations.** Find the single execution chokepoint in each client
  first, and extend its existing read-only enforcement rather than sitting
  beside it. VS Code first — the TypeScript SDK exists for it. Anything whose
  agent runs *in-process* with its executor is posture B at best, and the docs
  should say so.
- **MySQL and MongoDB proxies.** Same shape as Postgres: frame the wire, find
  the statement, authorize, refuse in the protocol's own vocabulary. MySQL is
  the obvious second — `COM_QUERY` and `COM_STMT_PREPARE` map cleanly onto
  `Query` and `Parse`.

### A proxy for browser automation

The browser is the one surface with no chokepoint at all: an agent driving one
never speaks to the daemon and never speaks Postgres. Browser automation *is* a
wire protocol — CDP is JSON-RPC over a WebSocket, WebDriver is JSON over HTTP —
so the way in is the same as any other proxy.

**The hard part is not the framing, it is what the human reads.** Postgres hands
the proxy a statement that *is* the action. CDP hands it
`Input.dispatchMouseEvent` at a coordinate, which means nothing on a screen. The
unit that can be rendered is not the unit that arrives on the wire, and
designing that mapping is the work.

| CDP surface | Action | Why |
|---|---|---|
| `Page.navigate`, `Page.navigateToHistoryEntry` | `browser.navigate` | The destination origin is the blast radius |
| `Runtime.evaluate`, `Runtime.callFunctionOn`, `Page.addScriptToEvaluateOnNewDocument` | `browser.evaluate` | Arbitrary script inside an authenticated session |
| `Network.getAllCookies`, `Storage.getCookies` | `browser.credentials` | A session cookie read is an exfiltrated login |
| `Fetch.*`, `Network.setExtraHTTPHeaders` | `browser.intercept` | Rewriting requests inside a session a human authenticated |
| `Browser.setDownloadBehavior`, `Page.setDownloadBehavior` | `browser.download` | Writes that land outside the browser |

Clicks, typing and scrolling are deliberately **not** on that list. A gate on
every input frame produces hundreds of prompts an hour, and someone who has held
the dial two hundred times is not reading the two hundred and first.

Shape: `countersign-web`, a pack mapping a method and its parameters onto a
statement and a severity, plus a proxy speaking the debugging port. It is
genuine posture C on one condition — the real port is reachable only by the
proxy and the agent cannot start a browser with a fresh one — which is easier to
state than to hold on a laptop. Say that in the README rather than implying
otherwise. It does **not** reach a human's own browsing, an agent running inside
the browser as an extension, or an agent on a remote service acting through its
own browser.

Order: after MySQL. MySQL proves the proxy generalizes across protocols of the
same shape; this asks the harder question of what a renderable action is when
the wire does not hand you one, and the answer is reusable for every
non-statement protocol after it.

### Ports and tooling

- **A Go port of the verifier.** Go is where the CI and cloud integrations live,
  and it would unblock a GitHub Action and a Vault plugin. Check it against
  `spec/vectors/`, never against the Rust.
- **Extract a thin client crate.** `countersign-proxy` depends on all of
  `signetd` for `service::Client` and `daemon::ApprovalRequest`, dragging the
  device and audit code into a binary that needs neither.
- **`signetd audit verify` and `signetd audit export --disclosure=digests-only`.**
  Verifying or exporting a trail means writing Rust today.

### Gaps that weaken a claim

- **Audit checkpoints are specced but never emitted.** `Checkpoint` exists and
  is tested; nothing in `signetd` writes one on a schedule, so truncation of the
  trail is undetectable.
- **The proxy's registry is hardcoded to the test key.** `countersign-hook`
  already loads the daemon's local `roster.json` and compiles the test keys in
  only under `--accept-test-keys`. The proxy should follow, and both should move
  from a local roster to a signed one.
- **A remote approval is a weaker claim and the spec does not say so.** The
  phone is a second device class: a general-purpose OS, no screen the requesting
  software cannot reach. It signs with a published test key so nothing turns on
  it today, but the moment an enclave-backed key is on the table the spec needs
  a device-class field and a written claim per class. Do that **before**
  building the enclave path.
- **`SignedRoster` cannot be signed by a Signet.** `spec/enrollment-v1.md` §4.2
  calls that the natural end state; it needs a format addition carrying an
  `ApprovalEnvelope` rather than a raw signature, so a roster change is
  displayed and countersigned like anything else. The wrong fix is a firmware
  raw-sign mode — that is blind signing.
- **Multi-writer replay state.** `FileStore` is single-writer; two verifiers
  sharing a state directory would race and nothing detects it. Advisory locking
  catches it at the cost of stale-lock recovery; a shared backend is the answer
  at scale. Not worth building until something actually runs two.
- **Manufacturer attestation.** Reserved in `spec/enrollment-v1.md` §7 and
  unspecified. A factory certificate proving a key lives in genuine hardware is
  a *different claim* from "this device belongs to Alice" and must not be
  conflated with it. Out of scope until hardware exists.
- **Windows.** `signetd::service` uses `std::os::unix::net` and
  `signetd::interactive` assumes a POSIX terminal. Named pipes and a different
  console path. No work done.
- **AddisDB dependency inversion.** `countersign-sql` was ported out of AddisDB
  so one implementation serves both, and AddisDB still has its own copies. Until
  it depends back the two can drift — and a classifier that disagrees with the
  read-only gate in front of it waves through exactly what the gate would block.

---

## 7. Hardware, when Phase 2 boards exist

- Implement `signetd::device::Device`; `MockDevice` is the reference shape.
  Reconnect-on-unplug and device-state push are not written.
- **Firmware obligations that are specced and untested:** low-S normalization on
  the signing path (§4), the `device_id` derivation including the `0x04` prefix
  a secure element omits (§4.2), the arm delay and its restart-on-new-payload
  (§6.2.3), the rest transition after render (§6.2.3), the sustained hold
  measured from that transition (§6.3.4), the acknowledge button (§6.3.3), and
  the rule that a button can never carry an approval (§8).
- Then `countersign doctor`: round-trip latency, dial angle telemetry, render
  timing, counter continuity. The tool that answers "is it the software or the
  hardware".

---

## 8. Constrained by the offline build

Built against whatever was in the local cargo registry cache. None of this is a
design decision. `HANDOFF.md` notes network was available by 2026-09-05, so the
first thing to do here is re-check rather than assume.

- **`p256` is pinned to `0.14.0-rc.10`** — still, as of 2026-09-17 — with
  `ecdsa 0.17.0-rc.18` and `elliptic-curve 0.14.0-rc.33` under it. A release
  candidate in the crate whose whole job is signature verification deserves a
  deliberate look. The blast radius is small on purpose: `SignatureBackend` is a
  trait and the RustCrypto implementation is one small module behind the
  `ecdsa-p256` feature.

  **Whatever replaces it, confirm it does not normalize `s` on the signing
  path.** RustCrypto does not, Node does not, CryptoKit does not. That is how
  three of four signature paths once shipped without a low-S check and a
  committed vector went out high-S.
- **No `hidapi`** in the lock — no real device. Not on the critical path; see §7.
- **No `axum`** in the lock — blocks the local HTTP/WS transport in §6.
- **MCP is hand-rolled.** Probably worth keeping: the bridge is small, an SDK
  would be larger than the thing it replaced, and it is deliberately the
  component with no keys and no authority. Revisit only if MCP adds something
  the bridge should support.
- **`Cargo.lock` was resolved entirely from cache.** Run a clean `cargo update`
  and full test on a fresh checkout to confirm nothing depends on a version that
  exists only on this machine.

---

## 9. What is deliberately not on this list

From `spec/countersign-v1.md` §9 and device-classes §8, written down so they are
not re-litigated by whoever has the most revenue attached to the request:

batch approval · remember-for-N-minutes · pattern-based auto-approve · a display
field separate from the signed payload · any software path to a
production-valid signature · a software key enrolled as a device · approving
from a notification · delegating approval to another agent · anti-automation
heuristics.

The moment any of these ships, the product is a confirmation dialog with a USB
cable.
