# Next steps

Everything still outstanding, in the order I would do it.

Sections 1–3 are work. Section 4 is the tail of decisions that were deferred
rather than made. Section 5 is what the offline build constrained — none of it
is a design decision, all of it is a constraint to re-examine with a network.

**Status:** 356 Rust tests, 23 TypeScript tests, 16 web tests, clippy clean.
Build-order steps 1–8 are done, and step 10 is half done — see §2.2. Hardware is
at Phase 0, and nothing below is blocked on it except where it says so.

---

## 1. Next up

### 1.1 Local HTTP + WebSocket transport

The last piece of build-order step 8. The unix socket covers same-machine
clients and SSH forwarding covers remote ones, so this is only needed for
clients that genuinely cannot use a socket: a browser, and eventually the cloud
relay.

- `127.0.0.1` only, with a token file readable solely by the user. **Localhost
  is not an authorization boundary** and the spec says so — the token is what
  makes it one.
- WS carries button events and device-state pushes; HTTP carries approvals.
- **Blocked offline:** no `axum` in the local cargo cache. See §5.3.

### 1.2 Client integrations

Build-order step 9, and the point where the "quality of the prompt" argument
pays off. A proxy sees SQL; a client knows the schema, the connection name and
the query plan, so it can populate `advisory` with something worth rendering.

Per the handoff's §1, find the **single execution chokepoint** in each client
before designing anything, and extend the existing read-only enforcement rather
than sitting beside it.

- VS Code extension — the TypeScript SDK exists for this now.
- Anything whose agent runs **in-process** with its executor is posture B at
  best, and the docs should say so rather than implying otherwise.

### 1.3 More domain packs

`countersign-db` is one pack and the protocol was built for many. The most
valuable next ones, from the addendum's Tier 1:

| Pack | Gated action |
|---|---|
| `countersign-tf` | `terraform apply` to prod, security-group and DNS edits |
| `countersign-k8s` | `kubectl delete namespace`, secret reads |
| `countersign-npm` | `npm publish`, container push, release tags |

`countersign-tf` is the best next one: the same blast-radius shape as DDL, and a
larger audience than DB clients.

**Remember:** a namespace is refused rather than shown until an operator enables
it (spec §6.2.2). Shipping a pack does not make it reachable, and that is
deliberate.

---

## 2. Bigger pieces

### 2.1 More wire protocols

The proxy is the coverage story and it currently speaks one protocol. MySQL and
MongoDB are the same shape: frame the wire, find the statement, authorize,
refuse politely in the protocol's own vocabulary.

MySQL is the obvious second — `COM_QUERY` and `COM_STMT_PREPARE` map cleanly
onto `Query` and `Parse`. Browser automation is the same shape and a harder
question about what gets rendered; it has its own section at §2.5.

### 2.2 The relay

Build-order step 10. Half of it exists — see [`web`](web).

**Built: the human-away-from-the-desk direction.** `signetd --device=relay`
presents to a hosted relay and blocks; the person answers on a phone with the
same payload, the same digest and the same hold; the daemon verifies the
signature itself before it believes any of it. The relay holds no key, and the
phone recomputes the digest from the request's own bytes and refuses to render
anything that disagrees, so a relay that rewrote a payload cannot get a
signature over the rewrite.

Signing is with a **second published test key**, so nothing on this path is a
production-valid approval and no verifier accepts one by default.

**Not built, and the harder half — the cloud-agent direction.** An agent with no
local presence POSTs a request and gets an id; the user's `signetd` holds a
subscription filtered to that user; the signature returns via the relay. Today
`signetd` is the one that starts every conversation, which is what makes the
relay a plain HTTP client and needs no inbound anything.

Still outstanding on what does exist:

- **The payload is not end-to-end encrypted.** The relay can read a statement.
  It cannot change one, which is the property that mattered most, but a hosted
  relay is currently a custodian of queries and should not have to be. Encrypt
  to the phone's key and the relay sees ciphertext plus a digest.
- **Long-polling, not WebSocket.** Serverless functions cannot hold a socket, so
  the daemon polls a call that holds for ~9 s. Fine for a demo, and the wrong
  shape for a fleet.
- ~~**The relay trusts its own pairing table for `device_id`.**~~ A phone now
  registers its enclave key (`web/api/phones.js`) and a signature says what
  signed it; the daemon verifies a phone against **its own roster** and the
  browser page against the derived test key, believing the relay about neither
  (`crates/signetd/src/relay.rs`). What remains is the *roster* trust model —
  a signed roster from an authority key, for teams — which is enrollment spec
  §7 and the same gap as §3's note about the proxy's hardcoded registry.
- **The dev store is in process memory.** It exists so the loop can be run on
  one machine without an account, behind two locks. It is not a smaller Redis.

This is still the one piece that wants to be a hosted service, and therefore the
one with a business model attached. It is also the one most likely to attract
requests for the things in spec §9. Hold that line.

### 2.3 Go port of the verifier

`countersign-verify` is the ecosystem surface, and Go is where the CI and cloud
integrations live. The TypeScript port already proved the vectors are portable;
Go is the second data point and would unblock a GitHub Action and a Vault
plugin.

Same rule as TypeScript: **check it against `spec/vectors/`**, not against the
Rust code.

### 2.4 Hardware, when Phase 2 boards exist

- Implement `signetd::device::Device`; `MockDevice` is the reference shape.
- Reconnect-on-unplug and device-state push are not written.
- **Firmware obligations that are specced and untested:** low-S normalization on
  the signing path (§4), the `device_id` derivation including the `0x04` prefix
  a secure element omits (§4.2), the arm delay and its restart-on-new-payload
  (§6.2.3), the rest transition after render (§6.2.3), the sustained hold
  measured from that transition (§6.3.4), the acknowledge button (§6.3.3), and
  the rule that a button can never carry an approval (§8).
- Then `countersign doctor`: round-trip latency, dial angle telemetry, render
  timing, counter continuity. The tool that answers "is it the software or the
  hardware".

### 2.5 A proxy for browser automation

The browser is the one surface with no chokepoint at all. A hook covers an agent
harness, the proxy covers a database, and an agent driving a browser is neither:
it never speaks to the daemon and it never speaks Postgres. Nothing here sits in
front of it, and a browser appears in this repository only on the *approving*
side, in [`web`](web).

The way in is the one §2.1 already describes, because browser automation **is** a
wire protocol. Chrome DevTools Protocol is JSON-RPC over a WebSocket, WebDriver
is JSON over HTTP, and Playwright has its own channel. Frame the wire, find the
action, authorize, refuse in the protocol's own vocabulary. Puppeteer,
Playwright, Selenium and every agent that drives a headless Chrome go through one
of them with no integration by any of them — the same argument that picked a
proxy over client integrations for databases.

**The hard part is not the framing, it is what the human reads.** Postgres hands
the proxy a statement that *is* the action, and `countersign-db` turns it into
something worth rendering. CDP hands it `Input.dispatchMouseEvent` at a
coordinate, which is a click on a pixel and means nothing on a screen. The unit
that can be rendered is not the unit that arrives on the wire, and designing that
mapping is the work.

The methods that carry a consequence, and are few enough to gate without training
someone to hold the dial without reading:

| CDP surface | Action | Why |
|---|---|---|
| `Page.navigate`, `Page.navigateToHistoryEntry` | `browser.navigate` | The destination origin is the blast radius |
| `Runtime.evaluate`, `Runtime.callFunctionOn`, `Page.addScriptToEvaluateOnNewDocument` | `browser.evaluate` | Arbitrary script inside an authenticated session. The highest severity a pack can raise to |
| `Network.getAllCookies`, `Storage.getCookies` | `browser.credentials` | A session cookie read is an exfiltrated login |
| `Fetch.*`, `Network.setExtraHTTPHeaders` | `browser.intercept` | Rewriting requests inside a session a human authenticated |
| `Browser.setDownloadBehavior`, `Page.setDownloadBehavior` | `browser.download` | Writes that land outside the browser |

Clicks, typing and scrolling are deliberately **not** on that list. A gate on
every input frame produces hundreds of prompts an hour, and someone who has held
the dial two hundred times is not reading the two hundred and first. That is the
failure the non-goals exist to prevent, reached from the other end.

So the shape is `countersign-web`, a pack mapping a method and its parameters
onto a statement and a severity, plus a proxy that speaks the debugging port. The
daemon learns nothing about CDP, which is the whole reason packs are a protocol
(`spec/pack-protocol-v1.md` §1).

**How much of a posture this is.** Genuine C for an automated browser, on one
condition: the real debugging port is reachable only by the proxy and the agent
cannot start a browser of its own with a fresh one. That is the same condition
the database proxy already has — it is posture C because there is no route around
it — and it is easier to state than to hold on a laptop where an agent with a
shell can launch Chrome however it likes. Write that in the README rather than
implying otherwise.

**What it does not reach**, and must not be sold as reaching:

- A human's own browsing. Not the threat model, and never was.
- An agent running *inside* the browser as an extension. It is not on the far
  side of any wire, it is in the process — posture B at best, and only for what
  the extension itself routes through a gate.
- An agent on a remote service acting through its own browser. Nothing local is
  in that path at all. That is §2.2's cloud-agent direction, and no proxy on this
  machine substitutes for it.

Order: after MySQL in §2.1. MySQL proves the proxy generalizes across protocols
of the same shape; this one asks the harder question of what a renderable action
is when the wire does not hand you one, and the answer is reusable for every
non-statement protocol after it.

---

## 3. Smaller, worth doing

- **Extract a thin client crate.** `countersign-proxy` depends on all of
  `signetd` just for `service::Client` and `daemon::ApprovalRequest`, which
  drags the device and audit code into a binary that needs neither.
- **Audit checkpoints are specced but never written.** `Checkpoint` exists and
  is tested; nothing in `signetd` emits one on a schedule. Until it does,
  truncation of the trail is undetectable.
- **`signetd` has no `audit` subcommand.** Verifying and exporting a trail
  currently means writing Rust. `signetd audit verify` and
  `signetd audit export --disclosure=digests-only` are the obvious pair.
- **Enrollment has no CLI.** `spec/enrollment-v1.md` §2 describes the ceremony
  and `countersign-verify` implements every check, but nothing runs it.
  `signetd enroll --subject alice@example.com` is the missing piece, and without
  it the trust root is theory.
- **The proxy's registry is hardcoded to the test key.** It should load a signed
  roster and trust one authority key configured out of band. `countersign-hook`
  has the same shape and now compiles in *two* test keys — the mock's and the
  remote one — which makes the smell harder to ignore.
- **A remote approval is a weaker claim, and the spec does not say so.** The
  phone is a second device class: a general-purpose OS, no screen the requesting
  software cannot reach. It signs with a published test key so nothing turns on
  it today, but the moment an enclave-backed key is on the table the spec needs
  a device-class field and a written-down claim per class. Do that *before*
  building the enclave path, not after.
- **`SignedRoster` cannot be signed by a Signet.** `spec/enrollment-v1.md` §4.2
  calls that the natural end state; it needs a small format addition (carry an
  `ApprovalEnvelope` rather than a raw signature) so the roster change is
  displayed and countersigned like anything else. The wrong fix is a firmware
  raw-sign mode — that is blind signing.

---

## 4. Deferred decisions

Not blocked, just not decided. Each will get harder to change later.

**Audit sync.** `spec/audit-v1.md` §6 says the chain may sync and payloads
should not, and nothing implements either. The question underneath is whether
you run a hosted compliance product — which is a different business with
different privacy obligations.

**Multi-writer replay state.** `FileStore` is single-writer. Two verifiers
sharing a state directory would race and nothing detects it. Advisory locking
catches it at the cost of stale-lock recovery; a shared backend is the answer at
scale. Neither is worth building until something actually runs two verifiers
against one history.

**Manufacturer attestation.** Reserved in `spec/enrollment-v1.md` §7 and
unspecified. A factory certificate proving a key lives in genuine hardware is a
*different claim* from "this device belongs to Alice" and must not be conflated
with it. Out of scope until hardware exists.

**Requester continuity across short-lived clients.** The device asks for an
acknowledgement when the requester changes, and `signetd` keys that on the
control-socket connection — the one thing about a caller it can actually verify.
The MCP bridge holds one connection per session, so the check means what it
says. `countersign-hook` is a fresh process per tool call, so the check reads
"changed" every single time and the operator types `ack` before every `turn`,
which drains the acknowledgement of the information it exists to carry. This
applies to every per-invocation enforcement point: a hook, a CLI, a cron job.

The three candidates are in `crates/countersign-hook/README.md`. The one worth
noting here is that the obvious fix — key continuity on the claimed requester id
instead — is the wrong one: a check keyed on a claim is defeated by making the
claim. Verified peer credentials plus a registered session is the only option
that keeps the acknowledgement honest, and it is the most machinery.

**Windows.** `signetd::service` uses `std::os::unix::net` and
`signetd::interactive` assumes a POSIX terminal. Named pipes and a different
console path. No work done.

**AddisDB dependency inversion.** `countersign-sql` was ported out of AddisDB so
that one implementation serves both, and AddisDB still has its own copies. Until
it depends back, the two can drift — and a classifier that disagrees with the
read-only gate in front of it waves through exactly what the gate would block.
Deliberately deferred.

---

## 5. Constrained by the offline build

This workspace was built on a machine with no network, against whatever was in
the local cargo registry cache. Nothing here is a design decision.

### 5.1 `p256` is pinned to a pre-release

`p256 = "0.14.0-rc.10"`, with `ecdsa 0.17.0-rc.18` and
`elliptic-curve 0.14.0-rc.33` underneath. That is the only generation in the
cache.

A release-candidate crypto dependency in the crate whose entire job is signature
verification deserves a deliberate look:

- Check whether 0.14 has shipped final and move to it.
- Otherwise consider pinning back to stable `p256 0.13`, which means adjusting
  `sha2` to 0.10 and the `SigningKey::from_slice` / `to_sec1_bytes` call sites.
- The blast radius is small on purpose: `SignatureBackend` is a trait and the
  RustCrypto implementation is one ~15-line module behind the `ecdsa-p256`
  feature. Everything else in `countersign-verify` compiles with no crypto
  dependency at all.

**Whatever replaces it, confirm it does not normalize `s` on the signing path.**
RustCrypto does not, and Node does not. That is how three of four signature
paths here shipped without a low-S check and a committed vector went out high-S.

### 5.2 No `hidapi`, so no real device

Not on the critical path — hardware is Phase 0 and the mock is the plan until
Phase 2 boards exist. See §2.4 for what lands with it.

### 5.3 No `axum`, so no local HTTP/WS

Blocks §1.1. The socket plus SSH forwarding covers more than it looks, so this
is not urgent.

### 5.4 MCP is hand-rolled

No MCP SDK was cached, so `signetd::mcp` implements the three methods it needs
directly over line-delimited JSON-RPC.

This is probably worth **keeping**: the bridge is under 300 lines, an SDK would
be larger than the thing it replaced, and this is deliberately the component
with no keys and no authority. Revisit only if MCP adds something the bridge
should support.

### 5.5 Not verified against a released registry

`Cargo.lock` was resolved entirely from cache. Once online, run a clean
`cargo update` and full test on a fresh checkout to confirm nothing depends on a
version that only exists on this machine.

---

## What is deliberately not on this list

From `spec/countersign-v1.md` §9, written down so they are not re-litigated by
whoever has the most revenue attached to the request:

batch approval · remember-for-N-minutes · pattern-based auto-approve · a display
field separate from the signed payload · any software path to a production-valid
signature · delegating approval to another agent · anti-automation heuristics.

The moment any of these ships, the product is a confirmation dialog with a USB
cable.
