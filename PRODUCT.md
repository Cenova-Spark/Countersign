# The product before the hardware

**An app that approves with Face ID or Touch ID, a service that delivers the
request to it, and a marketplace that teaches it what it is looking at — built
on what is in this repository, without waiting for a Signet board.**

Status: a plan. The spec change it depends on is drafted beside it in
[`spec/device-classes-v1.md`](spec/device-classes-v1.md). Nothing below is
built yet; §5 is the order to build it in.

---

## 1. The one decision everything rests on

Today the repository holds one line and holds it hard: **no software path
produces a production-valid signature.** The terminal mock, the scripted mock
and the phone relay all sign with published test keys, and a default verifier
refuses every one of them. That is what has let the whole system be built and
demonstrated without a single bypass that could survive into production.

A product in which an app's approval *counts* has to cross that line, and the
only honest way across is the one the docs have been pointing at for a while —
`web/README.md`, `NEXT_STEPS.md` §3 and the wire spec's own §8 all say the same
thing: a phone is a **second device class**, weaker than a Signet, and making
it real is a spec change before it is a code change.

So the decision is:

> An approval signed by a **non-extractable key in a secure enclave, unlocked
> by an operating-system presence check on every use**, rendered from the
> bytes it signs, with the arm delay, rest transition and hold intact, is a
> real approval with a smaller claim. It is class `enclave`. A default
> verifier accepts it. An operator who wants hardware only writes
> `accept_classes = ["signet"]`.

What survives, exactly: the line becomes *no path without an enclave-resident
key and a per-use presence check produces a production-valid signature.* Test
keys are still refused. Every non-goal in wire spec §9 still stands, and the
app makes each of them easier to build and none of them acceptable. When
hardware ships, nothing sold before it becomes worthless and nothing said about
the phone being weaker becomes untrue — the verifier just gets one more line of
config.

That decision is written out in normative form in
[`spec/device-classes-v1.md`](spec/device-classes-v1.md). Read that first; the
rest of this document assumes it.

---

## 2. What it looks like

```
   iPhone app ─── Face ID ── enclave key ──┐
        ▲                                  │
        │ APNs: "something is waiting"     │  signatures, verified by
        │ (an id, a label, a digest —      │  the daemon against its
        │  never the statement)            │  own roster
        │                                  │
   ┌────┴─────── the relay ───────────┐    │
   │  signet.addisdb.com · holds no   │    │
   │  key · sees ciphertext + digest  │    │
   │  · paid, or self-hosted for free │    │
   └────▲─────────────────────────────┘    │
        │ present / await                  │
        │ (unchanged)                      │
   ┌────┴──────────── the Mac app ─────────┴──────────────────────────┐
   │  menu bar · bundles signetd · Touch ID ── enclave key            │
   │  devices: this Mac · your iPhone · (a Signet, when it exists)    │
   │  plugins: installed / enabled · audit · pair a phone by QR       │
   └────▲──────────────────────────▲──────────────────────────────────┘
        │ unix socket / MCP        │ packs (wasm, sandboxed)
   Claude Code · hooks · proxy     countersign-db · countersign-tf · yours
```

Four surfaces, each with one job:

- **The Mac app** is where the daemon lives, so it is where agents connect,
  where packs run, and where a USB Signet will plug in. It approves with Touch
  ID when you are at the desk.
- **The iPhone app** approves with Face ID when you are not. It never talks to
  the daemon directly; the relay is the transport, and the daemon still
  verifies everything itself.
- **The relay** delivers. It is the thing you pay for, and the thing you can
  run yourself for nothing.
- **The marketplace** is a git repository with an index in it. Anyone can add
  a plugin by pull request; nothing in it can light up a dial until an
  operator turns it on.

---

## 3. The ask, mapped onto the code

| You asked for | What exists | What has to change |
|---|---|---|
| An app that requires Face ID / Touch ID / a password | The relay UI in `web/`, with the arm delay, rest transition and hold already right (`web/src/lib/hold.js`), signing with a published test key | The `enclave` class; a Swift package with the crypto and the gesture rules; the apps; a Secure Enclave key gated by biometry on every signature |
| A notification when an action needs me | Daemon → relay `present`, phone polls every two seconds | APNs pushes carrying an id, a label and a digest — the app fetches the payload |
| Plugins I can install, uninstall, and turn on and off | Packs are stdio executables; `signetd` finds `countersign-db` next to its own binary and nothing else (`discover_packs` in `crates/signetd/src/main.rs`); a namespace is presentable only if policy names it | A `[[pack]]` section in config, a packs directory, `signetd pack install/remove/enable/disable/list`, and the same in the app. **Installed** = on disk. **On** = its namespaces are presentable. Wire spec §6.2.2 already gives you exactly those two states |
| A marketplace anyone can add to, including me publishing my own | The pack protocol — two methods, any language | A plugin manifest, an index repository, a rule that anything distributed is WebAssembly, and a publish flow |
| The hardware plugs in when it exists | The `Device` trait with mock and relay implementations; no `hidapi` yet | A USB implementation. Nothing else moves; the app shows one more row under Devices |
| One-time payment for the service | WorkOS sign-in, Upstash store, Vercel functions | Stripe Checkout → an entitlement on the account; the relay checks it on `pair` and `present`; the free self-hosted relay is untouched |

---

## 4. The pieces

### 4.1 The spec — `spec/device-classes-v1.md`

Drafted. The short version: a `class` on every enrollment record (`signet` ·
`enclave` · `test`), a written claim per class, `accept_classes` on the
verifier defaulting to `{signet, enclave}`, and a section of obligations for
anything calling itself `enclave` — including the two rules that matter most
for an app: **the counter and the key live and die together**, and **no
approval from a notification, ever.**

### 4.2 `countersign-verify`

Small and mechanical: `class` on `EnrollmentRecord` and `EnrolledDevice`, the
agreement check with `is_test_key`, `accept_classes` on `VerifyPolicy`, a
class-rejected error before the cryptography, and the class on each
`VerifiedSigner`. The TypeScript SDK mirrors it. Both keep passing the existing
vectors; a new vector pins an `enclave` record.

### 4.3 `signetd`

Five changes, in dependency order.

**`signetd enroll`.** `NEXT_STEPS` §3 already lists it as the missing piece that
makes the trust root real. The app path needs it: the daemon must hold an
enrollment record for every device it will accept signatures from, in a local
roster (`~/.config/countersign/roster.json`, the *direct* trust model from
enrollment spec §7). The ceremony is the ordinary one — the device renders
*Enroll this device as an approver for you@example.com* and a human holds.

**The app as a device — `--device=app`.** A new `Device` implementation. The
app connects to the control socket and attaches as a device (`device.attach`,
a method that holds the connection); the daemon pushes `device.present` down
that connection and waits on a channel bounded by the TTL; the app answers with
a signature; the daemon verifies it the way `RelayDevice::accept` already does
— device id, counter ahead of the high-water mark, low-S, the signature over
its own digest — except against the enrolled record instead of a derived test
key. The control socket is already line-delimited JSON-RPC, so this is a method
on it, not a new transport.

**Several devices at once.** Today `Daemon` owns one `Box<dyn Device>`. It
needs a fan-out: present to every attached device — the Mac app, the phone via
the relay, later the USB Signet — take the first valid signature, withdraw the
payload from the rest. One request, one signature; wire spec §5.1's list stays
length one.

**Packs from config, not from a hard-coded list.**

```toml
[[pack]]
name    = "countersign-db"
enabled = true

[[pack]]
name    = "countersign-tf"
enabled = false        # installed, but its namespace is not presentable
```

with a directory per pack under `~/.config/countersign/packs/<name>/` holding
the manifest and the artifact. `enabled = true` adds the pack's claimed
namespaces to `policy.presentable`; `false` removes them, so a request in that
namespace is refused without a human ever being asked, which is what the spec
says an unconfigured namespace deserves. A manifest may *propose* policy rules;
the daemon never applies them silently — the app shows them and the operator
accepts each one.

**A WebAssembly pack host.** `PackHost::spawn` runs a subprocess.
`PackHost::spawn_wasm` instantiates a module with an **empty import section**
and drives it one JSON-RPC line at a time through four exports — no filesystem,
no network, no environment, no clock, not because they were withheld but
because the module cannot name them. The messages do not change by a byte;
only where the bytes go does. `countersign-db` already does no I/O; built for
`wasm32-unknown-unknown`, `countersign_pack::export_pack!` wraps it. Every call
is metered in fuel and memory is capped, so a hostile module degrades to the
fail-closed path rather than a hang. This is what makes a public marketplace of
classifiers that see production SQL acceptable — see §4.7 — and it delivers the
sandbox that pack protocol §5 has been saying hosts SHOULD have. (Built in M2
with `wasmi`, an interpreter: seconds to compile, and it runs on iOS later
without a JIT.)

### 4.4 `CountersignKit` — the Swift package

One package, shared by both apps, with no UI in it:

- JCS canonicalization, SHA-256, `request_digest`, the twelve-character digest
  — ported from `web/src/lib/jcs.js` and `sign.js`, tested against
  `spec/vectors/` and not against the Rust, for the reason `web/README.md`
  gives.
- The signing payload (`"countersign-v1" || 0x00 || digest || counter || ms`)
  and **low-S normalization**. CryptoKit does not normalize `s`, exactly like
  WebCrypto and RustCrypto, so this is the fourth signer in the repository that
  has to do it by hand and be tested over hundreds of signatures rather than
  one.
- The enclave key: `SecureEnclave.P256.Signing.PrivateKey` with an access
  control of `biometryCurrentSet`, and no passcode fallback on macOS. Its
  `x963Representation` is the SEC1 uncompressed encoding wire spec §4.2
  hashes, and its signature's `rawRepresentation` is `r || s` — the platform
  already speaks the spec's two encodings.
- The counter, in a `ThisDeviceOnly` keychain item, bound to the key per
  device-class spec §3.4, advanced and persisted before a signature is
  returned.
- The hold state machine — a port of `hold.js`: arm from paint, rest
  transition, severity-scaled hold, lapse on background. The existing
  fake-clock tests port with it.
- A fixture the Rust side verifies, the way
  `crates/signetd/tests/fixtures/remote-approval.json` closes the loop for the
  browser today.

### 4.5 The Mac app

A menu bar app (`MenuBarExtra`), not a window you have to find. It:

- Bundles `signetd` and its packs, starts the daemon at login with
  `--device=app`, and attaches to it. The existing socket, MCP bridge, hook
  and proxy all keep working untouched — they never learn the daemon is being
  run by an app.
- Shows a sheet when something is presented: the environment label, the render
  lines, the advisory marker, the digest. Acknowledge is a button. The hold is
  the dial control, ported from `SignetDevice.vue`. The hold commits, Touch ID
  prompts, the enclave signs.
- **Devices**: this Mac, each paired phone, and — later — the USB Signet.
  Enroll, rename, revoke.
- **Plugins**: installed and enabled, per §4.3, with the marketplace browser
  from §4.7.
- **Audit**: the chain the daemon already writes, with the export the daemon
  does not yet have a subcommand for.
- **Pair a phone**: shows the pairing code as a QR the phone scans, replacing
  reading eight characters off a screen by hand.

Distributed **outside the Mac App Store**, notarized. It has to spawn a daemon,
own a unix socket and later a USB device, none of which sits well in the App
Store sandbox — and staying outside keeps Apple's in-app purchase rules off the
desktop entirely.

One honest limit: a Mac in clamshell mode with no Touch ID keyboard cannot
satisfy `biometryCurrentSet`, so it cannot approve. The phone can. That is the
correct direction for it to fail.

### 4.6 The iPhone app

The same SwiftUI views on a phone. It pairs by scanning the QR, enrolls its
enclave key through the relay, registers for push, and approves with Face ID.
The relay is the only thing it talks to; the daemon on the Mac is what
verifies.

What is *not* here: an approve action on the notification, a widget, a watch
complication, or anything else that could approve without the full render and
the hold. Device-class spec §3.2 forbids it, and the reason is the reflex
attack in wire spec §6.2, not taste.

### 4.7 Plugins and the marketplace

**A plugin** is a directory with a manifest and one or more of: a **pack** (a
classifier, the thing the protocol already defines), an **integration** (a
requester — a hook, an MCP bridge, a proxy adapter), and a **proposed policy**
(rules the operator may accept). The three are separated because they have
different trust: a pack sees statements and must be sandboxed; an integration
is a process that asks; a policy fragment is text the operator reads.

```jsonc
// countersign-plugin.json
{
  "v": 1,
  "name": "countersign-tf",
  "version": "0.3.1",
  "description": "terraform plan, apply and state operations",
  "license": "Apache-2.0",
  "source": "https://github.com/…/countersign-tf",
  "pack": {
    "kind": "wasm",
    "artifact": "countersign-tf.wasm",
    "sha256": "…",
    "actions": ["terraform"],
    "pure": true
  },
  "policy": [
    { "tier": "production",  "actions": ["terraform.apply"], "decision": "require_approval" },
    { "tier": "development", "actions": ["terraform.plan"],  "decision": "auto_approve" }
  ]
}
```

**Two states.** *Installed* means the directory exists. *Enabled* means its
namespaces are presentable. Uninstalling removes the directory; disabling
leaves it and stops the namespace being shown. This is not a new concept
invented for a settings screen — it is wire spec §6.2.2, which says an action
namespace must be explicitly enabled before it can ask, and that the default
set is empty. A plugin cannot enroll itself into your attention by being
installed.

**The WebAssembly rule.** Anything the marketplace distributes as a pack is a
WASI module. Native stdio packs remain fully supported for your own machine and
are never listed. The reason is pack protocol §5: a pack sees production
statements, and a public directory of native executables that see production
statements is an exfiltration channel with a storefront. A wasm pack has no
network, no filesystem and no clock unless the host hands them over, and the
host does not.

**The index** is a repository — `countersign-marketplace` — with one
`index.json` and a directory per plugin. Adding one is a pull request; CI
checks the manifest, downloads the tagged artifact, checks its hash,
instantiates it with no imports, and confirms `describe` claims the namespaces
the manifest says. **Your own plugin** starts as a local directory under
`packs/` and is on the Mac app's Plugins screen the moment it is there;
*Publish* validates it, writes the manifest, and opens the pull request. No
account, no registry service, no moderation queue that can go quiet — the
review is the pull request.

**What ships enabled by default: nothing.** `countersign-db` ships installed.
So does the file-delete gate the hook demonstrates, as an integration with one
proposed rule. Both are off until you turn them on, because that is the rule
for everyone else and the first-party packs do not get an exception.

**What ships as the first third-party-shaped entry:** `countersign-tf`, which
`NEXT_STEPS` §1.3 already picks as the best next pack — the same blast-radius
shape as DDL and a bigger audience.

### 4.8 The relay

Four additions to `web/`, none of which change the property that the relay
holds no key and its word for an approval is worth nothing.

- **Enclave enrollment.** The phone runs the ceremony on its own screen; the
  enrollment record and its proof travel to the daemon through the relay during
  pairing; the daemon verifies the proof against the record's own key
  (enrollment spec §2) and adds it to its roster. The relay stores the record
  so the rack can show it, and stores nothing it could sign with.
- **Push.** Device tokens per account. On `present`, a push carrying the
  request id, the environment label and the short digest — device-class spec
  §3.5 — and never the statement. Long-polling stays as the fallback and the
  desktop path.
- **End-to-end encryption to the phone.** `NEXT_STEPS` §2.2's outstanding
  item, and it stops being optional the moment the relay costs money: a paid
  relay should not be a custodian of anyone's queries. The phone holds a second
  enclave key for key agreement; the daemon encrypts `request_json` and
  `render` to it; the relay sees a digest and ciphertext. The digest check on
  the phone is unchanged, because it runs after decryption on the bytes.
- **Entitlement.** One key per account, set by a Stripe webhook, checked on
  `pair-code` and `device/present`. The dev relay behind `SIGNET_DEV_RELAY=1`
  never checks it, so self-hosting stays free and the tests stay honest.

The cloud-agent direction — an agent with no local daemon posting a request —
stays out of this. The daemon still starts every conversation, which is what
keeps the relay a plain HTTP target with no inbound anything.

### 4.9 Paying for it

**What is paid for:** the hosted relay — delivery, push, and custody-free
encrypted transit — on the account, once. **What is not:** the protocol, the
daemon, the verifier, the apps, the marketplace, and running your own relay.
All of it stays Apache 2.0, because the strategic goal in the README has not
changed: the standard is given away so that everyone implements it, and the
paid thing is convenience on top of it.

**Where it is sold:** on the web, through Stripe Checkout in `mode: payment`,
with a webhook that sets the entitlement. The apps are free downloads that
sign in.

**Apple.** The Mac app is outside the App Store, so no rule applies. The
iPhone app is a "multiplatform service" under App Review guideline 3.1.3(b):
it may unlock what you bought on the web, provided the same purchase is *also*
available as an in-app purchase. So the iOS app offers one non-consumable IAP
as a second path to the same entitlement. Two doors, one account. Do not link
to the web checkout from inside the iOS app until you have checked the current
rule for your storefront; it has moved twice and it will move again.

**One-time, honestly.** Per-account hosting cost on this design is a few Redis
keys, a few function invocations and a push per approval, which is why a
one-time price can hold. If it ever does not, that is a "second decade" problem
and not one to solve before the first customer.

### 4.10 The hardware plugs in

`--device=usb`, via `hidapi`, in `signetd`. The Mac app enumerates it, runs the
enrollment ceremony on the device's own screen, and adds a `signet` record to
the roster. From then on it is one more device in the fan-out, first to answer
wins, and it is the one that answers when you are at the desk. Anyone who wants
the stronger claim only sets `accept_classes = ["signet"]` on the verifiers
that matter. Nothing in the apps, the relay or the marketplace changes.

---

## 5. Build order

Each milestone is demoable on its own. The fourth is the first one that is a
product. Current state, and what the next one needs, is in
[`HANDOFF.md`](HANDOFF.md).

| # | Milestone | Depends on | Demo |
|---|---|---|---|
| M1 | Device classes in the spec and in `countersign-verify` + the TS SDK | — | A vector with an `enclave` record verifies; the same record is refused with `accept_classes = ["signet"]` |
| M2 | `signetd`: `enroll`, `--device=app`, multi-device, `[[pack]]`, `signetd pack …`, wasm host | M1 | `countersign-db` runs as wasm; `signetd pack disable countersign-db` makes `sql.*` refused without asking |
| M3 | `CountersignKit` | M1 | Passes `spec/vectors`; a Secure Enclave signature made on a Mac is verified by `cargo test` from a fixture |
| M4 | **The Mac app** | M2, M3 | Claude Code tries `rm demo/scratch.txt`; a menu bar sheet appears; the digest matches the terminal; Touch ID; the hook proceeds — with a signature a default verifier **accepts** |
| M5 | The iPhone app + relay: enrollment, APNs, encryption | M3, M4 | Away from the desk, a push arrives, Face ID, the terminal unblocks |
| M6 | Plugins screen, the marketplace index, `countersign-tf` | M2, M4 | Install a pack from the index, turn it on, see `terraform.apply` gated; publish a local pack as a PR |
| M7 | Stripe, entitlement, App Store submission | M5 | A new account pairs after paying, and not before |
| M8 | USB Signet | M4, hardware | One more row under Devices |

Rough sizes for one person with an agent, and nobody should be held to them:
M1 in days; M2, M3 and M6 about a week or two each; M4 and M5 two to three
weeks each; M7 a week plus whatever App Review takes. Roughly a quarter to
something a stranger can pay for.

---

## 6. Decisions taken here, and why — reverse any of them

- **Native SwiftUI, Apple first.** The three things the product depends on —
  the Secure Enclave, the biometric prompt, and eventually App Attest — are
  native APIs, and the code that touches the key should have no JavaScript
  bridge in it. One SwiftUI codebase covers both the Mac and the phone. React
  Native, Flutter and Tauri were considered and rejected for that reason, not
  for taste.
- **Mac first, Windows and Linux later.** The daemon already runs on the Mac
  and the enclave is there. Windows needs named pipes in `signetd::service`
  (`NEXT_STEPS` §4) before an app is possible; a TPM behind Windows Hello
  satisfies the `enclave` class when it comes.
- **The Mac app lives outside the App Store.** It spawns a daemon and will own
  a USB device. Notarization is enough.
- **Push carries no payload.** Apple's push service is one more custodian, and
  the spec now says so.
- **No approve action in a notification.** Made a spec non-goal so it cannot
  be re-litigated by the next person to open Xcode.
- **Marketplace packs are WebAssembly.** The alternative is a public directory
  of native binaries that see production SQL.
- **Plugin on/off is policy presentability.** Not a parallel switch — the one
  the spec already has.
- **The relay stays a plain HTTP target.** No inbound to the daemon, no
  websockets, no cloud-agent direction in v1.
- **Enclave approvals accepted by default.** The product decision, made once,
  in the spec, with the one-line way back.

---

## 7. Things only you can decide

- **Apple Developer Program**, the team, bundle identifiers, and the App Store
  name. "Signet" is heavily used on the store; the relay already calls a
  paired daemon a signet, so the app's public name and the device's may need
  to differ.
- **The price**, and whether the first customers are individuals or teams.
  Teams change the trust model from *direct* to *roster* (enrollment spec §7),
  which is real work the plan above does not include.
- **Whether the hosted relay ever holds a plaintext payload.** §4.8 puts
  encryption in M5. Putting it in M7 instead gets to a phone sooner and means
  the first paying users' statements sit in Redis for up to a minute.
- **Where the marketplace repository lives**, and under whose name.

---

## 8. What does not change

Wire spec §9, unchanged, plus the two the device-class spec adds:

batch approval · remember-for-N-minutes · pattern-based auto-approve · a
display field separate from the signed payload · any software-key path to a
production-valid signature · delegating approval to another agent ·
anti-automation heuristics · **approve from a notification** · **a class
asserted by the signer**.

The moment any of these ships, the product is a confirmation dialog with a push
token.
