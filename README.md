# Countersign

**An agent can satisfy every software confirmation it encounters. This is the
one it can't — and here is the signed record that a human was there.**

Countersign is a protocol for requesting a *physical* human authorization for a
consequential action, and receiving back a cryptographic signature proving
someone actuated an enrolled key while a specific payload was displayed on a
device the requesting software does not control.

**Signet** is the hardware that implements it. **Countersign** is the protocol.
The protocol is the product; the device is one implementation of it.

Apache 2.0, all of it. The strategic goal is that DBeaver, DataGrip and everyone
else implement Countersign for free — copyleft would work against that. Sell the
device; give away the standard. WebAuthn is the model: the token was never the
moat, universal acceptance was.

---

## What a countersignature actually proves

> Proof that a specific enrolled key was physically actuated while a specific
> payload was displayed on a device the requesting software does not control.

It does **not** prove a human did it, and the docs here never claim otherwise.

**Content binding** is the genuinely new part. A security key proves actuation
but has no screen, so you never learn what you touched to approve. Signet shows
you, and it renders from the bytes it signs — never from a separate display
field, which is blind signing and is the failure mode hardware wallets spent a
decade learning to avoid.

### This is not a CAPTCHA replacement

Cloudflare ran that experiment in 2021 with Cryptographic Attestation of
Personhood, and within weeks someone had built a working click farm out of cheap
security keys and an Arduino. A dial is *easier* to automate than a capacitive
pad — it takes a servo, not a drinking bird.

The structural reasons matter more than the automation one: CAPTCHA's users are
anonymous and unenrolled, and Countersign's entire value comes from enrollment.
CAPTCHA is adversarial at scale; Countersign's threat model is a *cooperating*
user protecting themselves from their own tools. Opposite adversary.

Step-up authentication inside an already-authenticated session is a real and
adjacent use case. Anti-bot is not.

---

## Architecture

```
┌─ Layer 4 ── domain packs (optional) ────────────────────────────┐
│  countersign-db: SQL classification, blast radius               │
│  countersign-tf, countersign-k8s, …: yours to write             │
└──────────────────────────────┬──────────────────────────────────┘
┌─ Layer 3 ── transports ──────┴──────────────────────────────────┐
│  MCP server  │  local HTTP/WS  │  CLI  │  SDKs  │  wire proxy   │
└──────────────────────────────┬──────────────────────────────────┘
┌─ Layer 2 ── signetd (the daemon) ───────────────────────────────┐
│  owns the USB connection · policy engine · environment          │
│  classification · request queue · audit log                     │
└──────────────────────────────┬──────────────────────────────────┘
┌─ Layer 1 ── device transport ───────────────────────────────────┐
│  USB HID vendor page (Countersign) + HID keyboard (buttons)     │
└──────────────────────────────┬──────────────────────────────────┘
┌─ Layer 0 ── Signet firmware ────────────────────────────────────┐
│  renders payload · reads dial angle · secure element signs      │
└─────────────────────────────────────────────────────────────────┘
```

The daemon knows about "approval requests with a payload". It does not know what
SQL is. All database intelligence lives in an optional pack, which is why
`action` is a namespaced verb (`sql.ddl`, `terraform.apply`, `npm.publish`,
`email.send`) and `statement` is an opaque string to everything in Layer 2.

---

## What is here today

| Crate | What it does |
|---|---|
| [`countersign-verify`](crates/countersign-verify) | Canonicalization, digests, signature verification, replay defence. **No daemon, no USB, no network.** |
| [`countersign-sql`](crates/countersign-sql) | Dialect-tolerant SQL scanning and statement classification. Knows nothing about Countersign. |
| [`countersign-pack`](crates/countersign-pack) | The domain-pack plugin interface: protocol types, a stdio harness for pack authors, and a host that enforces the pack security rules. |
| [`countersign-db`](crates/countersign-db) | The first domain pack. SQL → severity, blast radius, and what the device should show. |
| [`countersign-audit`](crates/countersign-audit) | Hash-chained audit trails that export without disclosing a single query. |
| [`signetd`](crates/signetd) | **The daemon.** Owns the device, classifies environments, enforces policy, and writes the trail — plus the stdio MCP bridge Claude Code spawns. |
| [`countersign-proxy`](crates/countersign-proxy) | **Posture C.** A PostgreSQL wire proxy that refuses statements nobody countersigned. No agent integration at all. |
| [`countersign-hook`](crates/countersign-hook) | A Claude Code `PreToolUse` gate. Deleting a file takes a countersignature; creating one takes nothing. How to try the protocol without a database. |
| [`sdk/typescript`](sdk/typescript) | Verify approvals and request them, from Node. Zero dependencies, no build step, checked against the same vectors as Rust. |
| [`web`](web) | **The relay, and a Signet you are not sitting in front of.** Approve a pending request from a phone, with the same payload, the same digest and the same hold. The browser page signs with a published test key — see below; a phone registers its enclave key and is enrolled by the daemon. |

Specs live in [`spec/`](spec/), with machine-readable test vectors in
[`spec/vectors/`](spec/vectors/) — including a **published** test keypair whose
private half is in this repository on purpose (see below).

```bash
cargo test --workspace
```

Try it end to end, with no hardware, in two terminals — see
[`crates/signetd/README.md`](crates/signetd/README.md).

### What is not here yet

Client integrations and the firmware. The relay now exists in the direction that
serves a human away from their desk ([`web`](web)); serving a *cloud agent* with
no local presence is the other half and is not built. Everything still
outstanding — including what the offline build constrained — is in
[NEXT_STEPS.md](NEXT_STEPS.md).

Some of that is blocked by this workspace having been built offline; those items
and the versions to revisit are in [`BLOCKED.md`](BLOCKED.md).

---

## Identity, enrollment, and the audit trail

**A Signet belongs to one person.** The signature proves a device was actuated;
an enrollment record maps that device to a human. Share a device and the
signature proves only "someone with access to that desk", and the question the
product exists to answer stops having an answer. Devices are cheap — issue one
per person, the way security keys are issued.

One consequence that is easy to get wrong: a threshold of N signatures means N
*devices*. Alice with a primary and a spare satisfies "two signatures" alone,
which is exactly the control a dual-control rule existed to prevent. Genuine
dual control counts distinct people, and refuses a device whose owner the
verifier does not know.

**Enrollment is itself an approval.** A public key is not a secret, so enrolling
a device means asking it to countersign `Enroll this device as an approver for
alice@example.com` — rendered on its own screen, turned by a human. One signing
construction in the whole protocol, and no second chance to drift into blind
signing. Verifiers learn keys from a **roster** signed by an enrollment
authority: self-authenticating, so the distribution channel is untrusted, with a
monotonic serial because a revocation you can undo by replaying yesterday's file
is not a revocation.

**The audit trail can be shared without disclosing any query.** The hash chain
holds digests, identifiers and decisions — never a statement. Statements live in
detachable payloads bound to the chain by digest. So a digests-only export still
verifies every link *and every signature*, and still names the human behind each
approval, while revealing nothing about what was run. Redaction can never break
it, because the sensitive material was never in the shared half.

Chains detect insertion, reordering and edits. They do not detect truncation —
a shorter chain is a valid chain — which is what checkpoints are for, and a
daemon-signed checkpoint defends against everyone except the machine holding the
daemon key. That limit is documented rather than glossed.

---

## Enforcement postures — be honest about which one you have

A signature is worthless if the party that requested it is also the party that
decides whether to honour it.

**A. Advisory.** The agent asks, gets a signature, and chooses to proceed.
Protects against mistakes and runaway loops. Does not protect against a
compromised or sufficiently motivated agent. Zero infrastructure. Start here.

**B. Client-enforced.** The client verifies at its execution chokepoint before
dispatching to the driver. Works if the agent is a *separate process* from the
client — and fails if the agent runs in-process with the ability to call the
driver directly.

**C. Proxy-enforced.** A proxy in front of the database refuses any statement
without a valid, fresh, matching countersignature. The agent cannot reach the
resource except through it. **This is the only posture where the security claim
fully holds.**

`countersign-verify` is deliberately free of daemon and USB dependencies so that
C is buildable from day one, from a different host, by someone who has never
touched this codebase.

### Why the proxy, and not more integrations

You cannot enumerate the agents — new ones ship monthly. You *can* enumerate the
databases. Every agent eventually speaks Postgres, MySQL, MongoDB or one of about
ten wire protocols to a server, so a proxy catches Cursor, DBeaver's AI, an
unattended cron job, a cloud agent, and every tool that does not exist yet, with
zero integration work by any of them.

**Integrations improve the quality of the prompt. The proxy provides the
coverage.** Do not confuse the two.

---

## Testing without building a bypass

**No software path produces a production-valid signature.** That is the rule, it
has not moved, and §9 states it as a non-goal so it is not re-litigated later by
whoever has the most revenue attached to the request.

The mock device signs with a **published** test keypair whose private half is in
[`spec/vectors/test-key.json`](spec/vectors/test-key.json). Verifiers reject test-key
signatures unless explicitly configured to accept them.

That is the whole safety mechanism, and it is worth stating plainly: a mock
accidentally left enabled in a real deployment **fails loudly at verification
rather than silently passing.** The bypass is not "disabled by a flag" — it is
cryptographically incapable of producing a production-valid approval.

### The remote path, and why it is not the exception

[`web`](web) lets a phone answer a request when nobody is at the desk, and a
thumb on a phone is plainly a software confirmation. So the distinction has to
be exact rather than convenient.

It signs with a **second published test key**, derived like the mock's and
different from it so the two do not collide on `device_id`. Everything it
produces is refused by a default verifier, by the same mechanism and for the
same reason. The rule at the top of this section is intact.

What it is, is a **second device class, weaker than a Signet and honest about
it.** A Signet has a screen the requesting software does not control; a phone
runs a general-purpose OS. The claim is correspondingly smaller, and no document
here pretends otherwise.

If a phone is ever to make a real approval it will be with a non-extractable key
in a secure enclave, unlocked per signature, enrolled as its own device class
with its weaker claim written into the spec. **That is a spec change, not a code
change**, and nothing in `web/` presumes it.

Everything else carries over exactly: the arm delay measured from paint, the
rest transition, the severity-scaled hold, the acknowledgement on a different
organ from the dial, low-S normalization, the monotonic counter, and rendering
from the bytes that get signed. That last one does double duty off-host — the
phone recomputes the digest from the request's own bytes and refuses to render
anything that disagrees, which is what stops an untrusted relay from turning a
`SELECT 1` into a `DROP TABLE`.

---

## Non-goals, refused by design

Written down so they are not re-litigated later by whoever has the most revenue
attached to the request.

- **Batch approval.** One signature, one statement. No "approve these 40".
- **Remember for N minutes.** A time window is a software confirmation with
  extra steps.
- **Auto-approve on a pattern match.** If a regex can approve it, the agent can
  construct something that matches the regex.
- **A display field separate from the signed payload.** Blind signing.
- **A software approval path producing production-valid signatures.**
- **Approval delegated to another agent.** The human is the point.
- **Anti-automation heuristics.** `dwell_ms` is UX telemetry. A servo produces
  any dwell time you ask it for; a verifier that branches on it has
  misunderstood the primitive.

The moment any of these ships, the product is a confirmation dialog with a USB
cable.

---

## Build order

1. ~~Spec + `countersign-verify` + test vectors~~ ✅
2. ~~Pack interface + `countersign-db`~~ ✅
3. ~~Enrollment, revocation, and the audit trail~~ ✅
4. ~~`signetd` with `--device=mock` — policy, environment classification, the
   trail on disk~~ ✅
5. ~~MCP server — the first demoable milestone, and it needs no hardware~~ ✅
6. ~~SSH socket forwarding — cheap, and the difference between "works on my
   laptop" and "works how engineers actually operate"~~ ✅
7. ~~Reference Postgres proxy — the coverage story, and the first posture-C artifact~~ ✅
8. ~~TS SDK~~ ✅ · local HTTP/WS
9. Client integrations at whichever execution chokepoint each one has
10. ~~Relay — a Signet you are not sitting in front of~~ ✅ · cloud agents next
11. Swap mock for hardware

Steps 8–10 are entirely independent of hardware progress.

---

## Writing a pack

The flywheel: `countersign-db` ships here, and `countersign-tf`,
`countersign-k8s` and `countersign-npm` are yours to write. A pack is any
executable speaking a two-method JSON-RPC protocol on stdio — see
[`spec/pack-protocol-v1.md`](spec/pack-protocol-v1.md). Rust authors get a trait
and a harness from `countersign-pack`; everyone else implements the protocol
directly, which is deliberately small enough to do in an afternoon.
`signetd pack new <name>` writes a crate to start from, and
`signetd pack info` shows what any pack claims before it is installed.

Three rules a host enforces, so that running third-party code in front of an
approval prompt is acceptable:

1. A pack may **raise** severity and never lower it.
2. A pack may not write the environment label or the digest.
3. Failure is closed — a dead classifier means `critical`, not "probably fine".

## Licence

Apache 2.0. See [LICENCE](LICENSE) and [NOTICE](NOTICE).
