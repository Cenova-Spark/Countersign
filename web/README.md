# signet.addisdb.com — remote countersignature

Approve a pending Countersign request from a phone, with the same payload, the
same digest and the same hold the device asks for.

**Everything the browser page signs is signed with a published test key.** A
default verifier refuses all of it. That is not a limitation to be lifted later
— it is what makes a browser-based approval path compatible with
[wire spec §9](../spec/countersign-v1.md), which refuses any software path to a
production-valid signature. The bypass is not switched off; it is
cryptographically incapable.

A **phone** is different, and the relay now knows the difference: it signs with
a non-extractable key in its secure enclave, registers that key to the account
(below), and is enrolled by the daemon that will act on it. The relay learns
the public key and nothing else.

---

## Why this is not the thing the README refuses

The root README says there is no mouse-driven approval path and there will not
be one. A thumb on a phone is one, so it is worth being exact about what changed
and what did not.

What did not change: **no software path produces a production-valid signature.**
This signs with a second published test key, derived like `MockDevice`'s and
different from it, so the two do not collide on `device_id`.

What this is: a **second device class**, weaker than a Signet and honest about
it. A Signet has a screen the requesting software does not control. A phone
runs a general-purpose OS, and the browser it renders in is not a device you
own in the same sense. The claim is correspondingly smaller.

A *real* approval from a phone happens with a non-extractable key in the
phone's secure enclave, unlocked per signature by a biometric check, enrolled as
its own device class with its weaker claim written into the spec. That spec
change has been made — class `enclave` in
[`spec/device-classes-v1.md`](../spec/device-classes-v1.md) — and the relay
carries such signatures without ever being the thing that decides they count.

What the protocol *does* carry over exactly:

| Spec | Here |
|---|---|
| §6 render from the bytes you sign | The screen renders from `request_json`, and the page refuses to display anything whose digest does not match those bytes |
| §6.1 the client shows the same digest | The same twelve characters appear in the terminal, on the daemon's log line, and on the phone |
| §6.2.3 arm delay | Runs from paint, not from arrival, and restarts on every new payload |
| §6.2.3 rest transition | A thumb already down when the payload renders must lift before it can approve |
| §6.3.2 acknowledge before approve | Required on **every** remote request, which is stricter than the spec — away from the desk there is no continuity to have noticed a break in |
| §6.3.3 a different organ | ACK is a button. The hold is the dial. Never the same control |
| §6.3.4 hold, scaled by severity | 300 ms to 5 s, and an accumulated hold is discarded the moment engagement lapses |
| §4 low-S | WebCrypto does not normalize `s`; `lib/p256.js` does, and the test checks 200 signatures rather than one |
| §4.1 monotonic counter | Allocated by the relay, verified by the daemon, refused if it does not advance |
| §9 no anti-automation heuristics | `dwell_ms` travels as telemetry. Nothing branches on it |

---

## The relay is untrusted, and that is load-bearing

It holds no key and can forge nothing. It can **drop** a request, and it can
**read** one — that second limit is honest rather than solved, and
[NEXT_STEPS §2.2](../NEXT_STEPS.md) is where end-to-end encrypting the payload
belongs.

What it cannot do is **change** a request, and the reason is worth stating
because it is the only thing standing between a hosted relay and a very good
phishing device: the request travels as raw JSON, the phone recomputes
`SHA-256(jcs(request))` from those bytes, and refuses to render anything whose
digest disagrees. A relay that swapped a `SELECT 1` for a `DROP TABLE` cannot
also move the digest the human is comparing against their terminal.

The daemon then verifies the signature itself before believing any of it —
against its own copy of the payload, its own idea of the key, and its own
highest-accepted counter. A daemon that took the relay's word for an approval
would have moved the trust decision into the one component the design says not
to trust.

---

## Phones, and what the relay learns about them

A phone **registers** its enclave public key on the account:

```
POST /api/phones     { device_id, public_key_hex, class: "enclave", name }
GET  /api/phones     → { phones: [{ device_id, public_key_hex, class, name, … }] }
DELETE /api/phones   { device_id }

GET  /api/device/phones   the same list, for the paired daemon (bearer token)
```

The relay checks what it can check from where it stands — the key is 65-byte
SEC1 uncompressed and on P-256, `device_id` is its SHA-256 (wire spec §4.2),
the class is `enclave` and nothing else, and the key is not already on another
account (one device, one human — enrollment spec §6). It stores the public key,
a name, and later an APNs token. Never a private half.

A signature posted to `/api/approve` now says what signed it:

```
signature: { device_id, counter, device_unix_ms, signature, dwell_ms?,
             public_key_hex?, class: "enclave" | "test" }
```

For `enclave`, the relay confirms the `device_id` is a phone on **this**
account under **that** key, and refuses otherwise. For `test` — the browser
page — it confirms nothing, and stamps the class on so the daemon always sees
one. Both travel to the daemon as claims.

**Registering is not enrolling.** The daemon believes none of this on the
relay's word. For the enrollment ceremony it verifies against the key the
signature carries, because the ceremony is how a key becomes known; it then
reads `/api/device/phones` only to *find* that key and write the record. For
every approval after that it verifies against **its own roster** — `signetd
enroll` with the phone held on the ceremony — and a phone that is not enrolled,
or has been revoked, is refused however good its signature is. A test key that calls
itself `enclave`, or an unknown key that calls itself `test`, is refused before
its signature is even read. Device-class spec §6, "pairing is not enrolling";
the daemon side is `crates/signetd/src/relay.rs`.

Forgetting a phone here stops the relay accepting its approvals. It does not
revoke it — that is the daemon's roster, and the roster is what an audit of
last year reads.

---

## Run it on one machine

No Upstash, no WorkOS, no account. Three terminals.

```bash
cd web && npm install
```

**Terminal 1 — the relay:**

```bash
npm run dev:api
```

State lives in process memory and there is no sign-in step. Both are behind
`SIGNET_DEV_RELAY=1`, and the relay refuses to start in that mode on a
production deployment.

**Terminal 2 — the interface:**

```bash
npm run dev
```

**Terminal 3 — pair the daemon and start it:**

```bash
cargo build --workspace
open http://localhost:5180/pair          # read the code off the screen
./target/debug/signetd pair --relay=http://127.0.0.1:3000 --code=ABCD-EFGH
./target/debug/signetd run --device=relay --config=demo/countersign.toml
```

Then ask it for something. The demo config gates deleting a file:

```bash
touch demo/scratch.txt
echo '{"tool_name":"Bash","tool_input":{"command":"rm demo/scratch.txt"},"cwd":"'$PWD'","session_id":"demo"}' \
  | ./target/debug/countersign-hook --accept-test-keys --deadline-ms 120000
```

The terminal blocks. Open <http://localhost:5180/signets> on a phone on the same
network, read the payload, acknowledge it, hold. The terminal unblocks, and the
digest it prints is the digest you were shown.

To drive the same loop without a human — for tests, never as a feature — there
is `node scripts/approve-once.mjs`.

---

## Deploy it

A Vercel project pointed at `web/`, with the domain attached.

```
Framework      Vite
Build          npm run build
Output         dist
Root directory web
```

### Environment

| Variable | Where from |
|---|---|
| `WORKOS_API_KEY` | WorkOS dashboard → API keys |
| `WORKOS_CLIENT_ID` | WorkOS dashboard → the environment's client id |
| `WORKOS_COOKIE_PASSWORD` | 32+ random characters — `openssl rand -base64 32` |
| `UPSTASH_REDIS_REST_URL` | Upstash → the database's REST URL |
| `UPSTASH_REDIS_REST_TOKEN` | Upstash → the database's REST token |
| `SIGNET_ORIGIN` | `https://signet.addisdb.com` (optional; otherwise inferred) |

Vercel's own Upstash integration sets `KV_REST_API_URL` / `KV_REST_API_TOKEN`,
and both spellings are accepted.

In WorkOS, add the redirect URI:

```
https://signet.addisdb.com/api/auth/callback
```

Start in the **Staging** environment and move to Production when the flow is
right — they have different client ids, so the variable has to change with them.

Then point a daemon at it:

```bash
signetd pair --code ABCD-EFGH        # defaults to https://signet.addisdb.com
signetd run --device=relay
```

---

## Layout

```
api/            the relay. Vercel Node functions
  _lib/         store, session, validation, phone keys — shared, never routed
  auth/         WorkOS AuthKit
  device/       what signetd talks to: pair, present, await, phones
  phones.js     a phone registers its enclave key; approve.js checks against it
src/
  assets/       GENERATED from the form study — see scripts/build-chassis.mjs
  components/   SignetDevice (the instrument), HoldControl (the actuation)
  lib/          dial geometry · the hold rules · JCS · P-256 · signing
  views/        landing · the rack · one request · pairing
scripts/
  build-chassis.mjs      derive the artwork from public/signet-form-study.svg
  gen-remote-vector.mjs  a browser signature for Rust to verify
  dev-api.mjs            serve api/ locally, same handler signature
  approve-once.mjs       a headless phone, for tests only
test/           the crypto against spec/vectors/, and the gesture rules
```

### The artwork is derived, never hand-edited

`public/signet-form-study.svg` is the drawing of record.
`scripts/build-chassis.mjs` fits the dial's ellipse to the study's own knurl
ribs (RMS ~6e-5 — it recovers the original parameters rather than approximating
them), samples the key light off the ribs' measured colours, and emits the
chassis with the moving parts removed.

Only three things move: the 18 visible knurl ribs, the amber index mark, and
the screen. The dial's wall is a cylinder and therefore rotationally symmetric,
so it looks identical at every angle.

Re-run `npm run chassis` after changing the study.

## Tests

```bash
npm test
```

The crypto is checked against `spec/vectors/` — not against the Rust and not
against the TypeScript SDK, because two implementations agreeing with each other
and both being wrong is the failure this is meant to catch.

The phone registration and approval handlers run for real against the
in-memory dev store (`test/phones.test.js`), the same way `npm run dev:api`
serves them.

The gesture rules run on a fake clock, including the one that is easy to miss:
a backgrounded tab must **discard** an accumulated hold, because `now -
holdStartedAt` would otherwise come back from a thirty-second sleep already
satisfied and approve on wake.

`cargo test -p signetd relay` closes the loop from the other side: a signature
this browser code produced, verified by the daemon that would act on it.
