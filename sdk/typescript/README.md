# @countersign/sdk

Verify Countersign approvals, and request them. **Zero dependencies.**

Everything is built on `node:crypto`, `node:net` and `node:fs`. A library meant
to be embedded in security infrastructure should not drag a tree in with it —
and the people putting this in a GitHub Action have to accept every dependency
it carries.

Requires **Node 22.6+**. There is no build step: Node strips the types.

```bash
npm test    # runs the spec conformance vectors, no install needed
```

## Two halves, and most consumers want one

**Verification** — no daemon, no USB, no network. This is the half that goes in
a GitHub Action, a Vault plugin, or a service checking an approval against a
registered public key.

```ts
import {
  Registry, defaultPolicy, verifyForExecution, FileCounters, fingerprintUri,
} from "@countersign/sdk";

const registry = new Registry().enrol(devicePublicKey, {
  operator: { subject: "alice@example.com" },
});

const verified = verifyForExecution(
  envelope,
  { statement: sql, uriFingerprint: fingerprintUri(process.env.DATABASE_URL!) },
  registry,
  defaultPolicy(),
  new FileCounters("./state/counters.json"),
);

console.log("approved by", verified.operators); // ["alice@example.com"]
```

**Asking** — what a Node agent or a VS Code extension uses to request one.

```ts
import { Client } from "@countersign/sdk";

const client = new Client();                       // one per session, see below
const response = await client.requestApproval({
  action: "sql.execute",
  targetUri: process.env.DATABASE_URL,
  statement: "DELETE FROM orders",
});

if (response.decision !== "approved") {
  throw new Error(`not approved: ${response.explanation}`);
}
// Show response.digest_short to the user. It must match the device.
```

## Three things that are easy to get wrong

**Hold one `Client` per session.** The daemon keys its requester-continuity
check on the connection, because that is the only thing about a caller it can
verify. A client that reconnects per call looks like a new requester every time
and makes the operator acknowledge a change on every single approval — the
fatigue that check exists to avoid.

**Show `digest_short` to the user.** It is the client half of content binding
(spec §6.1). The device displays the same twelve characters, and the match is
how a human notices a disagreement between the two screens. Without it, content
binding is invisible to the person relying on it.

**A resolved promise is not a yes.** `requestApproval` resolves on *every*
decision. Check `response.decision`; a refusal is a normal answer, not an
exception.

## `verifyForExecution` versus `verifyBundle`

`verifyBundle` checks the cryptography. `verifyForExecution` additionally checks
that the approval covers the statement and target you are about to act on.

Use the second one. Without those bindings a verifier confirms only that *some*
approval exists, which an agent holding one can reuse for everything after it.

The statement comparison is byte for byte. Do not normalize before calling —
that is the whole vulnerability: `DELETE FROM t WHERE id=1` approved,
`DELETE FROM t` run.

## Conformance

`test/vectors.test.ts` runs the committed vectors from
[`spec/vectors/`](../../spec/vectors) — the same files the Rust implementation
is checked against. If the two ports ever disagree about a canonical form, a
digest, or a signature, one of them fails.

That is what makes the spec a spec rather than a description of one codebase,
and it is the reason to read `spec/countersign-v1.md` rather than this code if
you are writing a third port.

## Notes for porters

Two things are easier in JavaScript than in Rust and one is harder.

- **UTF-16 key ordering is free.** JS strings are UTF-16, so the default
  `sort()` is already RFC 8785's comparison. In Rust it has to be written out,
  because `str: Ord` compares UTF-8 bytes and the two disagree above the BMP.
- **The integer restriction has native vocabulary** — `Number.isInteger` and
  `Number.MAX_SAFE_INTEGER` are exactly the profile's bounds.
- **Duplicate keys need a separate scan.** `JSON.parse` keeps the last one and
  says nothing, so `findDuplicateKey` walks the source text. RFC 8785 requires
  rejection, and the disagreement is attacker-chosen.

And one that is the same everywhere and bites: **most ECDSA libraries do not
normalize `s`.** Node's `sign` does not. A signer that forgets emits a high-S
signature roughly half the time, so it appears to work and then intermittently
fails. Test a signer against *many* signatures — a single low-S result proves
nothing. See `spec/countersign-v1.md` §4.
