# Countersign audit trail v1

Status: **draft**. Normative for `countersign-audit`.
Licence: Apache-2.0.

---

## 1. The tension, and the shape that resolves it

A compliance owner wants *who approved what, when, and can you prove it* —
ideally somewhere central, retained, and queryable.

The statements that would answer it are production SQL: table names and literal
values, which means customer data. Syncing that to a server is exactly what a
regulated shop cannot do. Keeping it only on one laptop is exactly what an
auditor will not accept.

The resolution is structural, not a policy toggle:

- The **chain** (§2) holds digests, identifiers and decisions. **No statement
  ever enters it.**
- The **payloads** (§3) hold the statements, bound to the chain by
  `request_digest`, and detach cleanly.

A digests-only export is therefore *fully verifiable*: every link checks, every
signature verifies, and every approval names the human who gave it — while
revealing nothing about what was run.

**This is why redaction cannot break anything.** There is nothing to redact:
the sensitive material was never in the part that gets shared. A design that put
statements in the chain and stripped them later would produce an export whose
hashes no longer computed, which is how "we redact before sync" becomes "we
stopped verifying."

---

## 2. The chain

```jsonc
{
  "seq": 41,
  "prev": "<hash of entry 40, or 64 zeros for the first>",
  "at_unix_ms": 1755859200500,
  "action": "sql.ddl",
  "target_kind": "database",
  "target_fingerprint": "860e…",
  "environment_label": "prod-us-east-1",
  "request_digest": "df47…",
  "decision": "approved",
  "severity": "critical",
  "signatures": [ /* as in the approval bundle */ ]
}
```

`entry_hash = SHA-256(jcs(entry))`, lowercase hex. `prev` is the previous
entry's hash; the first entry's `prev` is 64 zeros.

`environment_label` is recorded because "was this production?" is the first
question anyone asks of an audit trail — and because the requester never got to
claim it (wire spec §2.1), so it is worth something.

**Nothing in an entry may leak statement contents.** An implementation adding a
field here MUST check it against that rule. `target_fingerprint` is a hash and
is fine; a `table_name` field would not be.

### 2.1 What the chain detects, and what it does not

Chain verification detects **insertion, reordering, and edits to any recorded
field** — downgrading a `prod` label to `staging` after the fact breaks every
link after it.

It does **not** detect truncation of the tail. Dropping the last twenty entries
leaves a shorter chain that verifies perfectly. §5 is the answer to that, and it
is stated here rather than buried so nobody ships believing otherwise.

---

## 3. Payloads

```jsonc
{ "seq": 41, "request_json": "{…the full request, statement and all…}" }
```

A payload is valid for an entry when
`SHA-256(jcs(payload.request_json)) == entry.request_digest`.

That check is what makes a detached payload trustworthy later. Someone who holds
a statement can prove it is the statement that was approved; someone who does
not holds a digest that reveals nothing. Handing over a query and *claiming* it
is what was approved proves nothing on its own — the digest settles it.

---

## 4. Disclosure levels

| Level | Contents | Use |
|---|---|---|
| `digests_only` | Chain, no payloads | **The one that should sync.** Compliance systems, relays, backups, off-site retention. |
| `with_statements` | Chain plus payloads | Local operations, incident review, an explicit disclosure to an auditor who is entitled to the query text. |

An export MUST declare its level, and a `digests_only` export carrying payloads
MUST be rejected — a privacy incident dressed as a safe one is worse than an
obvious one.

Exports MAY cover a contiguous range rather than the whole log; a year of
approvals is not one attachment. A partial export MUST make that visible: its
first entry's `prev` will not be the genesis value, and a receiver MUST NOT
report a range as complete history.

### 4.1 What a digests-only export tells an auditor

Everything except the query:

- that an approval happened, at a given time, in sequence
- which action class, on which target fingerprint, in which environment
- what the decision was, and what severity the classifier assigned
- **which enrolled device signed it, and therefore which human** — verifiable
  against a roster, because the signature covers the digest and the digest is
  present

That last point is the one worth internalising. Signature verification needs the
`request_digest` and nothing else, so it works unchanged on an export that
contains no statements at all.

---

## 5. Checkpoints

```jsonc
{
  "seq": 41, "head": "<entry 41's hash>", "entries": 42,
  "at_unix_ms": 1755859300000,
  "signer_id": "<hex SHA-256 of the signer's public key>",
  "signature": "<base64url unpadded, r||s>"
}
```

**Signing payload:** `"countersign-audit-v1" || 0x00 || head_bytes ||
u64_be(seq) || u64_be(entries) || u64_be(at_unix_ms)`. A distinct domain
separator from approvals and rosters, so no signature is replayable across them.

A log with fewer entries than a checkpoint recorded, or a different head at the
same seq, has lost or altered history.

**Low-S applies to a checkpoint signature** exactly as it does to approvals,
enrollment proofs and rosters (wire spec §4). Signers normalize; verifiers
reject.

### 5.1 Be honest about what this buys

A checkpoint signed by the daemon's own software key defends against anyone who
edits the log **later** — a log consumer, a sync server, a backup, an attacker
holding the file but not the key.

It does **not** defend against whoever controls the daemon at the moment of
writing. They hold the key; they can sign whatever history they like.

Getting that boundary stated matters more than the feature. A buyer told "this
log is tamper-proof" will eventually discover it means "tamper-evident against
everyone except the machine that wrote it", and it is far better for them to
read it here first.

The stronger version costs a dial turn: sign the head with an **enrolled
Signet** rather than the daemon key, at a low frequency — hourly, or at shift
boundaries. Then even the machine that wrote the log cannot rewrite it without a
human present. Implementations SHOULD offer this and MUST NOT do it per entry;
an approval prompt for every log line is how the log gets turned off.

---

## 6. Sync

The default is **local**. A daemon MUST work with no sync configured, and MUST
NOT make sync a condition of approving anything.

Where sync is configured:

- The **chain** syncs. Payloads MUST NOT be synced unless the operator
  explicitly opts in, per destination.
- The destination is **untrusted by design**. Entries are signed and chained, so
  tampering is detectable by anyone holding a checkpoint; the destination holds
  no key and can forge nothing.
- A sync destination MUST NOT be able to request approvals, alter policy, or
  push a roster. It is a sink.

This is the same posture the cloud-agent relay takes, and for the same reason:
the moment a hosted component becomes a custodian of customer queries, it
acquires a class of risk and obligation that a signature-shaped service does
not.

---

## 7. Retention and rotation

A rotated log MAY begin at a non-zero `seq`, so `entries` is carried in a
checkpoint alongside `seq`.

Payloads and entries have **different natural retention**. Statements are the
sensitive half and often want the shorter life; the chain is small, harmless,
and worth keeping for as long as anyone might ask. Implementations SHOULD allow
expiring payloads while retaining the chain — after which the entry still proves
an approval happened and who gave it, and nobody can reconstruct the query.

---

## 8. Verifying an export

1. Verify the chain links and sequence contiguity.
2. Note whether it is complete history or a range, and report which.
3. Reject a `digests_only` export carrying payloads.
4. For each payload present, check it against its entry's digest.
5. If a checkpoint is present, verify its signature and check the log against it.
6. For each entry, verify its signatures against a roster, using
   **as-of-the-entry** acceptance (enrollment spec §5) rather than
   acceptable-now, or a since-revoked device will void history it legitimately
   authorized.

Step 6 needs a registry and a signature backend, which is why it is the caller's
to run rather than part of export verification.

---

## 9. Non-goals

- **A log the daemon cannot append to.** Append-only is enforced by the chain
  and by checkpoints, not by pretending the writer is not the writer.
- **Storing decrypted statements off-box by default.** §6.
- **Making `dwell_ms` an audit signal.** It is UX telemetry and a servo produces
  any value you like. It MAY be recorded; nothing may conclude from it.
- **Deleting an entry.** Retention expires payloads, never entries. An entry
  that vanishes is indistinguishable from tampering, which defeats the point.
