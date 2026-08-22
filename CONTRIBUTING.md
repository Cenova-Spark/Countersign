# Contributing

## The spec is the artifact

`crates/` is one implementation of `spec/`. When they disagree, that is a bug in
at least one of them and possibly both — say which you think it is.

A change to the wire format or the pack protocol needs, in the same pull request:

1. the spec text,
2. regenerated vectors (`cargo run -p countersign-verify --example gen-vectors`),
3. the implementation,
4. a test that would have failed before.

## What review will push back on

**Anything on the non-goals list.** Batch approval, "remember for N minutes",
pattern-based auto-approve, a display field separate from the signed payload, a
software path to a production-valid signature, delegating approval to another
agent. These are in `spec/countersign-v1.md` §9 with the reasoning attached.
They are not open questions, and a pull request implementing one will be closed
with a link rather than a debate.

**Treating `dwell_ms` as evidence.** It is UX telemetry. A servo produces any
dwell time you ask it for. Any code that branches on it is wrong.

**New dependencies in `countersign-verify`.** That crate is embedded in wire
proxies, CI runners and Vault plugins, and ported to other languages. Every
dependency it carries is one those people have to accept. Hand-rolling forty
lines of hex is the right trade there and the wrong trade almost anywhere else.

**Normalizing before comparing a statement.** Verification compares statement
text byte-for-byte. Anything that trims, lowercases or collapses whitespace
first is the vulnerability, not a convenience: approve
`DELETE FROM t WHERE id=1`, run `DELETE FROM t`.

**Making a pack authoritative.** Packs classify; policy decides. A pack's answer
can raise the host's floor and can never lower it, and a pack can never write the
environment label or the digest.

**Putting a statement in the audit chain.** `AuditEntry` holds digests,
identifiers and decisions — never query text. That is the single property that
makes a digests-only export both shareable and verifiable, and it is why
redaction cannot break anything: the sensitive half was never in the shared
half. A new field on an entry has to be checked against that rule.

**Dropping the roster serial check.** A revocation you can undo by replaying
yesterday's signed roster is not a revocation, and every signature on that old
file still verifies. Same shape as the approval counter, same reason.

**Conflating "may this device act now" with "was it trusted when it signed".**
Revoking a lost device must stop it immediately and must not erase the approvals
its owner legitimately gave. `Acceptance::Now` and `Acceptance::AsOf` exist for
that, and collapsing them costs one of the two.

## Style

Comments explain *why*, especially where the code looks like it could be
simpler. Much of this codebase is deliberately more careful than it appears —
reading SQL under two backslash dialects, sorting JSON keys by UTF-16 code unit,
refusing to record a counter until verification has fully passed. Each of those
has a test named after the thing it prevents. Add yours the same way.

Tests are named as sentences describing the property, not the function under
test: `an_approval_cannot_be_reused_for_a_different_statement`, not `test_verify_2`.

## Before opening a pull request

```
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

## Provenance

`countersign-sql` originates in AddisDB's `core/src/sql_text.rs` and
`core/src/safety.rs`, relicensed under Apache 2.0 by their copyright holder. If
you change classification behaviour there, be aware a read-only connection gate
depends on the same answers — a classifier that disagrees with the gate in front
of it waves through exactly the statement the gate would have blocked.
