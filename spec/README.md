# Countersign specifications

| Document | What it fixes |
|---|---|
| [`countersign-v1.md`](countersign-v1.md) | The wire format: request, canonicalization, digest, signature, response bundle, display rules, verification, non-goals. |
| [`pack-protocol-v1.md`](pack-protocol-v1.md) | The domain-pack plugin interface, and the rules a host enforces on packs. |
| [`enrollment-v1.md`](enrollment-v1.md) | The trust root: enrollment ceremony, records, rosters, revocation, and why one device belongs to one person. |
| [`audit-v1.md`](audit-v1.md) | The audit trail: hash chain, detachable statements, disclosure levels, checkpoints, and sync. |
| [`vectors/`](vectors/) | Machine-readable conformance vectors. |

Both are **drafts**, normative for the crates in this repository, and expected to
move until a non-Rust implementation exists — an implementer's first port is
what usually finds the ambiguity.

## Vectors

| File | Contents |
|---|---|
| `canonicalization.json` | JCS accept and reject cases, each with its canonical form and SHA-256. |
| `approval.json` | A complete signed approval envelope, plus the exact signing payload in hex. |
| `enrollment.json` | A countersigned enrollment proof and a roster signed by the published test authority. |
| `test-key.json` | The published test keypair. |

These are the contract; the Rust crates are one implementation of it. A port to
Go or TypeScript should be checked against these files rather than against the
Rust code — `crates/countersign-verify/tests/vectors.rs` is a worked example of
what that check looks like.

Regenerate after any deliberate format change:

```
cargo run -p countersign-verify --example gen-vectors
```

Everything is deterministic — the test key is derived from a published string
and ECDSA signing uses RFC 6979 nonces — so a diff here always means a behaviour
change and never noise.

## The test key is public on purpose

`test-key.json` contains a **private key**. That is deliberate and it is the
mechanism that makes a software mock safe to ship.

Verifiers reject signatures from a known test key unless explicitly configured
otherwise, so there is no code path where a software approval produces a
production-valid signature. A mock left enabled by accident fails loudly at
verification instead of silently passing.

Never enrol this key as a production device. Nothing signed by it means anything.
