# Countersign — notes for Claude Code sessions

A physical human-authorization protocol (Countersign), its daemon (`signetd`),
domain packs, a Postgres proxy, a Claude Code hook, a phone relay (`web/`), a
TypeScript SDK, a Swift kit, and a Mac app. Apache-2.0. Specs in `spec/` are
normative and lead the code.

Read `HANDOFF.md` for where the product build stands and `PRODUCT.md` for the
plan. `NEXT_STEPS.md` is the single list of everything outstanding — work and
decisions both — and nothing finished stays in it.

## Commands

```bash
cargo test --workspace && cargo clippy --workspace --all-targets
(cd sdk/typescript && npm test)              # Node 22.6+, no install
(cd swift/CountersignKit && swift test)
(cd swift/SignetUI && swift test)                # the shared approval screen
(cd swift/Signet && swift test && ./build-app.sh)
(cd web && npm test)
cargo run -p countersign-verify --example gen-vectors        # after a deliberate format change only
cargo build -p countersign-db --lib --target wasm32-unknown-unknown --release
```

Keep all of it green. The vectors in `spec/vectors/` are the contract between
the Rust, TypeScript and Swift implementations; a port is checked against the
files, never against another implementation.

## Conventions

- **Fail toward friction.** Unknown targets are production, unknown actions
  are refused, dead classifiers are `critical`, a counter that cannot be
  persisted refuses the approval. Every new path should fail in that direction.
- **The non-goals are not up for re-litigation**: wire spec §9 and
  device-classes §8. No batch approval, no remember-for-N, no pattern
  auto-approve, no display field separate from the signed payload, no software
  key enrolled as a device, no approving from a notification.
- **Low-S on every signer.** CryptoKit, WebCrypto, RustCrypto and Node all skip
  it. Test many signatures, not one.
- **Docs are in a specific voice**: plain, reasoned, states the why, says what
  a thing does not claim. Match it in comments and READMEs. RFC 2119 words in
  specs.
- **Dirty files may be someone's in-progress work.** Check `git status` before
  editing; prefer adding files to rewriting ones that are already modified.

## Traps

- The project's own hook (`.claude/settings.local.json`) gates `rm` in Bash
  through `signetd`. With no daemon on the default socket, a command containing
  `rm` is refused whole. Leave temp files; do not delete in tool calls.
- Isolate daemons under test with `XDG_CONFIG_HOME`, `COUNTERSIGN_RUNTIME_DIR`
  and a short `COUNTERSIGN_SOCK`.
- Swift packages: Swift 6 tools, Swift 5 language mode, on purpose.
- `wasmi` must keep the `portable-dispatch` feature.
- Unix socket paths cap near 100 bytes; `/tmp/cs-*.sock` in tests.
