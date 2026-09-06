# countersign-pack-template

A Countersign domain pack. It tells `signetd` how bad a statement in its
namespace is and what the approval screen should show. It decides nothing —
policy decides — and it connects to nothing.

## Make it yours

1. In `src/lib.rs`, set `NAMESPACE` and replace `classify` with a real
   reading of your domain. Keep the shape: an action inside the namespace, a
   severity, whether it can be undone, and the lines a person must read
   before they hold.
2. `cargo test`. The tests are the host's rules; keep them green.
3. Try it on stdio, which is how the daemon runs a native pack:

   ```bash
   printf '%s\n' \
     '{"jsonrpc":"2.0","id":1,"method":"describe"}' \
     '{"jsonrpc":"2.0","id":2,"method":"classify","params":{"action":"example.run","statement":"delete everything"}}' \
     | cargo run -q
   ```

Working from a checkout of Countersign rather than the repository? Point the
dependency in `Cargo.toml` at it:
`countersign-pack = { path = "/path/to/countersign/crates/countersign-pack" }`.

## Ship it

Build the module. It imports nothing, so wherever it runs it cannot reach a
network, a filesystem or a clock. That is the sandbox, and it is what lets a
marketplace list a classifier that sees production statements.

```bash
rustup target add wasm32-unknown-unknown
cargo build --lib --release --target wasm32-unknown-unknown
signetd pack info    target/wasm32-unknown-unknown/release/countersign_pack_template.wasm
signetd pack install target/wasm32-unknown-unknown/release/countersign_pack_template.wasm
signetd pack enable  countersign-pack-template
```

`pack info` shows what the module claims, asked inside the sandbox, before
anything is installed. `pack install` writes the manifest for you, pinned to
the module's hash, and leaves the pack **off**. Nothing in your namespace
reaches a person until `pack enable`.

The native binary from `cargo build --release` installs too, from a directory
holding a `countersign-plugin.json` beside it. Fine on your own machine, never
listed publicly: a native pack has every capability the operating system
gives it.

## The rules a host enforces

1. A pack may **raise** severity and never lower it.
2. A pack cannot write the environment label or the digest.
3. Failure is closed. A dead classifier means `critical`, not "probably fine".

The protocol is two methods and one response shape:
[`spec/pack-protocol-v1.md`](https://github.com/Cenova-Spark/Countersign/blob/main/spec/pack-protocol-v1.md).
