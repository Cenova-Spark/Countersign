# Blocked offline — revisit with a network

This workspace was built on a machine with no network access, against whatever
was already in the local cargo registry cache. Nothing below is a design
decision; each is a constraint to re-examine once crates.io is reachable.

Ordered by how much it matters.

---

## 1. `p256` is pinned to a pre-release

`p256 = "0.14.0-rc.10"`, with `ecdsa 0.17.0-rc.18` and `elliptic-curve
0.14.0-rc.33` underneath. That is the only version generation in the cache.

A release-candidate crypto dependency in the crate whose entire job is signature
verification deserves a deliberate look:

- Check whether 0.14 has shipped final, and move to it.
- Otherwise consider pinning back to the last stable `p256 0.13`, which would
  mean adjusting `sha2` to 0.10 and the `SigningKey::from_slice` /
  `to_sec1_bytes` call sites.
- The blast radius is small on purpose: `SignatureBackend` is a trait, and the
  RustCrypto implementation is one ~15-line module behind the `ecdsa-p256`
  feature. Everything else in `countersign-verify` compiles with no crypto
  dependency at all.

**Watch for:** whichever library replaces it, confirm it does **not** normalize
`s` on the signing path. RustCrypto does not, which is how three of the four
signature paths here shipped without a low-S check and a committed vector went
out high-S. See `spec/countersign-v1.md` §4 and
`crates/signetd/src/device.rs::sign_low_s`.

## 2. No `hidapi`, so there is no real device

Not on the critical path — hardware is at Phase 0 and the mock is the plan until
Phase 2 boards exist. When it lands:

- `signetd::device::Device` is the trait to implement; `MockDevice` is the
  reference shape.
- The daemon already assumes one device and one active request at a time, which
  is what a single USB HID handle allows.
- Reconnect-on-unplug and device-state push are not written yet.

## 3. No `axum`, so no local HTTP/WS transport

Build-order step 8. The unix socket in `signetd::service` covers same-machine
clients today, and SSH `RemoteForward` will cover remote ones without any HTTP
at all. Revisit when a client genuinely cannot use a socket — a browser, or the
cloud-agent relay.

## 4. MCP is hand-rolled

No MCP SDK was cached, so `signetd::mcp` implements the three methods it needs
(`initialize`, `tools/list`, `tools/call`) directly over line-delimited
JSON-RPC.

This is probably worth **keeping** rather than replacing: the bridge is under
300 lines, an SDK would be larger than the thing it replaced, and this component
is deliberately the one with no keys and no authority. Revisit only if MCP adds
something the bridge should support — resources, prompts, or a transport change.

## 5. Unix-only

`signetd::service` uses `std::os::unix::net`, and `signetd::interactive` assumes
a POSIX terminal. Windows needs named pipes and a different console path. No
work has been done here.

## 6. Not yet verified against a released registry

`Cargo.lock` was resolved entirely from cache. Once online, run a clean
`cargo update` + `cargo test --workspace` on a fresh checkout to confirm nothing
here depends on a version that only exists on this machine.
