# The marketplace

One `index.json`, and a directory per plugin holding its manifest and the
WebAssembly module the manifest pins. Anyone can add a plugin by pull request;
nothing in here can light up a dial until an operator installs it and turns
it on.

This directory is the marketplace's first home, inside the main repository.
It is meant to become a repository of its own; nothing about the format
changes when it moves, and every daemon finds it through one URL
(`COUNTERSIGN_INDEX`, or the default in `crates/signetd/src/marketplace.rs`).

## Using it

```bash
signetd pack index                       # what is listed
signetd pack info countersign-db         # fetched and checked on this machine, not installed
signetd pack install countersign-db      # installed, switched off
signetd pack enable countersign-db       # its namespaces may now reach a person
```

The Mac app's Plugins tab does the same four things with buttons.

## Publishing yours

```bash
cargo build --lib --release --target wasm32-unknown-unknown
signetd pack publish target/wasm32-unknown-unknown/release/my_pack.wasm \
  --into path/to/marketplace \
  --description "what it classifies" --license Apache-2.0 --source https://github.com/you/my-pack
```

That checks the module the way an install checks it, copies it and its
manifest into `<marketplace>/<name>/`, and writes the index entry. Then open
the pull request. CI runs the same checks; so does every daemon, again, before
it starts the pack — because a directory of ordinary files is exactly what a
swapped classifier hides in.

## The rules

Pack protocol §8.3 and §8.4, in short:

- **WebAssembly only.** A module with an empty import section cannot reach a
  network, a filesystem or a clock, and that is the whole reason a public
  directory of classifiers that see production statements is acceptable.
- **Hash-pinned, three ways.** The index's hash, the manifest's pin and the
  module's bytes must agree, and the pin is checked every time the pack
  starts.
- **`describe` must agree with the manifest.** A manifest that promises `sql`
  for a module that answers `terraform` is refused.
- **Installed is off.** Nothing listed can enroll itself into anyone's
  attention.
