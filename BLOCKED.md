# Blocked offline

Moved into [NEXT_STEPS.md §5](NEXT_STEPS.md#5-constrained-by-the-offline-build),
so that everything outstanding is in one list rather than two that drift.

The short version, for anyone grepping:

- **`p256` is pinned to `0.14.0-rc.10`** — a release candidate, in the crate
  whose whole job is signature verification. Swappable behind one trait.
- **No `hidapi`** — no real device yet. Not on the critical path.
- **No `axum`** — no local HTTP/WS transport.
- **MCP is hand-rolled** — and probably should stay that way.
- **`Cargo.lock` came entirely from a local cache** — needs a clean resolve.
