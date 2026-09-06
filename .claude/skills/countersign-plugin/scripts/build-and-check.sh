#!/bin/sh
# Test a pack crate, build its WebAssembly module, and show what the daemon
# would make of it before anything is installed.
#
#   build-and-check.sh <pack-directory>
#
# Prints the module's path last, so a caller can take it.
set -eu

DIR=${1:?usage: build-and-check.sh <pack-directory>}
ROOT=$(git rev-parse --show-toplevel)
SIGNETD=${SIGNETD:-$ROOT/target/debug/signetd}

if ! rustup target list --installed 2>/dev/null | grep -q '^wasm32-unknown-unknown$'; then
  echo "the wasm32-unknown-unknown target is not installed; run: rustup target add wasm32-unknown-unknown" >&2
  exit 1
fi
if [ ! -x "$SIGNETD" ]; then
  (cd "$ROOT" && cargo build -q -p signetd)
fi

cd "$DIR"
echo "== tests"
cargo test -q 2>&1 | grep -E "test result|error" || true
echo "== module"
cargo build -q --lib --release --target wasm32-unknown-unknown
IDENT=$(grep '^name = ' Cargo.toml | head -1 | sed 's/name = "\(.*\)"/\1/' | tr '-' '_')
MODULE=$DIR/target/wasm32-unknown-unknown/release/$IDENT.wasm
echo "== signetd pack info"
"$SIGNETD" pack info "$MODULE"
echo
echo "$MODULE"
