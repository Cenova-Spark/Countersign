#!/bin/sh
# Scaffold a pack crate from this checkout's template and point its one
# dependency at the checkout, because the published dependency line points at
# the repository and only resolves once the work is pushed.
#
#   new-pack.sh <name> <namespace> [directory]
#
# Names and namespaces are lowercase letters, digits and hyphens; a namespace
# has no dot. The crate lands in <checkout>/plugins/<name> unless told where.
set -eu

NAME=${1:?usage: new-pack.sh <name> <namespace> [directory]}
NAMESPACE=${2:?usage: new-pack.sh <name> <namespace> [directory]}
ROOT=$(git rev-parse --show-toplevel)
DEST=${3:-$ROOT/plugins/$NAME}
SIGNETD=${SIGNETD:-$ROOT/target/debug/signetd}

if [ ! -x "$SIGNETD" ]; then
  echo "building signetd" >&2
  (cd "$ROOT" && cargo build -q -p signetd)
fi

"$SIGNETD" pack new "$NAME" --namespace "$NAMESPACE" --dir "$DEST" >/dev/null
# The checkout's crate, not the repository's.
sed -i '' "s#countersign-pack = { git = \"[^\"]*\" }#countersign-pack = { path = \"$ROOT/crates/countersign-pack\" }#" "$DEST/Cargo.toml"

echo "$DEST"
echo "  src/lib.rs      classify goes here; NAMESPACE is \"$NAMESPACE\""
echo "  cargo test      the host's rules, as tests"
echo "next: $ROOT/.claude/skills/countersign-plugin/scripts/build-and-check.sh $DEST"
