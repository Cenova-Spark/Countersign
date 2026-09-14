#!/bin/sh
# Build Signet.app: the Swift executable, the daemon and its pack beside it,
# an Info.plist that makes it a menu bar app, and a code signature so the
# Secure Enclave and the keychain will talk to it.
#
#   swift/Signet/build-app.sh            # debug
#   swift/Signet/build-app.sh release    # release
#   SIGNET_UNIVERSAL=1 swift/Signet/build-app.sh release
#                                        # release, Apple Silicon and Intel in one bundle
#
# The signature is what makes a rebuilt app the same app to the keychain.
# An ad-hoc signature identifies code by its hash, so every build is a
# stranger and the login keychain asks "Signet wants to use your confidential
# information" on each launch. A certificate-backed signature identifies the
# team and the bundle identifier, which do not change. So: a "Developer ID
# Application" identity from the login keychain when there is one, or the
# one named in SIGNET_CODESIGN_IDENTITY (a name, or the SHA-1 from
# `security find-identity -v -p codesigning`), and ad hoc only as a last
# resort, said out loud.
#
# Distribution needs three more things, and none of them changes what the app
# does. Both architectures, because an Intel Mac cannot run an arm64 binary.
# A secure timestamp on every signature, because notarization refuses a
# Developer ID signature without one. And a bundle version that only grows,
# so whatever installs Signet can tell a newer copy from an older one and
# never replaces the first with the second. Notarizing is the distributor's
# step, not this script's: AddisDB notarizes Signet.app as part of the bundle
# it ships it inside.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PROFILE=${1:-debug}
OUT="$HERE/dist/Signet.app"
UNIVERSAL=${SIGNET_UNIVERSAL:-}

if [ -n "$UNIVERSAL" ] && [ "$PROFILE" != release ]; then
  echo "SIGNET_UNIVERSAL builds release only: SIGNET_UNIVERSAL=1 $0 release" >&2
  exit 1
fi

# The marketing version is the workspace's. The build number is the commit
# count, which grows on one line of history; SIGNET_BUILD overrides it for a
# build from somewhere that has no history.
SHORT_VERSION=${SIGNET_VERSION:-$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/Cargo.toml" | head -n 1)}
BUILD_VERSION=${SIGNET_BUILD:-$(git -C "$ROOT" rev-list --count HEAD 2>/dev/null || echo 1)}

echo "building the daemon ($PROFILE${UNIVERSAL:+, universal})"
if [ -n "$UNIVERSAL" ]; then
  RUST="$ROOT/target/universal-apple-darwin/release"
  mkdir -p "$RUST"
  for triple in aarch64-apple-darwin x86_64-apple-darwin; do
    (cd "$ROOT" && cargo build -q --release --target "$triple" -p signetd -p countersign-db)
  done
  for bin in signetd countersign-db; do
    lipo -create -output "$RUST/$bin" \
      "$ROOT/target/aarch64-apple-darwin/release/$bin" \
      "$ROOT/target/x86_64-apple-darwin/release/$bin"
  done
elif [ "$PROFILE" = release ]; then
  (cd "$ROOT" && cargo build -q --release -p signetd -p countersign-db)
  RUST="$ROOT/target/release"
else
  (cd "$ROOT" && cargo build -q -p signetd -p countersign-db)
  RUST="$ROOT/target/debug"
fi

echo "building the app ($PROFILE${UNIVERSAL:+, universal})"
if [ -n "$UNIVERSAL" ]; then
  # One native build per architecture, then lipo, the same as the daemon.
  # Passing --arch twice hands the build to Xcode's build system instead, and
  # that fails on this package ("missing target configuration for
  # 'SignetCore'", Swift 6.0).
  SWIFT_BIN="$HERE/.build/universal-apple-macosx/$PROFILE"
  mkdir -p "$SWIFT_BIN"
  for triple in arm64-apple-macosx x86_64-apple-macosx; do
    (cd "$HERE" && swift build -q -c "$PROFILE" --product Signet --triple "$triple")
  done
  lipo -create -output "$SWIFT_BIN/Signet" \
    "$(cd "$HERE" && swift build -c "$PROFILE" --triple arm64-apple-macosx --show-bin-path)/Signet" \
    "$(cd "$HERE" && swift build -c "$PROFILE" --triple x86_64-apple-macosx --show-bin-path)/Signet"
else
  (cd "$HERE" && swift build -q -c "$PROFILE" --product Signet)
  SWIFT_BIN=$(cd "$HERE" && swift build -c "$PROFILE" --show-bin-path)
fi

mkdir -p "$OUT/Contents/MacOS" "$OUT/Contents/Resources" "$OUT/Contents/Helpers"
cp "$SWIFT_BIN/Signet" "$OUT/Contents/MacOS/Signet"
cp "$RUST/signetd" "$OUT/Contents/Helpers/signetd"
cp "$RUST/countersign-db" "$OUT/Contents/Helpers/countersign-db"

# A universal build that quietly lost an architecture works on this Mac and
# nowhere else, so check the files rather than the flags.
if [ -n "$UNIVERSAL" ]; then
  for f in "$OUT/Contents/MacOS/Signet" "$OUT/Contents/Helpers/signetd" "$OUT/Contents/Helpers/countersign-db"; do
    archs=$(lipo -archs "$f")
    case " $archs " in
      *" arm64 "*) ;;
      *) echo "not universal, no arm64: $f ($archs)" >&2; exit 1 ;;
    esac
    case " $archs " in
      *" x86_64 "*) ;;
      *) echo "not universal, no x86_64: $f ($archs)" >&2; exit 1 ;;
    esac
  done
fi

cat > "$OUT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Signet</string>
  <key>CFBundleDisplayName</key><string>Signet</string>
  <key>CFBundleIdentifier</key><string>com.addisdb.signet</string>
  <key>CFBundleVersion</key><string>$BUILD_VERSION</string>
  <key>CFBundleShortVersionString</key><string>$SHORT_VERSION</string>
  <key>CFBundleExecutable</key><string>Signet</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>Apache-2.0</string>
</dict>
</plist>
PLIST

# The identity: named, or the first Developer ID Application identity the
# keychain holds (any certificate of the same team is the same identity to
# the keychain), or ad hoc. The SHA-1 is used rather than the name, because
# two certificates can share a name and codesign refuses to guess.
if [ -n "${SIGNET_CODESIGN_IDENTITY:-}" ]; then
  IDENTITY=$SIGNET_CODESIGN_IDENTITY
else
  IDENTITY=$(security find-identity -v -p codesigning 2>/dev/null \
    | awk '/"Developer ID Application:/ { print $2; exit }')
fi
if [ -n "$IDENTITY" ]; then
  echo "signing as $(security find-identity -v -p codesigning | awk -v h="$IDENTITY" '$2 == h || index($0, h) { sub(/^[^"]*"/, ""); sub(/"[^"]*$/, ""); print; exit }')"
else
  IDENTITY=-
  echo "signing ad hoc: no Developer ID Application identity in the keychain, and SIGNET_CODESIGN_IDENTITY is unset."
  echo "Every rebuild will be a new app to the keychain, and it will ask on each launch."
fi

# A secure timestamp on a release signed with a real identity, because that is
# the build someone might notarize. Not on a debug build, where it would only
# make every rebuild wait on Apple's timestamp server, and never ad hoc, which
# cannot carry one.
TIMESTAMP=
if [ "$PROFILE" = release ] && [ "$IDENTITY" != - ]; then
  TIMESTAMP=--timestamp
fi

# The hardened runtime, so the keychain and the enclave accept the process.
codesign --force --sign "$IDENTITY" --options runtime $TIMESTAMP "$OUT/Contents/Helpers/signetd"
codesign --force --sign "$IDENTITY" --options runtime $TIMESTAMP "$OUT/Contents/Helpers/countersign-db"
codesign --force --sign "$IDENTITY" --options runtime $TIMESTAMP --identifier com.addisdb.signet "$OUT"

echo "built $OUT ($SHORT_VERSION, build $BUILD_VERSION)"
echo "run with:  open $OUT"
