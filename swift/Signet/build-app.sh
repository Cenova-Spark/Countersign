#!/bin/sh
# Build Signet.app: the Swift executable, the daemon and its pack beside it,
# an Info.plist that makes it a menu bar app, and a code signature so the
# Secure Enclave and the keychain will talk to it.
#
#   swift/Signet/build-app.sh            # debug
#   swift/Signet/build-app.sh release    # release
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
# Distribution adds notarization on top; nothing else here changes.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
PROFILE=${1:-debug}
OUT="$HERE/dist/Signet.app"

echo "building the daemon ($PROFILE)"
if [ "$PROFILE" = release ]; then
  (cd "$ROOT" && cargo build -q --release -p signetd -p countersign-db)
  RUST="$ROOT/target/release"
else
  (cd "$ROOT" && cargo build -q -p signetd -p countersign-db)
  RUST="$ROOT/target/debug"
fi

echo "building the app ($PROFILE)"
(cd "$HERE" && swift build -q -c "$PROFILE" --product Signet)
SWIFT_BIN=$(cd "$HERE" && swift build -c "$PROFILE" --show-bin-path)

mkdir -p "$OUT/Contents/MacOS" "$OUT/Contents/Resources" "$OUT/Contents/Helpers"
cp "$SWIFT_BIN/Signet" "$OUT/Contents/MacOS/Signet"
cp "$RUST/signetd" "$OUT/Contents/Helpers/signetd"
cp "$RUST/countersign-db" "$OUT/Contents/Helpers/countersign-db"

cat > "$OUT/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Signet</string>
  <key>CFBundleDisplayName</key><string>Signet</string>
  <key>CFBundleIdentifier</key><string>com.addisdb.signet</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>0.1.0</string>
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

# The hardened runtime, so the keychain and the enclave accept the process.
codesign --force --sign "$IDENTITY" --options runtime "$OUT/Contents/Helpers/signetd"
codesign --force --sign "$IDENTITY" --options runtime "$OUT/Contents/Helpers/countersign-db"
codesign --force --sign "$IDENTITY" --options runtime --identifier com.addisdb.signet "$OUT"

echo "built $OUT"
echo "run with:  open $OUT"
