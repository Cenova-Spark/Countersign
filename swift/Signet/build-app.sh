#!/bin/sh
# Build Signet.app: the Swift executable, the daemon and its pack beside it,
# an Info.plist that makes it a menu bar app, and an ad-hoc signature so the
# Secure Enclave and the data-protection keychain will talk to it.
#
#   swift/Signet/build-app.sh            # debug
#   swift/Signet/build-app.sh release    # release
#
# Distribution outside the App Store needs a Developer ID signature and
# notarization in place of the ad-hoc step; nothing else here changes.
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

# Ad hoc, with the hardened runtime, so the keychain and the enclave accept
# the process. Replace `-` with a Developer ID identity to distribute.
codesign --force --sign - --options runtime "$OUT/Contents/Helpers/signetd"
codesign --force --sign - --options runtime "$OUT/Contents/Helpers/countersign-db"
codesign --force --sign - --options runtime --identifier com.addisdb.signet "$OUT"

echo "built $OUT"
echo "run with:  open $OUT"
