#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/XRPLF/xrpl.js.git"
PACKAGE_PATH="packages/mpt-crypto"
VENDOR_DIR="$(cd "$(dirname "$0")/.." && pwd)/vendor/mpt-crypto"
TMP_DIR="$(mktemp -d)"

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

echo "Sparse-cloning @xrplf/mpt-crypto from main..."
git clone --depth 1 --filter=blob:none --sparse "$REPO_URL" "$TMP_DIR"
cd "$TMP_DIR"
git sparse-checkout set "$PACKAGE_PATH"

cd "$TMP_DIR/$PACKAGE_PATH"
echo "Patching tsconfig for TypeScript 7 compatibility..."
# Add ignoreDeprecations to suppress node10 moduleResolution deprecation error in TS7
for f in tsconfig.build.json tsconfig.esm.json tsconfig.json; do
  if [ -f "$f" ]; then
    # Insert ignoreDeprecations into compilerOptions if not already present
    node -e "
      const fs = require('fs');
      const data = JSON.parse(fs.readFileSync('$f', 'utf8'));
      if (data.compilerOptions && !data.compilerOptions.ignoreDeprecations) {
        data.compilerOptions.ignoreDeprecations = '6.0';
        fs.writeFileSync('$f', JSON.stringify(data, null, 2));
        console.log('Patched $f');
      }
    " 2>/dev/null || true
  fi
done

echo "Building TypeScript..."
npm install
npm run build

echo "Copying built artefacts to $VENDOR_DIR..."
rm -rf "$VENDOR_DIR"
mkdir -p "$VENDOR_DIR"
cp -r dist wasm package.json "$VENDOR_DIR/"

echo "Done. Now run: npm install (in the extension root)"
echo "Then commit vendor/mpt-crypto/ to lock the build."
