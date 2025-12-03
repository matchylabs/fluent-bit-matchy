#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT_DIR"

# Resolve version from Cargo.toml
VERSION=$(sed -n 's/^version\s*=\s*"\([^"]*\)"/\1/p' Cargo.toml | head -1)
: "${VERSION:=0.1.0}"

TARGET_DIR="$ROOT_DIR/target/wasm32-wasip1/release"
DIST_DIR="$ROOT_DIR/dist"
PKG_NAME="fluent-bit-matchy"
WASM_NAME="fluent_bit_matchy.wasm"

mkdir -p "$DIST_DIR"

# 1) Build WASM
rustup target add wasm32-wasip1 >/dev/null 2>&1 || true
cargo build --target wasm32-wasip1 --release

# 2) Create tarball (platform-independent)
STAGE_TAR="$ROOT_DIR/.stage/tar"
rm -rf "$STAGE_TAR"
mkdir -p "$STAGE_TAR"

install -D -m0644 "$TARGET_DIR/$WASM_NAME" "$STAGE_TAR/$WASM_NAME"
install -D -m0644 "$ROOT_DIR/examples/matchy.conf.example" "$STAGE_TAR/matchy.conf.example"
install -D -m0644 "$ROOT_DIR/examples/fluent-bit.conf.example" "$STAGE_TAR/fluent-bit.conf.example"
install -D -m0644 "$ROOT_DIR/README.md" "$STAGE_TAR/README.md"

TARBALL="$DIST_DIR/${PKG_NAME}-${VERSION}-any.tar.gz"
( cd "$STAGE_TAR" && tar -czf "$TARBALL" . )
sha256sum "$TARBALL" > "$TARBALL.sha256" 2>/dev/null || shasum -a 256 "$TARBALL" > "$TARBALL.sha256"

echo "Created tarball: $TARBALL"

# 3) Create Debian package (.deb) if dpkg-deb is available
if command -v dpkg-deb >/dev/null 2>&1; then
  STAGE_DEB="$ROOT_DIR/.stage/deb"
  rm -rf "$STAGE_DEB"
  mkdir -p "$STAGE_DEB/DEBIAN"
  mkdir -p "$STAGE_DEB/usr/lib/fluent-bit/plugins"
  mkdir -p "$STAGE_DEB/etc/fluent-bit"
  mkdir -p "$STAGE_DEB/usr/share/doc/${PKG_NAME}"

  install -m0644 "$TARGET_DIR/$WASM_NAME" "$STAGE_DEB/usr/lib/fluent-bit/plugins/$WASM_NAME"
  install -m0644 "$ROOT_DIR/examples/matchy.conf.example" "$STAGE_DEB/etc/fluent-bit/matchy.conf.example"
  install -m0644 "$ROOT_DIR/README.md" "$STAGE_DEB/usr/share/doc/${PKG_NAME}/README"

  cat > "$STAGE_DEB/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: all
Depends: fluent-bit
Maintainer: MatchyLabs <support@matchy.dev>
Description: Matchy WASM filter for Fluent Bit
 Installs a WebAssembly filter (matchy) for Fluent Bit with example configs.
EOF

  DEB_OUT="$DIST_DIR/${PKG_NAME}_${VERSION}_all.deb"
  dpkg-deb --build "$STAGE_DEB" "$DEB_OUT"
  echo "Created deb: $DEB_OUT"
else
  echo "dpkg-deb not found; skipping .deb build"
fi

# 4) Print next steps
cat <<EOS

Artifacts written to: $DIST_DIR
- ${PKG_NAME}-${VERSION}-any.tar.gz (+ .sha256)
- ${PKG_NAME}_${VERSION}_all.deb (if dpkg-deb available)

Install (tarball):
  sudo mkdir -p /usr/lib/fluent-bit/plugins /etc/fluent-bit
  sudo tar -C /usr/lib/fluent-bit/plugins -xzf ${PKG_NAME}-${VERSION}-any.tar.gz ${WASM_NAME}
  sudo tar -C /etc/fluent-bit -xzf ${PKG_NAME}-${VERSION}-any.tar.gz matchy.conf.example

Install (Debian/Ubuntu):
  sudo dpkg -i ${PKG_NAME}_${VERSION}_all.deb
  sudo cp /etc/fluent-bit/matchy.conf.example /etc/fluent-bit/matchy.conf
  sudo editor /etc/fluent-bit/matchy.conf  # point Database to your .mxy

Then configure Fluent Bit filter:
  [FILTER]
      Name            wasm
      Match           *
      WASM_Path       /usr/lib/fluent-bit/plugins/${WASM_NAME}
      Function_Name   matchy_filter
      accessible_paths /etc/fluent-bit

EOS
