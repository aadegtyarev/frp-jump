#!/usr/bin/env bash
# Build the frp-jump-client .deb for one target architecture.
#
# Usage: build.sh <amd64|arm64|armhf> <version> [output-dir]
#
# <version> must already be published on PyPI -- this only packages an
# already-released frp-jump into a self-contained, arch-specific bundle
# (see Dockerfile's own docstring for why: a private Python 3.12 under
# /opt/frp-jump-client, so the device's own Python/pip/apt are never
# touched). Requires: docker buildx with QEMU registered for foreign
# architectures (`docker run --privileged --rm tonistiigi/binfmt --install all`
# once per build host), and dpkg-deb.
set -euo pipefail

DEB_ARCH="${1:?usage: build.sh <amd64|arm64|armhf> <version> [output-dir]}"
VERSION="${2:?usage: build.sh <amd64|arm64|armhf> <version> [output-dir]}"
OUT_DIR="${3:-.}"

case "$DEB_ARCH" in
    amd64) BUILDX_PLATFORM=linux/amd64 ; UV_TARGET=x86_64-unknown-linux-gnu ;;
    arm64) BUILDX_PLATFORM=linux/arm64 ; UV_TARGET=aarch64-unknown-linux-gnu ;;
    armhf) BUILDX_PLATFORM=linux/arm/v7 ; UV_TARGET=armv7-unknown-linux-gnueabihf ;;
    *)
        echo "unknown architecture ${DEB_ARCH!r} -- use amd64, arm64, or armhf" >&2
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "==> building the /opt/frp-jump-client tree for $DEB_ARCH ($BUILDX_PLATFORM)"
docker buildx build \
    --platform "$BUILDX_PLATFORM" \
    --build-arg "BASE_PLATFORM=$BUILDX_PLATFORM" \
    --build-arg "UV_TARGET=$UV_TARGET" \
    --build-arg "FRP_JUMP_VERSION=$VERSION" \
    --target export \
    -o "type=local,dest=$WORK_DIR/export" \
    -f "$SCRIPT_DIR/Dockerfile" \
    "$SCRIPT_DIR"

STAGING="$WORK_DIR/staging"
mkdir -p "$STAGING/DEBIAN" "$STAGING/opt" "$STAGING/usr/bin" "$STAGING/lib/systemd/system"
cp -a "$WORK_DIR/export/out" "$STAGING/opt/frp-jump-client"
ln -s /opt/frp-jump-client/site-packages/bin/frp-jump-client "$STAGING/usr/bin/frp-jump-client"
cp "$SCRIPT_DIR/frp-jump-client.service" "$STAGING/lib/systemd/system/frp-jump-client.service"

cat > "$STAGING/DEBIAN/control" <<EOF
Package: frp-jump-client
Version: $VERSION
Section: net
Priority: optional
Architecture: $DEB_ARCH
Maintainer: Alexander Degtyarev <a.degtyarev@struhe.com>
Description: frp-jump tunnel agent (self-contained)
 P2P-with-relay-fallback ssh/http/tcp tunnel client agent. Ships its own
 Python 3.12 runtime under /opt/frp-jump-client -- does not touch or
 require the system Python/pip/apt.
Homepage: https://github.com/aadegtyarev/frp-jump
EOF

cat > "$STAGING/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    systemctl daemon-reload || true
fi
EOF

cat > "$STAGING/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl daemon-reload || true
fi
EOF

chmod 755 "$STAGING/DEBIAN/postinst" "$STAGING/DEBIAN/postrm"

mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/frp-jump-client_${VERSION}_${DEB_ARCH}.deb"
# -Zxz: some devices' dpkg (e.g. Debian 11 on Wiren Board controllers)
# predates default zstd support for the control member.
dpkg-deb --build -Zxz --root-owner-group "$STAGING" "$OUT_FILE"
echo "==> built $OUT_FILE"
