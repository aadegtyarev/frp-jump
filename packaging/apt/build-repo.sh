#!/usr/bin/env bash
# Builds a signed apt repository tree from a directory of .deb files.
#
# Usage: build-repo.sh <deb-dir> <output-dir>
#
# Requires: dpkg-dev (dpkg-scanpackages), apt-utils (apt-ftparchive), gnupg.
# The signing key must already be imported into the active GNUPGHOME, and
# GPG_SIGNING_FINGERPRINT must name it -- this script doesn't generate or
# manage keys, only signs with one that's already there.
set -euo pipefail

DEB_DIR=$(cd "${1:?usage: build-repo.sh <deb-dir> <output-dir>}" && pwd)
mkdir -p "${2:?usage: build-repo.sh <deb-dir> <output-dir>}"
OUT_DIR=$(cd "$2" && pwd)
: "${GPG_SIGNING_FINGERPRINT:?GPG_SIGNING_FINGERPRINT must be set to the signing key fingerprint}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ARCHES=(amd64 arm64 armhf)
SUITE=stable
COMPONENT=main

REPO_DIR="$OUT_DIR/repo"
POOL_DIR="$REPO_DIR/pool/$COMPONENT"
DISTS_DIR="$REPO_DIR/dists/$SUITE"

rm -rf "$REPO_DIR"
mkdir -p "$POOL_DIR"
cp "$DEB_DIR"/*.deb "$POOL_DIR/"

for arch in "${ARCHES[@]}"; do
  bin_dir="$DISTS_DIR/$COMPONENT/binary-$arch"
  mkdir -p "$bin_dir"
  # Run from $REPO_DIR so the Packages file's Filename: fields come out
  # relative to the repo root (pool/main/...), which is what apt expects.
  (cd "$REPO_DIR" && dpkg-scanpackages --arch "$arch" "pool/$COMPONENT") \
    > "$bin_dir/Packages"
  gzip -9 -k -f "$bin_dir/Packages"
done

cat > "$OUT_DIR/apt-ftparchive.conf" <<EOF
APT::FTPArchive::Release::Origin "frp-jump";
APT::FTPArchive::Release::Label "frp-jump";
APT::FTPArchive::Release::Suite "$SUITE";
APT::FTPArchive::Release::Codename "$SUITE";
APT::FTPArchive::Release::Architectures "${ARCHES[*]}";
APT::FTPArchive::Release::Components "$COMPONENT";
APT::FTPArchive::Release::Description "frp-jump package repository";
EOF

(cd "$REPO_DIR" && apt-ftparchive -c "$OUT_DIR/apt-ftparchive.conf" release "dists/$SUITE") \
  > "$DISTS_DIR/Release"

gpg --batch --yes --local-user "$GPG_SIGNING_FINGERPRINT" \
  --clearsign -o "$DISTS_DIR/InRelease" "$DISTS_DIR/Release"
gpg --batch --yes --local-user "$GPG_SIGNING_FINGERPRINT" \
  -abs -o "$DISTS_DIR/Release.gpg" "$DISTS_DIR/Release"

cp "$SCRIPT_DIR/frp-jump-archive-keyring.asc" "$REPO_DIR/frp-jump-archive-keyring.asc"

echo "Repo built at $REPO_DIR"
