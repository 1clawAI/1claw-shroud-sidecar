#!/usr/bin/env sh
# Install shroud-sidecar from GitHub Releases (linux-amd64 / darwin-arm64 only).
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/1clawAI/1claw-shroud-sidecar/v1.0.0/install.sh | sh
# Or pin version:
#   SHROUD_SIDECAR_VERSION=v1.0.0 curl -fsSL ... | sh
# Override install location:
#   PREFIX=/usr/local/bin curl -fsSL ... | sh

set -eu

REPO="${SHROUD_SIDECAR_REPO:-1clawAI/1claw-shroud-sidecar}"
BINARY_NAME="${BINARY_NAME:-shroud-sidecar}"

detect_suffix() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$os-$arch" in
    Linux-x86_64) asset_suffix=linux_amd64 ;;
    Darwin-arm64) asset_suffix=darwin_arm64 ;;
    *)
      echo "shroud-sidecar: unsupported platform $os $arch (prebuilt binaries: linux/amd64, darwin/arm64)" >&2
      exit 1
      ;;
  esac
}

latest_tag() {
  tmp=$(mktemp)
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" -o "$tmp"
  tag=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp" | head -n1)
  rm -f "$tmp"
  if [ -z "$tag" ]; then
    echo "shroud-sidecar: could not resolve latest release for https://github.com/${REPO}" >&2
    exit 1
  fi
  printf '%s' "$tag"
}

detect_suffix

VERSION="${SHROUD_SIDECAR_VERSION:-}"
if [ -z "$VERSION" ]; then
  VERSION=$(latest_tag)
fi

asset="${BINARY_NAME}_${asset_suffix}.tar.gz"
url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
sumurl="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

PREFIX="${PREFIX:-${HOME}/.local/bin}"
mkdir -p "$PREFIX"

tmpd=$(mktemp -d)
trap 'rm -rf "$tmpd"' EXIT

echo "shroud-sidecar: fetching ${VERSION} ($asset) ..."
curl -fsSL "$url" -o "$tmpd/$asset"

if curl -fsSL "$sumurl" -o "$tmpd/checksums.txt" 2>/dev/null; then
  cd "$tmpd"
  if command -v sha256sum >/dev/null 2>&1; then
    grep "$asset" checksums.txt | sha256sum -c
  else
    grep "$asset" checksums.txt | shasum -a 256 -c
  fi
else
  echo "shroud-sidecar: warning: checksums.txt not found; skipping checksum verify" >&2
fi

tar -xzf "$tmpd/$asset" -C "$tmpd"
src="$tmpd/${BINARY_NAME}_${asset_suffix}/${BINARY_NAME}"
if [ ! -f "$src" ]; then
  echo "shroud-sidecar: expected binary missing at $src" >&2
  exit 1
fi

if command -v install >/dev/null 2>&1; then
  install -m 0755 "$src" "$PREFIX/${BINARY_NAME}"
else
  cp "$src" "$PREFIX/${BINARY_NAME}"
  chmod 0755 "$PREFIX/${BINARY_NAME}"
fi

ver_out=$("$PREFIX/${BINARY_NAME}" --version 2>/dev/null || echo "?")
echo "shroud-sidecar: installed ($ver_out)"
echo "shroud-sidecar: -> $PREFIX/${BINARY_NAME}"
case ":${PATH}:" in
  *":$PREFIX:"*) ;;
  *) echo "shroud-sidecar: add to PATH: export PATH=\"$PREFIX:\$PATH\"" >&2 ;;
esac
