#!/bin/sh
# eesel-cli installer.
#
# Usage:
#   curl -fsSL https://eesel.ai/install.sh | sh
#   curl -fsSL https://eesel.ai/install.sh | sh -s -- --version v0.1.0
#
# Env:
#   EESEL_INSTALL_DIR   override install dir (default: $HOME/.local/bin)
#   EESEL_REPO          override repo (default: eeselapp/eesel-cli)

set -eu

REPO="${EESEL_REPO:-eeselapp/eesel-cli}"
BIN_NAME="eesel"
INSTALL_DIR="${EESEL_INSTALL_DIR:-$HOME/.local/bin}"
REQUESTED_VERSION=""

while [ $# -gt 0 ]; do
  case "$1" in
    --version) REQUESTED_VERSION="$2"; shift 2 ;;
    --version=*) REQUESTED_VERSION="${1#*=}"; shift ;;
    -h|--help)
      cat <<EOF
eesel-cli installer

Options:
  --version <tag>   install a specific release (e.g. v0.1.0)
  -h, --help        show this help

Env:
  EESEL_INSTALL_DIR  install dir (default: \$HOME/.local/bin)
EOF
      exit 0 ;;
    *) printf "error: unknown arg: %s\n" "$1" >&2; exit 2 ;;
  esac
done

err()  { printf "error: %s\n" "$*" >&2; exit 1; }
info() { printf "%s\n" "$*"; }

command -v python3 >/dev/null 2>&1 || err "python3 is required (>= 3.8)"
command -v curl    >/dev/null 2>&1 || err "curl is required"

PY_OK=$(python3 -c 'import sys; print("ok" if sys.version_info >= (3, 8) else "")')
[ "$PY_OK" = "ok" ] || err "python 3.8+ is required (found $(python3 --version))"

mkdir -p "$INSTALL_DIR"

if [ -n "$REQUESTED_VERSION" ]; then
  VERSION="$REQUESTED_VERSION"
else
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null) \
    || err "failed to resolve latest release for $REPO"
fi
[ -n "$VERSION" ] || err "could not determine release version"

URL="https://github.com/$REPO/releases/download/$VERSION/eesel"
TMP="$INSTALL_DIR/$BIN_NAME.download.$$"
trap 'rm -f "$TMP"' EXIT

info "installing eesel $VERSION → $INSTALL_DIR/$BIN_NAME"
curl -fsSL "$URL" -o "$TMP" || err "download failed: $URL"

# Sanity check: must be a python script.
head -1 "$TMP" | grep -q '^#!.*python' || err "downloaded file is not a python script (corrupt download?)"

chmod +x "$TMP"
mv "$TMP" "$INSTALL_DIR/$BIN_NAME"
trap - EXIT

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    info ""
    info "note: $INSTALL_DIR is not on your PATH."
    info "add this to your shell rc (.bashrc / .zshrc):"
    info "  export PATH=\"$INSTALL_DIR:\$PATH\""
    ;;
esac

info ""
info "done. try:"
info "  eesel login"
