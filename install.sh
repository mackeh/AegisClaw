#!/bin/sh
# AegisClaw install script
# Usage: curl -fsSL https://raw.githubusercontent.com/mackeh/AegisClaw/main/install.sh | sh
set -e

REPO="mackeh/AegisClaw"
BINARY="aegisclaw"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  OS="Linux" ;;
    Darwin) OS="Darwin" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Get latest release tag
echo "Fetching latest release..."
LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST" ]; then
    echo "Error: Could not determine latest release"
    exit 1
fi

VERSION="${LATEST#v}"
echo "Latest version: ${LATEST}"

# Build download URL
ARCHIVE="${BINARY}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${LATEST}/${ARCHIVE}"

# Download
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading ${ARCHIVE}..."
curl -fsSL "$URL" -o "${TMPDIR}/${ARCHIVE}"

# Verify checksum if available
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"
if curl -fsSL "$CHECKSUMS_URL" -o "${TMPDIR}/checksums.txt" 2>/dev/null; then
    echo "Verifying checksum..."
    cd "$TMPDIR"
    if command -v sha256sum >/dev/null 2>&1; then
        grep "$ARCHIVE" checksums.txt | sha256sum -c --quiet
    elif command -v shasum >/dev/null 2>&1; then
        grep "$ARCHIVE" checksums.txt | shasum -a 256 -c --quiet
    fi
    cd - >/dev/null
fi

# Extract
echo "Extracting..."
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"

# Install
echo "Installing to ${INSTALL_DIR}..."
if [ -w "$INSTALL_DIR" ]; then
    mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
    sudo mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi
chmod +x "${INSTALL_DIR}/${BINARY}"

echo ""
echo "AegisClaw ${LATEST} installed successfully!"
echo "Run 'aegisclaw init' to get started."
