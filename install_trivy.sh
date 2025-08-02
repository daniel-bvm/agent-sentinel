#!/usr/bin/env bash
set -euo pipefail

TRIVY_VERSION="0.20.2"

echo "Detecting architecture..."
ARCH="$(dpkg --print-architecture)"
echo "Detected architecture: $ARCH"

case "$ARCH" in
  amd64)
    TRIVY_PKG="trivy_${TRIVY_VERSION}_Linux-64bit.deb"
    ;;
  arm64)
    TRIVY_PKG="trivy_${TRIVY_VERSION}_Linux-ARM64.deb"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

echo "Downloading Trivy package: $TRIVY_PKG"
wget "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TRIVY_PKG}"

echo "Installing Trivy..."
dpkg -i "$TRIVY_PKG"

echo "Cleaning up..."
rm "$TRIVY_PKG"

echo "Trivy installed successfully!"
