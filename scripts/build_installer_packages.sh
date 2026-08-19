#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
VERSION="${CYBERION_AGENT_VERSION:-1.0.0}"

mkdir -p "$DIST_DIR"

echo "Building universal installer bundle..."
tar -czf "$DIST_DIR/cyberion-agent-installer-${VERSION}.tar.gz" \
  -C "$ROOT_DIR" installer Agent requirements.txt agent.yaml config_reference.yaml

echo "Preparing Linux package skeletons..."
mkdir -p "$DIST_DIR/deb" "$DIST_DIR/rpm"
cp "$DIST_DIR/cyberion-agent-installer-${VERSION}.tar.gz" "$DIST_DIR/deb/"
cp "$DIST_DIR/cyberion-agent-installer-${VERSION}.tar.gz" "$DIST_DIR/rpm/"

echo "Build complete:"
ls -1 "$DIST_DIR"
