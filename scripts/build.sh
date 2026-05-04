#!/usr/bin/env bash
# Build the keep binary.
#
# 1. Build Tailwind CSS into web/dist/keep.css (so it can be embedded by Go).
# 2. Compile the Go binary.
#
# First-time setup: `cd web && npm install`. After that, this script regenerates
# the CSS each time.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Step 1: build CSS.
if [[ ! -d web/node_modules ]]; then
    echo "[build] installing tailwind..."
    (cd web && npm install --silent)
fi
echo "[build] generating web/dist/keep.css..."
(cd web && npx tailwindcss -i ./input.css -o ./dist/keep.css --minify)

# Step 2: build Go binary.
echo "[build] compiling go binary..."
go build -trimpath -ldflags="-s -w" -o keep ./cmd/keep

echo "[build] done -> ./keep"
