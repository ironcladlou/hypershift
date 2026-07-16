#!/usr/bin/env bash
set -euo pipefail

export ARTIFACT_DIR="${ARTIFACT_DIR}/dumps/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$ARTIFACT_DIR"

exec "${E2EV2_BIN_DIR}/dump-guests"
