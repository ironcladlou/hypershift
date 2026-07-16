#!/usr/bin/env bash
set -euo pipefail

variant="$1"; shift
filter="${1:-}"; shift || true

export ARTIFACT_DIR="${ARTIFACT_DIR}/tests/$(date +%Y%m%d-%H%M%S)-${variant}"
mkdir -p "$ARTIFACT_DIR"

exec "${E2EV2_BIN_DIR}/test-e2e-v2" \
  ${filter:+--ginkgo.label-filter="$filter"} \
  --ginkgo.junit-report="$ARTIFACT_DIR/junit.xml" \
  --ginkgo.v \
  "$@"
