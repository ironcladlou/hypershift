#!/usr/bin/env bash
set -euo pipefail

export ARTIFACT_DIR="${ARTIFACT_DIR}/tests/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$ARTIFACT_DIR"

GINKGO_LABEL_FILTER="$1" exec "${E2EV2_BIN_DIR}/run-tests" "${@:2}"
