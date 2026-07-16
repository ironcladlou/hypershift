#!/usr/bin/env bash
set -euo pipefail

variant="$1"; shift
cluster_name="$1"; shift
namespace="$1"; shift

export ARTIFACT_DIR="${ARTIFACT_DIR}/dumps/$(date +%Y%m%d-%H%M%S)-${variant}"
mkdir -p "$ARTIFACT_DIR"

exec "${HYPERSHIFT_BINARY}" dump cluster \
  --artifact-dir="$ARTIFACT_DIR" \
  --dump-guest-cluster=true \
  --name="$cluster_name" \
  --namespace="$namespace" \
  "$@"
