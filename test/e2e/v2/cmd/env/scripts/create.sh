#!/usr/bin/env bash
set -euo pipefail

if [ -f shared/.create-started ]; then
  echo "ERROR: A previous create was attempted. Run 'mise run destroy' first."
  exit 1
fi
touch shared/.create-started
"${E2EV2_BIN_DIR}/create-guests"
