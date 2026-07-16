#!/usr/bin/env bash
set -euo pipefail

"${E2EV2_BIN_DIR}/destroy-guests"
rm -f shared/.create-started
