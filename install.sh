#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
install -d -m 0700 "$BIN_DIR"

# Both commands are the exact same Python program, not separate installations.
install -m 0755 "$SCRIPT_DIR/codex_account_manager.py" "$BIN_DIR/cam"
install -m 0755 "$SCRIPT_DIR/codex_account_manager.py" "$BIN_DIR/codex-account-manager"

printf 'Installed %s/cam and %s/codex-account-manager\n' "$BIN_DIR" "$BIN_DIR"
printf 'Try: cam --help  (equivalently: codex-account-manager --help)\n'
