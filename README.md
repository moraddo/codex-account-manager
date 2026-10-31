# Codex Account Manager

**Codex Account Manager** is a Linux CLI for managing multiple ChatGPT accounts in Codex without signing in again every time you switch. Each account uses its own Codex authentication profile, while projects, configuration, and local conversation history remain shared.

Use either `cam` or `codex-account-manager` — both commands are identical.

## What it does

- Register multiple Codex accounts with one-time sign-in per account.
- Switch the active account and resume an existing Codex session.
- Share session history, `AGENTS.md`, skills, rules, and `config.toml` across accounts.
- Let Codex store and refresh account credentials using the native OS keyring; the manager does not copy OAuth tokens.
- Back up and restore Codex data, optionally encrypting the backup with GPG.

Account switching is **manual**, not automatic on quota exhaustion. Stop the current Codex session before switching; an interrupted model request is not transferred mid-generation.

## Requirements

- Linux with a working, unlocked OS keyring (for example, GNOME Keyring).
- Codex CLI installed and available as `codex` in `PATH`, with support for `cli_auth_credentials_store = "keyring"` and `CODEX_SQLITE_HOME`.
- Python 3.11 or newer (standard library only).
- GnuPG (`gpg`) for encrypted backups.

## Installation

From the project directory:

```bash
./install.sh
cam init
```

The installer creates `~/.local/bin/cam` and `~/.local/bin/codex-account-manager`. Make sure `~/.local/bin` is on your `PATH`.

`cam init` enables native keyring authentication in `~/.codex/config.toml` and keeps your existing Codex configuration and sessions. It does **not** delete an existing `~/.codex/auth.json`; check for leftover file-based credentials with `cam doctor`.

## Usage

### Register accounts

```bash
cam add personal             # Authenticate once using the browser
cam add second               # Authenticate the second account once
cam list                     # List accounts (* marks the active one)
```

For device-code sign-in, use `cam add personal --device-auth`.

### Switch accounts and continue a session

```bash
cam run                      # Start Codex with the active account
# Exit Codex before switching
cam switch second --resume   # Switch and resume the newest session for this project
cam switch personal          # Switch without opening Codex
cam resume                   # Resume the newest session for this project
cam resume <SESSION_ID>      # Resume a specific session
```

The long command name works the same way:

```bash
codex-account-manager switch second --resume
```

Other commands:

| Command | Purpose |
| --- | --- |
| `cam init` | Initialize shared configuration and require keyring credentials |
| `cam add NAME` | Create an account profile and sign in |
| `cam relogin NAME` | Sign in again if an account's login expires or is revoked |
| `cam list` | List saved profiles and the active profile |
| `cam switch NAME` | Select an account without starting Codex |
| `cam switch NAME --resume` | Select an account and resume a local session |
| `cam run [ARGS...]` | Run Codex with the selected account; pass through Codex arguments |
| `cam resume [SESSION_ID]` | Resume a project session (or a specified session) |
| `cam doctor` | Report profile configuration and possible plaintext credential files |
| `cam backup FILE` | Create a backup ZIP |
| `cam restore FILE` | Validate and restore a backup |

For example, `cam run exec "fix the failing tests"` passes `exec` and its arguments to Codex.

## Backup and restore

```bash
# Recommended: password-encrypted backup (requires gpg)
cam backup ~/codex-backup.zip.gpg --encrypt

# Plain ZIP (not encrypted)
cam backup ~/codex-backup.zip

# Replace an existing backup intentionally
cam backup ~/codex-backup.zip --overwrite

# Validate and preview restore paths
cam restore ~/codex-backup.zip.gpg --dry-run

# Restore after exiting all Codex instances
cam restore ~/codex-backup.zip.gpg
```

Backups include Codex's canonical configuration, local sessions and history, shared skills and instructions, SQLite state, and account-manager metadata. **OAuth credentials and OS-keyring secrets are not exported.** Backups can still contain sensitive project content or MCP settings, so use encryption when storing or sharing them.

Restore verifies archive paths and checksums before writing and saves a local recovery ZIP before making changes. **The recovery ZIP is not encrypted.** Existing files not included in the backup are left alone. Restoring on another computer requires signing in to each account again using `cam relogin NAME`.

## Security and limitations

- Each account has its own `CODEX_HOME` and native keyring entry. Shared session/configuration files are linked to the canonical `~/.codex` directory; credentials are not linked or copied.
- Keyring storage protects credentials at rest, **not against malware operating within your unlocked user session**. Protect your device and backups accordingly.
- Exit Codex before account switching, backup, or restore. Running multiple Codex clients against shared state can cause inconsistent behavior; checks for unmanaged processes are best-effort.
- Cross-account session resumption depends on Codex's session format and may behave differently across Codex releases. Test with a disposable session before relying on it for critical work.
- The CLI is Linux-only. It does not automatically rotate accounts at quota limits.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests use a mock Codex executable and do not replace a live multi-account/keyring compatibility test.
