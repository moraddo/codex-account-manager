# Codex Account Manager

**Codex Account Manager** is a Linux CLI for managing multiple ChatGPT accounts in Codex without signing in again every time you switch. Each account uses its own Codex authentication profile, while projects, configuration, and local conversation history remain shared.

Use either `cam` or `codex-account-manager` — both commands are identical.

## What it does

- Import an existing Codex login without signing in again, including automatic migration from `~/.codex/auth.json` to the native Linux keyring.
- Cycle through accounts with `cam switch`, select one with `cam switch NAME`, and resume existing sessions.
- Share session history, `AGENTS.md`, skills, rules, and `config.toml` across accounts.
- Let Codex store and refresh account credentials using the native OS keyring. During file-backed login migration, tokens stream directly from the existing file into the keyring without an extra plaintext copy.
- Back up and restore Codex data, optionally encrypting the backup with GPG.

Account switching is **manual**, not automatic on quota exhaustion. Stop the current Codex session before switching; an interrupted model request is not transferred mid-generation.

## Requirements

- Linux with a working, unlocked OS keyring (for example, GNOME Keyring).
- Codex CLI installed and available as `codex` in `PATH`, with support for `cli_auth_credentials_store = "keyring"` and `CODEX_SQLITE_HOME`.
- Python 3.11 or newer (standard library only).
- `libsecret-tools` (`secret-tool`) to migrate an existing file-backed Codex login (Ubuntu: `sudo apt install libsecret-tools`).
- GnuPG (`gpg`) for encrypted backups.

## Installation

From the project directory:

```bash
./install.sh
cam init
```

The installer creates `~/.local/bin/cam` and `~/.local/bin/codex-account-manager`. Make sure `~/.local/bin` is on your `PATH`.

`cam init` configures native keyring authentication in `~/.codex/config.toml` and preserves existing Codex sessions. If `~/.codex/auth.json` contains your current login, initialization **migrates it automatically** using the Linux Secret Service and verifies it with Codex in keyring-only mode before deleting the plaintext file. The original file and configuration are retained if migration fails. Close all Codex processes first, and ensure your desktop keyring is unlocked.

To migrate separately, run `cam migrate-auth`. It is safe to run when there is no file-backed login; it then makes no changes.

## Usage

### Register accounts

```bash
cam import-current personal  # Import existing login, migrating auth.json if necessary
cam add second               # Authenticate the second account once
cam list                     # List accounts (* marks the active one)
cam remove wrong-name        # Unregister a profile without deleting shared data
cam import-current correct   # Re-import the existing ~/.codex login under a new name
```

`cam import-current NAME` also performs the one-time secure migration if `~/.codex/auth.json` is present. No browser reauthentication is normally required. Migration never sends token values through CLI arguments, environment variables, terminal output, or a second plaintext file. It fails closed if the keyring is unavailable, Codex cannot verify the keyring entry, the credential file is unsafe, or a different login is already stored under the same keyring identity. The original file remains in place on failure.

If migration reports `auth.json is readable by other users`, first run `chmod 600 ~/.codex/auth.json` and retry. If it cannot find `secret-tool`, install `libsecret-tools` and make sure GNOME Keyring is unlocked.

For device-code sign-in, use `cam add second --device-auth`.

To correct the name of an imported login, use `cam remove wrong-name` followed by
`cam import-current correct`. This reuses your original `~/.codex` keyring login
without reauthentication. For a separately added account, use `cam add correct`
after removal; **the new profile path requires a new sign-in**.

### Switch accounts and continue a session

```bash
cam run                      # Start Codex with the active account
# Exit Codex before switching
cam switch                  # Rotate to the next registered account
cam switch --resume         # Rotate and resume the newest session for this project
cam switch second --resume  # Switch to a specific account and resume
cam switch personal         # Switch to a specific account without opening Codex
cam resume                   # Resume the newest session for this project
cam resume <SESSION_ID>      # Resume a specific session
```

Unnamed switching follows registration order and wraps around after the last
account (A → B → C → A). `cam list` shows the rotation order. If no account is
selected, unnamed switching selects the first account. At least two accounts
must be registered. Existing installations without saved order metadata initially
use alphabetical order; subsequently added accounts are appended.

The long command name works the same way:

```bash
codex-account-manager switch second --resume
```

Other commands:

| Command | Purpose |
| --- | --- |
| `cam init` | Configure keyring and migrate an existing `auth.json`, if present |
| `cam migrate-auth` | Migrate existing file-backed login to keyring without signing in |
| `cam import-current NAME` | Import the current login, migrating file-backed auth if necessary |
| `cam add NAME` | Create an account profile and sign in |
| `cam relogin NAME` | Sign in again if an account's login expires or is revoked |
| `cam remove NAME` | Unregister a profile without deleting shared sessions or keyring credentials |
| `cam remove NAME --forget-login` | Also log out a non-imported profile from the native keyring |
| `cam list` | List saved profiles and the active profile |
| `cam switch` | Select the next account in registration order (wraps around) |
| `cam switch --resume` | Rotate to the next account and resume a local session |
| `cam switch NAME` | Select an account without starting Codex |
| `cam switch NAME --resume` | Select an account and resume a local session |
| `cam run [ARGS...]` | Run Codex with the selected account; pass through Codex arguments |
| `cam resume [SESSION_ID]` | Resume a project session (or a specified session) |
| `cam doctor` | Report profile configuration and possible plaintext credential files |
| `cam backup FILE` | Create a backup ZIP |
| `cam restore FILE` | Validate and restore a backup |

For example, `cam run exec "fix the failing tests"` passes `exec` and its arguments to Codex.

### Remove an account

```bash
cam list
cam remove wrong-name
cam add correct-name           # Sign in once for the replacement managed profile
# OR, for an imported original ~/.codex login:
cam import-current correct-name  # Reuses its existing keyring login
```

Remove requires all Codex processes to be stopped. The removed profile is moved
into `~/.local/share/codex-account-manager/removed-accounts/` (or the configured
`CAM_HOME`) instead of deleting unknown files. If it was active, no account is
selected until you explicitly switch or add an account. The original `~/.codex`
home, shared sessions, and Codex configuration are never removed.

By default, removal **does not delete native keyring credentials**. Use
`cam remove NAME --forget-login` to also run `codex logout` for a non-imported
profile. The tool intentionally refuses this flag for an imported `~/.codex`
account to avoid unexpectedly signing you out of your normal Codex installation.
Retired profile directories are excluded from backups; inspect and delete them
manually when no longer needed.

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

- Imported existing login uses its original `~/.codex` and keyring entry; additional accounts use separate `CODEX_HOME` paths and keyring entries. Shared session/configuration files are linked. File-backed credentials are only read for a one-time direct import to keyring, not copied to another plaintext file.
- Keyring storage protects credentials at rest, **not against malware operating within your unlocked user session**. Protect your device and backups accordingly.
- Exit Codex before account switching, backup, or restore. Running multiple Codex clients against shared state can cause inconsistent behavior; checks for unmanaged processes are best-effort.
- Cross-account session resumption depends on Codex's session format and may behave differently across Codex releases. Test with a disposable session before relying on it for critical work.
- Migration uses Codex's current Linux direct-keyring format (`service=Codex Auth`, `username=cli|…`). The tool verifies compatibility with your installed Codex version before removing `auth.json`. A later Codex release may change the keyring format, in which case migration stops without deleting the original login.
- The CLI is Linux-only. It does not automatically rotate accounts at quota limits.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests use a mock Codex executable and do not replace a live multi-account/keyring compatibility test.
