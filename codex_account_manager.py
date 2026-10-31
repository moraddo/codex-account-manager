#!/usr/bin/env python3
"""Codex Account Manager: native keyring per account; shared session data.

Linux only. Existing file-backed logins can be streamed directly into the
OS keyring using secret-tool, without logging or persisting extra token copies.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib

LABEL = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$")
# Only data that is safe to share between profile homes. No auth/MCP token files.
SHARED_DIRS = ("sessions", "archived_sessions", "skills", "rules", "memories", "prompts", "plugins")
SHARED_FILES = ("history.jsonl", "session_index.jsonl", "AGENTS.md", "hooks.json")
CONF_KEY = "cli_auth_credentials_store"
CANONICAL_MARKER = "canonical-home.json"  # Metadata only; never stores credentials
ORDER_FILE = "account-order.json"  # Registration order; no credentials


class CxaError(Exception):
    pass


def root_home() -> Path:
    override = os.environ.get("CAM_CODEX_HOME") or os.environ.get("CXA_CODEX_HOME")
    return Path(override or Path.home() / ".codex").expanduser().absolute()


def manager_home() -> Path:
    override = os.environ.get("CAM_HOME") or os.environ.get("CXA_HOME")
    if override:
        return Path(override).expanduser().absolute()
    # Keep existing keyring identities working after upgrading from the old name.
    # Moving CODEX_HOME profile paths might otherwise require reauthentication.
    modern = Path.home() / ".local/share/codex-account-manager"
    legacy = Path.home() / ".local/share/cxa-secure"
    return (modern if modern.exists() or not legacy.exists() else legacy).absolute()


def profile_home(name: str) -> Path:
    if not LABEL.fullmatch(name):
        raise CxaError("Account name must use 1–48 letters, digits, underscores or hyphens")
    return manager_home() / "accounts" / name


def private_dir(path: Path) -> None:
    if path.is_symlink():
        raise CxaError(f"Symlinked private directory is not allowed: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    if info.st_uid != os.getuid() or not stat.S_ISDIR(info.st_mode):
        raise CxaError(f"Unsafe directory owner/type: {path}")
    if info.st_mode & 0o077:
        path.chmod(0o700)


def atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise CxaError(f"Refusing to replace symlink: {path}")
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".cam-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)


def _configure_keyring() -> None:
    """Configure native keyring without modifying any credential file."""
    private_dir(root_home())
    private_dir(manager_home())
    private_dir(manager_home() / "accounts")
    for folder in SHARED_DIRS[:2]:
        (root_home() / folder).mkdir(exist_ok=True)
    config = root_home() / "config.toml"
    if config.is_symlink():
        raise CxaError("Refusing to modify symlinked Codex config")
    data = config.read_text("utf-8") if config.exists() else ""
    try:
        existing = tomllib.loads(data)
    except tomllib.TOMLDecodeError as exc:
        raise CxaError(f"Invalid Codex configuration: {exc}") from exc
    if existing.get(CONF_KEY) != "keyring":
        # Top-level TOML fields only exist before first table header.
        lines = data.splitlines(keepends=True)
        section = next((i for i, ln in enumerate(lines) if ln.lstrip().startswith("[")), len(lines))
        matches = [i for i in range(section) if re.match(r'^\s*cli_auth_credentials_store\s*=', lines[i])]
        if len(matches) > 1:
            raise CxaError("Duplicate keyring storage config")
        if matches:
            lines[matches[0]] = 'cli_auth_credentials_store = "keyring"\n'
            updated = "".join(lines)
        else:
            updated = 'cli_auth_credentials_store = "keyring"\n' + data
        if tomllib.loads(updated).get(CONF_KEY) != "keyring":
            raise CxaError("Could not configure keyring mode safely")
        if config.exists():
            backup = root_home() / "config.toml.cxa-pre-keyring"
            if not backup.exists():
                # Configuration can contain MCP secrets: protect the backup.
                fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as out:
                    out.write(data.encode())
        atomic_write(config, updated.encode())
        print(f"Set cli_auth_credentials_store=keyring in {config}")
    else:
        print("Codex already configured to use the native OS keyring")
    print("Codex credential files are unchanged by configuration; use 'cam doctor' for security checks.")




def _auth_environment() -> dict[str, str]:
    """Ensure authentication checks cannot succeed via an injected API key."""
    env = dict(os.environ)
    env["CODEX_HOME"] = str(root_home())
    env["CODEX_SQLITE_HOME"] = str(shared_sqlite_home())
    for key in ("OPENAI_API_KEY", "CODEX_API_KEY", "CODEX_HOME_OVERRIDE"):
        env.pop(key, None)
    return env


def _codex_auth_status(mode: str) -> bool:
    try:
        result = subprocess.run(
            [codex(), "-c", f'{CONF_KEY}="{mode}"', "login", "status"],
            env=_auth_environment(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=25,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CxaError(f"Unable to check Codex {mode}-backed authentication: {type(exc).__name__}") from exc
    return result.returncode == 0


def _keyring_account_key() -> str:
    # Codex key: sha256(canonical CODEX_HOME path)[:16], prefixed by 'cli|'.
    digest = hashlib.sha256(str(root_home().resolve()).encode("utf-8")).hexdigest()[:16]
    return "cli|" + digest


def _keyring_attributes() -> list[str]:
    # Codex's Linux direct keyring backend uses keyring-rs/Secret Service.
    return ["service", "Codex Auth", "username", _keyring_account_key()]


def _secret_tool(*args: str, stdin=None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["secret-tool", *args], stdin=stdin, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CxaError(f"OS keyring operation failed: {type(exc).__name__}") from exc


def migrate_auth_json() -> None:
    """Migrate ~/.codex/auth.json using the Linux Secret Service, without re-login.

    This is intentionally fail-closed. No auth file is removed until Codex
    independently verifies the new keyring entry. We never pass tokens through
    argv, environment, terminal output, logs, or temporary files.
    """
    path = root_home() / "auth.json"
    if not os.path.lexists(path):
        return
    if root_home().is_symlink():
        raise CxaError("Refusing symlinked Codex home")
    reject_running_codex()
    if shutil.which("secret-tool") is None:
        raise CxaError("Install Linux keyring utilities: sudo apt install libsecret-tools. "
                       "Original auth.json was not changed.")
    config = root_home() / "config.toml"
    if config.is_symlink():
        raise CxaError("Refusing symlinked Codex config")
    if config.exists():
        parsed = tomllib.loads(config.read_text("utf-8"))
        if parsed.get("auth_keyring_backend_kind", "direct") != "direct":
            raise CxaError("Migration supports only Codex's native Linux direct keyring backend")

    # An existing keyring entry might represent a different account. Never overwrite.
    lookup = _secret_tool("lookup", *_keyring_attributes())
    # libsecret returns status 1 with no stderr if a key does not exist;
    # failure to contact the service also returns 1, but reports stderr.
    if lookup.returncode not in (0, 1) or lookup.stderr or (lookup.returncode == 0 and not lookup.stdout):
        raise CxaError("Cannot inspect the OS keyring (is it unlocked?). "
                       "Original auth.json was not changed.")
    existing_keyring_secret = lookup.stdout  # Never log or write this secret.
    del lookup

    # Open without following links; reject suspicious ownership or non-regular files.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise CxaError(f"Refusing unsafe auth.json: {exc.strerror}") from exc
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise CxaError("auth.json must be a regular file owned by the current user")
        if info.st_mode & 0o077:
            raise CxaError("auth.json is readable by other users. Run chmod 600 ~/.codex/auth.json "
                           "and retry; no credentials were copied.")
        if info.st_size == 0 or info.st_size > 1024 * 1024:
            raise CxaError("Unexpected auth.json size; refusing migration")
        if not _codex_auth_status("file"):
            raise CxaError("Codex cannot verify the existing file login. "
                           "Original auth.json was not changed.")
        # If an earlier migration was interrupted, allow retry only when
        # the existing keyring secret is byte-for-byte equal to the file.
        if existing_keyring_secret:
            source.seek(0)
            if source.read() != existing_keyring_secret:
                raise CxaError("Codex already has a different keyring entry for this home. "
                               "Refusing to overwrite it or delete auth.json.")
            print("Matching Codex keyring entry found; completing earlier migration...", flush=True)
        previous_config = config.read_bytes() if config.exists() else None
        created_keyring_entry = False
        try:
            if not existing_keyring_secret:
                source.seek(0)
                print("Moving existing Codex login into native Linux keyring...", flush=True)
                saved = _secret_tool("store", "--label=Codex Auth", *_keyring_attributes(), stdin=source)
                if saved.returncode:
                    raise CxaError("OS keyring rejected the credentials; auth.json was preserved. "
                                   "Check that your desktop keyring is unlocked.")
                created_keyring_entry = True
            # Codex must read this specific keyring entry with file fallback disabled.
            if not _codex_auth_status("keyring"):
                raise CxaError("Codex could not verify keyring-only login; "
                               "auth.json was preserved. Check your Codex version/backend.")
            _configure_keyring()
            if not _codex_auth_status("keyring"):
                raise CxaError("Keyring login failed after configuration change; "
                               "auth.json was preserved.")
            # Detect any unexpected concurrent credential refresh or replacement.
            current = path.lstat()
            if (current.st_ino, current.st_size, current.st_mtime_ns) != (info.st_ino, info.st_size, info.st_mtime_ns):
                raise CxaError("auth.json changed during migration; refusing deletion")
            reject_running_codex()
            path.unlink()
        except (CxaError, OSError):
            # Keep the previous file-based login intact on every failure.
            if path.exists():
                try:
                    if previous_config is None:
                        if config.exists():
                            config.unlink()
                    elif config.exists() and config.read_bytes() != previous_config:
                        atomic_write(config, previous_config)
                except OSError:
                    print("WARNING: Could not restore config.toml; original auth.json still exists.",
                          file=sys.stderr)
                if created_keyring_entry:
                    # Remove only the entry that *this invocation* created.
                    cleanup = _secret_tool("clear", *_keyring_attributes())
                    if cleanup.returncode:
                        print("WARNING: Could not roll back new keyring entry.", file=sys.stderr)
            raise
    print("Migrated login to native keyring; removed the original plaintext auth.json.")


def initialize() -> None:
    if os.path.lexists(root_home() / "auth.json"):
        migrate_auth_json()
    if os.path.lexists(root_home() / "auth.json"):
        raise CxaError("auth.json still exists; refusing insecure initialization")
    _configure_keyring()

def shared_sqlite_home() -> Path:
    config = root_home() / "config.toml"
    parsed = tomllib.loads(config.read_text("utf-8")) if config.exists() else {}
    path = parsed.get("sqlite_home") or os.environ.get("CODEX_SQLITE_HOME")
    if path is not None:
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise CxaError("sqlite_home must be an absolute path")
        return Path(path)
    return root_home()


def validate_config() -> None:
    config = root_home() / "config.toml"
    if not config.exists():
        raise CxaError("Run 'cam init' before using the CLI")
    parsed = tomllib.loads(config.read_text("utf-8"))
    if parsed.get(CONF_KEY) != "keyring":
        raise CxaError("Codex must use 'keyring' storage (never 'auto' or 'file'); run 'cam init'")


def link_shared(home: Path) -> None:
    for name in ("config.toml",) + SHARED_DIRS + SHARED_FILES:
        src, dst = root_home() / name, home / name
        if name != "config.toml" and not src.exists() and not src.is_symlink():
            continue
        if dst.is_symlink():
            if dst.resolve(strict=False) != src.resolve(strict=False):
                raise CxaError(f"Wrong shared symlink target: {dst}")
        elif dst.exists():
            raise CxaError(f"Cannot link shared state: {dst} already exists")
        else:
            dst.symlink_to(src, target_is_directory=src.is_dir())
    # session rolls and index DB must be shared. Do not link whole homes:
    # that would also share credential files.


def setup_profile(name: str) -> Path:
    validate_config()
    home = profile_home(name)
    private_dir(manager_home())
    private_dir(manager_home() / "accounts")
    private_dir(home)
    link_shared(home)
    return home


def is_canonical_profile(name: str) -> bool:
    """A managed name may use the existing ~/.codex keyring identity in-place."""
    marker = profile_home(name) / CANONICAL_MARKER
    if not marker.exists():
        return False
    if marker.is_symlink() or not marker.is_file() or marker.stat().st_mode & 0o077:
        raise CxaError(f"Unsafe canonical profile metadata: {marker}")
    try:
        value = json.loads(marker.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise CxaError(f"Invalid canonical profile metadata: {marker}") from exc
    if value != {"use_canonical_home": True}:
        raise CxaError(f"Invalid canonical profile metadata: {marker}")
    return True


def account_home(name: str) -> Path:
    home = profile_home(name)
    return root_home() if is_canonical_profile(name) else home


def import_current(name: str) -> None:
    """Adopt an existing native-keyring login without reading/copying its tokens."""
    with lock():
        if os.path.lexists(root_home() / "auth.json"):
            initialize()  # Includes safe file-to-keyring migration when needed.
        validate_config()
        reject_running_codex()
        if name in account_names():
            raise CxaError(f"Profile '{name}' already exists")
        if any(is_canonical_profile(other) for other in account_names()):
            raise CxaError("The canonical Codex login is already imported")
        env = dict(os.environ)
        env["CODEX_HOME"] = str(root_home())
        env["CODEX_SQLITE_HOME"] = str(shared_sqlite_home())
        env.pop("OPENAI_API_KEY", None)
        check = subprocess.run([codex(), "login", "status"], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if check.returncode:
            raise CxaError("No working native-keyring login found under ~/.codex. "
                           "Nothing was imported; your existing Codex login was not changed.")
        previous = account_names()
        home = setup_profile(name)
        atomic_write(home / CANONICAL_MARKER, b'{"use_canonical_home": true}\n')
        save_account_order(previous + [name])
        set_active(name)
        print(f"Imported existing native-keyring account as '{name}' without reauthentication")


def read_account_order() -> list[str]:
    """Persist rotation order independently of the active account.

    Pre-existing installations without metadata fall back to alphabetical order.
    Subsequent registrations append to that order, without renaming profiles.
    """
    path = manager_home() / ORDER_FILE
    if not path.exists() and not path.is_symlink():
        return []
    if (path.is_symlink() or not path.is_file()
            or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077):
        raise CxaError(f"Unsafe account-order metadata: {path}")
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise CxaError(f"Invalid account-order metadata: {path}") from exc
    if (not isinstance(value, list)
            or any(not isinstance(n, str) or not LABEL.fullmatch(n) for n in value)
            or len(value) != len(set(value))):
        raise CxaError(f"Invalid account-order metadata: {path}")
    return value


def account_names() -> list[str]:
    parent = manager_home() / "accounts"
    if not parent.is_dir():
        return []
    current = sorted(p.name for p in parent.iterdir()
                     if p.is_dir() and not p.is_symlink() and LABEL.fullmatch(p.name)
                     and (p / "config.toml").is_symlink())
    saved = read_account_order()
    return [n for n in saved if n in current] + [n for n in current if n not in saved]


def save_account_order(names: list[str]) -> None:
    if len(names) != len(set(names)) or any(not LABEL.fullmatch(n) for n in names):
        raise CxaError("Invalid account registration order")
    atomic_write(manager_home() / ORDER_FILE, (json.dumps(names) + "\n").encode("utf-8"))


def get_active() -> str | None:
    file = manager_home() / "active.json"
    if not file.exists():
        return None
    if file.is_symlink() or file.stat().st_uid != os.getuid() or file.stat().st_mode & 0o077:
        raise CxaError("Unsafe active-account metadata")
    value = json.loads(file.read_text("utf-8")).get("active")
    if value is None:
        return None
    profile_home(value)
    return value


def set_active(name: str | None) -> None:
    atomic_write(manager_home() / "active.json", json.dumps({"active": name}).encode())


@contextmanager
def lock():
    private_dir(manager_home())
    path = manager_home() / ".lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CxaError("Another managed Codex session is active. Exit it before switching.") from exc
        yield
    finally:
        os.close(fd)


def codex() -> str:
    path = shutil.which("codex")
    if path is None:
        raise CxaError("Codex CLI not found in PATH")
    return path


def environment(name: str) -> dict[str, str]:
    profile = profile_home(name)
    if not profile.is_dir() or profile.is_symlink():
        raise CxaError(f"Unknown profile: {name}")
    validate_config()
    link_shared(profile)
    home = account_home(name)
    env = dict(os.environ)
    # The canonical account retains its original keyring key, which Codex
    # derives from CODEX_HOME. No OAuth token is read or copied by cam.
    env["CODEX_HOME"] = str(home)
    env["CODEX_SQLITE_HOME"] = str(shared_sqlite_home())
    # Avoid accidental API-key override of the stored ChatGPT account.
    env.pop("OPENAI_API_KEY", None)
    return env


def ensure_no_plaintext(name: str) -> None:
    locations = (profile_home(name) / "auth.json", account_home(name) / "auth.json")
    for path in locations:
        if os.path.lexists(path):
            raise CxaError(f"FAIL CLOSED: unexpected plaintext auth.json: {path}; check managed Codex policy and remove it safely")


def login(name: str, device_auth: bool = False) -> None:
    if name in account_names():
        raise CxaError(f"Profile '{name}' already exists. Use 'cam relogin {name}' to reauthenticate it")
    with lock():
        previous = account_names()
        if name in previous:
            raise CxaError(f"Profile '{name}' already exists")
        home = setup_profile(name)
        env = environment(name)
        command = [codex(), "login"] + (["--device-auth"] if device_auth else [])
        print(f"Signing in once for '{name}' with native keyring; no token files will be copied.", flush=True)
        result = subprocess.run(command, env=env)
        ensure_no_plaintext(name)
        if result.returncode:
            raise CxaError("Login did not succeed; you can retry with 'cam relogin NAME'")
        check = subprocess.run([codex(), "login", "status"], env=env)
        if check.returncode:
            raise CxaError("Codex did not confirm the keyring login; account not activated")
        save_account_order(previous + [name])
        set_active(name)
        print(f"Saved account '{name}' in Codex's native OS keyring")


def relogin(name: str, device_auth: bool = False) -> None:
    if name not in account_names():
        raise CxaError(f"Unknown account {name}")
    with lock():
        env = environment(name)
        result = subprocess.run([codex(), "login"] + (["--device-auth"] if device_auth else []), env=env)
        ensure_no_plaintext(name)
        if result.returncode:
            raise CxaError("Codex login failed")


def switch(name: str | None = None) -> None:
    with lock():
        names = account_names()
        if name is None:
            if len(names) < 2:
                raise CxaError("Account rotation requires at least two accounts; use 'cam add NAME'")
            current = get_active()
            # If no account is selected, start at the first registered profile.
            name = names[(names.index(current) + 1) % len(names)] if current in names else names[0]
        elif name not in names:
            raise CxaError(f"Unknown account '{name}'; run 'cam add {name}'")
        ensure_no_plaintext(name)
        set_active(name)
    print(f"Active account: {name}")


def remove_account(name: str, *, forget_login: bool = False) -> None:
    """Unregister an account while preserving profile data and shared Codex state.

    Archiving rather than unlinking prevents accidental loss of user files that
    Codex or its plugins may have placed inside a profile home. The original
    ~/.codex is never touched for an imported account.
    """
    profile_home(name)  # Validate before filesystem operations.
    with lock():
        reject_running_codex()
        if name not in account_names():
            raise CxaError(f"Unknown account '{name}'")
        if forget_login and is_canonical_profile(name):
            raise CxaError("Refusing --forget-login for an imported account: that would log out "
                           "the original ~/.codex login. Remove the registration without "
                           "--forget-login, or use native 'codex logout' separately.")
        ensure_no_plaintext(name)
        home = profile_home(name)
        if home.is_symlink() or not home.is_dir() or home.stat().st_uid != os.getuid():
            raise CxaError(f"Unsafe account profile: {home}")
        was_active = get_active() == name
        # Logging out, if explicitly requested, happens BEFORE archiving so
        # Codex can still locate its keyring identity using the old CODEX_HOME.
        if forget_login:
            result = subprocess.run([codex(), 'logout'], env=environment(name))
            if result.returncode != 0:
                raise CxaError("Codex logout failed; account registration was not removed")
        retired_root = manager_home() / 'removed-accounts'
        private_dir(retired_root)
        retired = retired_root / f'{name}-{secrets.token_hex(8)}'
        if os.path.lexists(retired):
            raise CxaError(f'Refusing existing archived destination: {retired}')
        # Same-filesystem rename: never follow profile-local shared symlinks.
        os.rename(home, retired)
        try:
            # Keep the order compact; re-adding an account appends it at the end.
            save_account_order([n for n in account_names() if n != name])
            if was_active:
                set_active(None)
        except Exception:
            os.rename(retired, home)
            raise
        print(f"Removed account '{name}' from Codex Account Manager.")
        print(f"Preserved its profile files at: {retired}")
        if was_active:
            print('No active account selected; use `cam switch NAME` or `cam add NAME`.')
        if forget_login:
            print('The managed Codex profile was logged out of its native keyring.')
        else:
            print('Existing OS-keyring credentials were not deleted or exported.')


def newest_session(cwd: Path) -> str | None:
    root = root_home() / "sessions"
    if not root.exists():
        return None
    # Prefer matching cwd rather than a session from an unrelated project.
    candidates = sorted(root.rglob("rollout-*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in candidates:
        try:
            with path.open("r", encoding="utf-8") as f:
                # Usually the first record is session_meta, but tolerate leading events.
                for _ in range(4):
                    line = f.readline(16000)
                    if not line:
                        break
                    item = json.loads(line)
                    payload = item.get("payload", {})
                    if item.get("type") == "session_meta" and Path(payload.get("cwd", "")).resolve() == cwd.resolve():
                        sid = payload.get("id")
                        if isinstance(sid, str) and re.fullmatch(r"[0-9a-fA-F-]{36}", sid):
                            return sid
        except (ValueError, OSError, TypeError):
            continue
    return None


def run(kind: str, arguments: list[str]) -> int:
    with lock():
        name = get_active()
        if name is None:
            raise CxaError("No account selected. Run 'cam add NAME' first")
        ensure_no_plaintext(name)
        env = environment(name)
        command = [codex()]
        if kind == "resume":
            command.append("resume")
            if not arguments:
                session = newest_session(Path.cwd())
                if session:
                    arguments = [session]
                else:
                    # Native --last behavior if the shared record has no matching cwd.
                    arguments = ["--last"]
        command += arguments
        print(f"Codex profile: {name}", flush=True)
        result = subprocess.run(command, env=env)
        ensure_no_plaintext(name)
        return result.returncode


def doctor() -> None:
    print(f"Canonical shared Codex home: {root_home()}")
    print(f"Account profiles (token-free): {manager_home() / 'accounts'}")
    try:
        print(f"Native credentials backend: {tomllib.loads((root_home() / 'config.toml').read_text()) .get(CONF_KEY)}")
    except (OSError, ValueError):
        print("Native credentials backend: UNKNOWN (run cam init)")
    print(f"Shared SQLite home: {shared_sqlite_home()}")
    print(f"Active profile: {get_active() or 'none'}")
    print(f"Accounts: {', '.join(account_names()) or 'none'}")
    imported = [name for name in account_names() if is_canonical_profile(name)]
    print(f"Imported native login: {', '.join(imported) if imported else 'none'}")
    leaks = [root_home() / "auth.json"] + [profile_home(n) / "auth.json" for n in account_names()]
    legacy_dir = Path.home() / ".local/share/cxa/profiles"
    if legacy_dir.exists():
        leaks.extend(legacy_dir.rglob("auth.json"))
    found = [p for p in leaks if os.path.lexists(p)]
    if found:
        for p in found:
            print(f"WARNING: plaintext credentials still exist at {p}")
        print("After verifying keyring logins, remove legacy token files; check backup/snapshot copies too.")
    else:
        print("No plaintext auth.json files found at managed locations")
    print("OS keyring security still requires a trusted, malware-free user session.")


# --- Backup / restore implementation ---
# Deliberately not archiving operating-system keyring credentials.
import datetime as dt
import hashlib
import io
import sqlite3
import zipfile
from pathlib import PurePosixPath

BACKUP_SCHEMA = 'codex-account-manager-backup-v1'
BACKUP_EXCLUDED_DIRS = {'.git', 'tmp', 'temp', 'cache', 'logs', 'restore-snapshots', 'backups', '__pycache__'}
BACKUP_EXCLUDED_FILES = {'auth.json', '.credentials.json', 'credentials.json', 'secrets.json', '.env', '.lock'}
SQLITE_SUFFIXES = ('.sqlite', '.sqlite3', '.db')
MAX_RESTORE_FILES = 200_000
MAX_RESTORE_BYTES = 50 * 1024**3  # 50 GiB upper bound for archive extraction


def sensitive_name(name: str) -> bool:
    lower = name.lower()
    return (lower in BACKUP_EXCLUDED_FILES or lower.startswith('.env.')
            or lower.endswith(('.pem', '.p12', '.pfx', '.key'))
            or lower.endswith(('-wal', '-shm', '-journal'))
            or lower.startswith(('token-', 'secret-', 'credentials-')))


def is_database(path: Path) -> bool:
    return path.suffix.lower() in SQLITE_SUFFIXES


def is_relative_to(path: Path, ancestor: Path) -> bool:
    return path == ancestor or ancestor in path.parents


def walk_backup_files(source: Path, prefix: str, exclude: set[Path] | None = None):
    if source.is_symlink():
        raise CxaError(f'Refusing symlinked backup root: {source}')
    if not source.exists():
        return
    exclude = exclude or set()
    for folder, directories, files in os.walk(source, topdown=True, followlinks=False):
        current = Path(folder)
        # Do not dereference arbitrary links or external mounts through symlinks.
        directories[:] = sorted(n for n in directories
                                if n not in BACKUP_EXCLUDED_DIRS
                                and not (current / n).is_symlink())
        for filename in sorted(files):
            path = current / filename
            if path in exclude or sensitive_name(filename) or path.is_symlink():
                continue
            try:
                if not path.is_file() or not stat.S_ISREG(path.lstat().st_mode):
                    continue
            except OSError as exc:
                raise CxaError(f'Cannot inspect {path}: {exc}') from exc
            relative = path.relative_to(source).as_posix()
            if prefix == 'manager' and relative not in ('active.json', ORDER_FILE):
                # Account profiles are represented by manifest names. Other
                # profile-local files could contain Codex/MCP login material.
                continue
            if prefix == 'sqlite' and not (filename.startswith('state') and is_database(path)):
                continue
            yield f'{prefix}/{relative}', path


def database_snapshot(source: Path, destination: Path) -> None:
    """Use SQLite online backup API to capture a consistent DB, including WAL."""
    uri = source.resolve().as_uri() + '?mode=ro'
    try:
        with sqlite3.connect(uri, uri=True, timeout=10) as src:
            with sqlite3.connect(destination) as dst:
                src.backup(dst, pages=256, sleep=0.1)
    except sqlite3.Error as exc:
        raise CxaError(f'SQLite snapshot failed for {source}: {exc}') from exc


def add_zip_file(archive: zipfile.ZipFile, arcname: str, source: Path) -> dict:
    mode = stat.S_IMODE(source.stat().st_mode) & 0o700
    info = zipfile.ZipInfo(arcname, date_time=(2020, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | (0o700 if mode & 0o100 else 0o600)) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    digest = hashlib.sha256()
    size = 0
    with source.open('rb') as input_file, archive.open(info, 'w', force_zip64=True) as output:
        for data in iter(lambda: input_file.read(1024 * 1024), b''):
            digest.update(data)
            size += len(data)
            output.write(data)
    return {'sha256': digest.hexdigest(), 'size': size,
            'executable': bool(mode & 0o100)}


def ensure_backup_output(path: Path, *, overwrite: bool, internal: bool = False) -> None:
    if path.is_symlink() or (path.exists() and not overwrite):
        raise CxaError(f'Backup already exists or is a symlink: {path}')
    if not internal and (is_relative_to(path.absolute(), root_home())
                         or is_relative_to(path.absolute(), manager_home())):
        raise CxaError('Choose a backup destination outside the Codex and manager homes')
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise CxaError(f'Refusing symlinked destination directory: {path.parent}')


def backup_zip(destination: Path, *, overwrite: bool = False, internal: bool = False) -> None:
    ensure_backup_output(destination, overwrite=overwrite, internal=internal)
    fd, temp_name = tempfile.mkstemp(prefix='.cam-backup-', suffix='.zip', dir=destination.parent)
    os.fchmod(fd, 0o600)
    os.close(fd)
    temporary = Path(temp_name)
    try:
        sqlite_root = shared_sqlite_home()
        roots = [('codex', root_home()), ('manager', manager_home())]
        if sqlite_root != root_home():
            roots.append(('sqlite', sqlite_root))
        manifest = {'schema': BACKUP_SCHEMA, 'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
                    'roots': {name: str(path) for name, path in roots},
                    'accounts': account_names(),
                    'canonical_accounts': [n for n in account_names() if is_canonical_profile(n)],
                    'files': {},
                    'note': 'No keyring credentials, auth.json, .env, key files, or transient data.'}
        seen = set()
        with zipfile.ZipFile(temporary, 'w', allowZip64=True) as archive:
            with tempfile.TemporaryDirectory(prefix='cam-sqlite-') as tmp:
                for prefix, home in roots:
                    for archive_name, source in walk_backup_files(home, prefix, {destination, temporary}):
                        if archive_name in seen:
                            raise CxaError(f'Duplicate backup path: {archive_name}')
                        seen.add(archive_name)
                        if is_database(source):
                            snapshot = Path(tmp) / f'database-{len(seen)}.sqlite'
                            database_snapshot(source, snapshot)
                            manifest['files'][archive_name] = add_zip_file(archive, archive_name, snapshot)
                        else:
                            manifest['files'][archive_name] = add_zip_file(archive, archive_name, source)
            archive.writestr('manifest.json', json.dumps(manifest, sort_keys=True, indent=2).encode())
        os.replace(temporary, destination)
        destination.chmod(0o600)
        print(f'Backup: {destination} ({len(seen)} files, 0600 permissions)')
    finally:
        temporary.unlink(missing_ok=True)


def atomic_restore_file(source: Path, destination: Path, executable: bool) -> None:
    if destination.is_symlink():
        raise CxaError(f"Refusing to overwrite symlink: {destination}")
    private_dir(destination.parent)
    fd, temp_name = tempfile.mkstemp(prefix='.cam-restore-', dir=destination.parent)
    temp = Path(temp_name)
    try:
        os.fchmod(fd, 0o700 if executable else 0o600)
        with os.fdopen(fd, 'wb') as output, source.open('rb') as input_file:
            shutil.copyfileobj(input_file, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, destination)
    finally:
        temp.unlink(missing_ok=True)


def gpg_process(args: list[str]) -> None:
    executable = shutil.which('gpg')
    if not executable:
        raise CxaError('GnuPG is required for --encrypt or encrypted restore (install: sudo apt install gnupg)')
    try:
        result = subprocess.run([executable, '--yes', *args])
    except OSError as exc:
        raise CxaError(f'Cannot run GnuPG: {exc}') from exc
    if result.returncode:
        raise CxaError('GnuPG encryption/decryption failed; no existing backup was changed')


def backup(destination: Path, *, overwrite: bool = False, encrypt: bool = False) -> None:
    destination = destination.expanduser().absolute()
    with lock():
        reject_running_codex()
        if not encrypt:
            backup_zip(destination, overwrite=overwrite)
            print('SECURITY: ZIP is NOT encrypted. Config, session text and MCP settings can contain secrets.')
            print('Use `cam backup FILE.zip.gpg --encrypt` for passphrase-encrypted backup.')
            return
        ensure_backup_output(destination, overwrite=overwrite)
        with tempfile.TemporaryDirectory(prefix='cam-encrypted-') as tmp:
            plain = Path(tmp) / 'backup.zip'
            backup_zip(plain, internal=True)
            fd, dest_name = tempfile.mkstemp(prefix='.cam-encrypted-', dir=destination.parent)
            os.fchmod(fd, 0o600)
            os.close(fd)
            encrypted = Path(dest_name)
            try:
                gpg_process(['--symmetric', '--cipher-algo', 'AES256', '--output', str(encrypted), str(plain)])
                os.replace(encrypted, destination)
                destination.chmod(0o600)
                print(f'Encrypted backup: {destination}')
            finally:
                encrypted.unlink(missing_ok=True)


def safe_entry_name(name: str) -> tuple[str, Path]:
    if '\\' in name or '\x00' in name or name.startswith('/'):
        raise CxaError(f'Invalid ZIP entry: {name!r}')
    parts = name.split('/')
    if len(parts) < 2 or any(n in ('', '.', '..') for n in parts):
        raise CxaError(f'Unsafe ZIP entry: {name!r}')
    prefix = parts[0]
    if prefix not in ('codex', 'manager', 'sqlite'):
        raise CxaError(f'Unexpected ZIP root: {name!r}')
    if any(sensitive_name(part) for part in parts[1:]):
        raise CxaError(f'ZIP includes forbidden credential/transient path: {name!r}')
    if any(part in BACKUP_EXCLUDED_DIRS for part in parts[1:]):
        raise CxaError(f'ZIP includes excluded cache/backup path: {name!r}')
    return prefix, Path(*parts[1:])


def inspect_archive(archive: zipfile.ZipFile) -> dict:
    infos = archive.infolist()
    names = [i.filename for i in infos]
    if len(names) != len(set(names)) or names.count('manifest.json') != 1:
        raise CxaError('Backup ZIP has duplicate entries or no unique manifest')
    if archive.getinfo('manifest.json').file_size > 32 * 1024 * 1024:
        raise CxaError('Backup manifest is too large')
    try:
        manifest = json.loads(archive.read('manifest.json'))
    except (json.JSONDecodeError, KeyError, UnicodeDecodeError) as exc:
        raise CxaError(f'Invalid backup manifest: {exc}') from exc
    if manifest.get('schema') != BACKUP_SCHEMA or not isinstance(manifest.get('files'), dict):
        raise CxaError('Not a compatible Codex Account Manager backup')
    files = manifest['files']
    if len(files) > MAX_RESTORE_FILES or sum(i.file_size for i in infos) > MAX_RESTORE_BYTES:
        raise CxaError('Backup exceeds restore safety limits')
    if set(names) != set(files) | {'manifest.json'}:
        raise CxaError('Archive entries do not match manifest')
    for info in infos:
        if info.filename == 'manifest.json':
            continue
        safe_entry_name(info.filename)
        mode = info.external_attr >> 16
        if info.is_dir() or (mode and not stat.S_ISREG(mode)):
            raise CxaError(f'Archive contains a non-regular file: {info.filename}')
        data = files[info.filename]
        if (not isinstance(data, dict) or not isinstance(data.get('size'), int)
                or data['size'] != info.file_size
                or not isinstance(data.get('sha256'), str)
                or not re.fullmatch('[0-9a-f]{64}', data['sha256'])):
            raise CxaError(f'Manifest checksum/size invalid: {info.filename}')
    accounts = manifest.get('accounts')
    if not isinstance(accounts, list) or len(accounts) != len(set(accounts)):
        raise CxaError('Invalid account list in manifest')
    for name in accounts:
        if not isinstance(name, str) or not LABEL.fullmatch(name):
            raise CxaError('Invalid account name in manifest')
    canonical = manifest.get('canonical_accounts', [])
    if (not isinstance(canonical, list)
            or any(not isinstance(name, str) or name not in accounts for name in canonical)
            or len(canonical) != len(set(canonical)) or len(canonical) > 1):
        raise CxaError('Invalid canonical account mapping in manifest')
    return manifest


def guarded_destination(root: Path, relative: Path) -> Path:
    if root.is_symlink():
        raise CxaError(f'Restore root is a symlink: {root}')
    current = root
    for segment in relative.parts:
        current = current / segment
        if current.is_symlink():
            raise CxaError(f'Refusing to restore through symlink: {current}')
    if current.exists() and not current.is_file():
        raise CxaError(f'Restore destination is not a regular file: {current}')
    return current


def check_restore_roots(manifest: dict) -> dict[str, Path]:
    target = {'codex': root_home(), 'manager': manager_home()}
    if any(name.startswith('sqlite/') for name in manifest['files']):
        sqlite_root = shared_sqlite_home()
        saved = manifest.get('roots', {}).get('sqlite')
        if not saved or sqlite_root == root_home():
            raise CxaError('Archive has external SQLite data but current config has no external sqlite_home')
        if str(sqlite_root) != saved:
            raise CxaError(f'External sqlite_home differs: backup={saved}, current={sqlite_root}. '
                           'Restore on the original path or adjust config before restoring.')
        target['sqlite'] = sqlite_root
    for path in target.values():
        if path.is_symlink():
            raise CxaError(f'Refusing symlinked restore destination: {path}')
    return target


def reject_running_codex() -> None:
    """Best-effort extra guard; lock already stops other cam commands."""
    proc = Path('/proc')
    if not proc.is_dir():
        return
    for task in proc.iterdir():
        if not task.name.isdecimal() or int(task.name) == os.getpid():
            continue
        try:
            if task.stat().st_uid != os.getuid():
                continue
            cmdline = (task / 'cmdline').read_bytes().split(b'\x00')
            if not cmdline or not cmdline[0]:
                continue
            exe = Path(os.fsdecode(cmdline[0])).name
            if exe in ('codex', 'codex-linux', 'codex-app-server'):
                raise CxaError(f'Codex process {task.name} is running; exit Codex before restoring')
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue


def restore(archive_path: Path, *, dry_run: bool = False) -> None:
    archive_path = archive_path.expanduser().absolute()
    if not archive_path.is_file():
        raise CxaError(f'Backup file not found: {archive_path}')
    with lock():
        reject_running_codex()
        with tempfile.TemporaryDirectory(prefix='cam-restore-', dir=None) as tmp:
            zip_path = archive_path
            if archive_path.suffix.lower() == '.gpg':
                zip_path = Path(tmp) / 'decrypted.zip'
                gpg_process(['--decrypt', '--output', str(zip_path), str(archive_path)])
                zip_path.chmod(0o600)
            try:
                archive = zipfile.ZipFile(zip_path)
            except (zipfile.BadZipFile, OSError) as exc:
                raise CxaError(f'Invalid ZIP backup: {exc}') from exc
            with archive:
                manifest = inspect_archive(archive)
                targets = check_restore_roots(manifest)
                planned: list[tuple[Path, Path, bool]] = []
                stage = Path(tmp) / 'staging'
                stage.mkdir(mode=0o700)
                for name, metadata in manifest['files'].items():
                    prefix, relative = safe_entry_name(name)
                    destination = guarded_destination(targets[prefix], relative)
                    staged = stage / name
                    staged.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    digest = hashlib.sha256()
                    with archive.open(name) as reader, staged.open('xb') as writer:
                        for chunk in iter(lambda: reader.read(1024 * 1024), b''):
                            digest.update(chunk)
                            writer.write(chunk)
                    if digest.hexdigest() != metadata['sha256']:
                        raise CxaError(f'Checksum mismatch: {name}')
                    planned.append((staged, destination, bool(metadata.get('executable'))))
                # Refuse a source archive that would force Codex back to insecure auth mode.
                conf = stage / 'codex/config.toml'
                if conf.exists():
                    try:
                        cfg = tomllib.loads(conf.read_text('utf-8'))
                    except (OSError, ValueError) as exc:
                        raise CxaError(f'Invalid config.toml in backup: {exc}') from exc
                    if cfg.get(CONF_KEY) != 'keyring':
                        raise CxaError('Backup does not use keyring credential mode; refusing unsafe restore')
                if dry_run:
                    print(f'DRY RUN: archive valid; would restore {len(planned)} files, '
                          f'{len(manifest["accounts"])} account profiles')
                    for prefix, target in targets.items():
                        print(f'  {prefix}/ -> {target}')
                    print('No files changed.')
                    return
                # Keep a recovery ZIP of the current state before changing *any* files.
                snapshot_dir = manager_home() / 'restore-snapshots'
                private_dir(snapshot_dir)
                timestamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
                recovery = snapshot_dir / f'before-restore-{timestamp}.zip'
                backup_zip(recovery, internal=True)
                print(f'Pre-restore safety backup: {recovery}')
                try:
                    for staged, dest, executable in planned:
                        guarded_destination(dest.parent, Path(dest.name))
                        if is_database(dest):
                            # A restored SQLite snapshot must never be replayed
                            # against old WAL or rollback-journal files.
                            for suffix in ('-wal', '-shm', '-journal'):
                                sidecar = Path(str(dest) + suffix)
                                if sidecar.is_symlink():
                                    raise CxaError(f'Refusing SQLite sidecar symlink: {sidecar}')
                                if sidecar.exists():
                                    if not sidecar.is_file():
                                        raise CxaError(f'Unsafe SQLite sidecar: {sidecar}')
                                    sidecar.unlink()
                        atomic_restore_file(staged, dest, executable)
                    for name in manifest['accounts']:
                        setup_profile(name)
                        marker = profile_home(name) / CANONICAL_MARKER
                        if name in manifest.get('canonical_accounts', []):
                            atomic_write(marker, b'{"use_canonical_home": true}\n')
                        elif marker.exists():
                            marker.unlink()
                    if f'manager/{ORDER_FILE}' not in manifest['files']:
                        # Backups created before rotation had no order file.
                        save_account_order(manifest['accounts'])
                except (OSError, CxaError) as exc:
                    raise CxaError(f'Restore stopped after partial changes: {exc}. '
                                   f'Original state was saved to {recovery}') from exc
                print(f'Restored {len(planned)} files and {len(manifest["accounts"])} profile(s).')
                print('Keyring credentials were NOT restored. On another computer, run `cam relogin NAME`.')
                print('Use `cam doctor` to check restored profiles and legacy plaintext token files.')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cam", description="Codex multi-account switcher using native OS keyring")
    subs = parser.add_subparsers(dest="action", required=True)
    subs.add_parser("init", help="Initialize keyring; automatically migrate an existing auth.json")
    subs.add_parser("migrate-auth", help="Migrate existing auth.json to native keyring without signing in")
    for name in ("add", "relogin"):
        p = subs.add_parser(name)
        p.add_argument("name")
        p.add_argument("--device-auth", action="store_true")
    p = subs.add_parser("import-current", help="Adopt the existing native-keyring login under ~/.codex")
    p.add_argument("name")
    p = subs.add_parser("switch", help="Switch to NAME, or rotate to the next registered account")
    p.add_argument("name", nargs="?", help="Account name (omit to cycle through accounts)")
    p.add_argument("--resume", action="store_true")
    p = subs.add_parser("remove", help="Unregister an account without deleting shared sessions")
    p.add_argument("name")
    p.add_argument("--forget-login", action="store_true",
                   help="Also run native Codex logout for a managed (not imported) profile")
    subs.add_parser("list")
    subs.add_parser("doctor")
    bp = subs.add_parser("backup", help="Back up Codex state to ZIP (credentials excluded)")
    bp.add_argument("file", nargs="?", help="Destination .zip or .zip.gpg")
    bp.add_argument("--encrypt", action="store_true", help="Encrypt ZIP using GnuPG AES-256")
    bp.add_argument("--overwrite", action="store_true", help="Replace an existing backup")
    rp = subs.add_parser("restore", help="Restore Codex state from ZIP or encrypted ZIP")
    rp.add_argument("file", help="Backup ZIP file to restore")
    rp.add_argument("--dry-run", action="store_true", help="Verify ZIP and list destinations without modifying anything")
    subs.add_parser("run")
    subs.add_parser("resume")
    args, trailing = parser.parse_known_args(argv)
    if trailing and args.action not in ("run", "resume"):
        parser.error("unexpected arguments: " + " ".join(trailing))
    try:
        if sys.platform != "linux":
            raise CxaError("Linux only")
        if args.action == "init":
            with lock():
                initialize()
        elif args.action == "migrate-auth":
            with lock():
                if os.path.lexists(root_home() / "auth.json"):
                    migrate_auth_json()
                else:
                    print("No auth.json found; nothing to migrate.")
        elif args.action == "add":
            login(args.name, args.device_auth)
        elif args.action == "import-current":
            import_current(args.name)
        elif args.action == "relogin":
            relogin(args.name, args.device_auth)
        elif args.action == "switch":
            switch(args.name)
            if args.resume:
                return run("resume", [])
        elif args.action == "remove":
            remove_account(args.name, forget_login=args.forget_login)
        elif args.action == "list":
            print("\n".join(("* " if n == get_active() else "  ") + n for n in account_names()))
        elif args.action == "doctor":
            doctor()
        elif args.action == "backup":
            suffix = ".zip.gpg" if args.encrypt else ".zip"
            default = f"codex-backup-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}{suffix}"
            backup(Path(args.file or default), overwrite=args.overwrite, encrypt=args.encrypt)
        elif args.action == "restore":
            restore(Path(args.file), dry_run=args.dry_run)
        else:
            return run(args.action, trailing)
        return 0
    except (CxaError, OSError, ValueError, tomllib.TOMLDecodeError,
            zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        print(f"cam: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
