import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'codex_account_manager.py'
spec = importlib.util.spec_from_file_location('cxa', SOURCE)
cxa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cxa)


class SecureCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.codex_home = self.root / 'codex'
        self.cxa_home = self.root / 'cxa'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.codex_home.mkdir()
        (self.codex_home / 'config.toml').write_text('model = "gpt-test"\ncli_auth_credentials_store = "file"\n[mcp_servers.local]\ncommand = "node"\n')
        self.mock = self.bin / 'codex'
        self.mock.write_text('#!/usr/bin/env python3\nimport sys,os,json,pathlib\n'
                             'pathlib.Path(os.environ["TEST_LOG"]).open("a").write(json.dumps({' 
                             '"cmd": sys.argv[1:], "home": os.environ["CODEX_HOME"], '
                             '"sqlite": os.environ["CODEX_SQLITE_HOME"]})+"\\n")\n')
        self.mock.chmod(0o755)
        self.log = self.root / 'log.jsonl'
        self.env = {**os.environ, 'CAM_CODEX_HOME': str(self.codex_home), 'CAM_HOME': str(self.cxa_home),
                    'PATH': f'{self.bin}:{os.environ.get("PATH", "")}', 'TEST_LOG': str(self.log)}

    def cmd(self, *args, success=True):
        result = subprocess.run([sys.executable, str(SOURCE), *args], env=self.env, text=True, capture_output=True)
        if success:
            self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        return result

    def events(self):
        return [json.loads(s) for s in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_installer_exposes_both_commands(self):
        home = self.root / 'fake-user'
        home.mkdir()
        installed = subprocess.run(['bash', str(SOURCE.parent / 'install.sh')],
                                   env={**os.environ, 'HOME': str(home)},
                                   capture_output=True, text=True)
        self.assertEqual(installed.returncode, 0, installed.stderr)
        for alias in ('cam', 'codex-account-manager'):
            executable = home / '.local/bin' / alias
            self.assertTrue(executable.is_file())
            self.assertTrue(os.access(executable, os.X_OK))
            output = subprocess.run([str(executable), '--help'], text=True, capture_output=True)
            self.assertEqual(output.returncode, 0, output.stderr)
            self.assertIn('Codex multi-account', output.stdout)

    def test_previous_secure_install_keeps_storage_location(self):
        # Prior secure CLI used this root. Rebranding must not break logins.
        home = self.root / 'previous-home'
        legacy = home / '.local/share/cxa-secure'
        legacy.mkdir(parents=True)
        env = {**os.environ, 'HOME': str(home)}
        for key in ('CAM_HOME', 'CXA_HOME'):
            env.pop(key, None)
        result = subprocess.run([sys.executable, '-c',
                                 'import sys; sys.path.insert(0, sys.argv[1]); '
                                 'import codex_account_manager as m; print(m.manager_home())',
                                 str(SOURCE.parent)],
                                env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(legacy))

    def test_keyring_default_and_preserve_other_config(self):
        self.cmd('init')
        cfg = (self.codex_home / 'config.toml').read_text()
        self.assertIn('cli_auth_credentials_store = "keyring"', cfg)
        self.assertIn('command = "node"', cfg)
        self.assertIn('model = "gpt-test"', cfg)
        self.assertIn('cli_auth_credentials_store = "file"', (self.codex_home / 'config.toml.cxa-pre-keyring').read_text())

    def test_two_accounts_no_token_files_shared_sessions(self):
        self.cmd('init')
        self.cmd('add', 'first')
        self.cmd('add', 'second')
        self.assertEqual([x['cmd'] for x in self.events()], [['login'], ['login', 'status'], ['login'], ['login', 'status']])
        first = self.cxa_home / 'accounts' / 'first'
        second = self.cxa_home / 'accounts' / 'second'
        self.assertNotEqual(first, second)
        for name in ('first', 'second'):
            home = self.cxa_home / 'accounts' / name
            self.assertFalse((home / 'auth.json').exists())
            self.assertTrue((home / 'config.toml').is_symlink())
            self.assertEqual((home / 'sessions').resolve(), (self.codex_home / 'sessions').resolve())
        self.cmd('switch', 'first')
        self.cmd('run')
        ev = self.events()[-1]
        self.assertEqual(ev['home'], str(first))
        self.assertEqual(ev['sqlite'], str(self.codex_home))
        self.cmd('switch', 'second')
        self.cmd('run')
        self.assertEqual(self.events()[-1]['home'], str(second))
        self.assertFalse(any(self.cxa_home.rglob('auth.json')))

    def test_switch_without_name_rotates_in_registration_order_and_wraps(self):
        self.cmd('init')
        # These are intentionally not in alphabetical order.
        for name in ('zeta', 'alpha', 'beta'):
            self.cmd('add', name)
        self.assertEqual(self.cmd('list').stdout.splitlines(), ['  zeta', '  alpha', '* beta'])
        self.cmd('switch', 'zeta')
        for expected in ('alpha', 'beta', 'zeta', 'alpha'):
            self.assertIn(f'Active account: {expected}', self.cmd('switch').stdout)
            self.assertEqual(json.loads((self.cxa_home / 'active.json').read_text())['active'], expected)
            self.cmd('run')
            self.assertEqual(self.events()[-1]['home'], str(self.cxa_home / 'accounts' / expected))
        self.assertEqual(json.loads((self.cxa_home / 'account-order.json').read_text()),
                         ['zeta', 'alpha', 'beta'])

    def test_switch_no_name_with_resume_uses_next_profile(self):
        self.cmd('init')
        self.cmd('import-current', 'original')
        self.cmd('add', 'second')
        self.cmd('switch', 'original')
        result = self.cmd('switch', '--resume')
        self.assertIn('Active account: second', result.stdout)
        self.assertEqual(self.events()[-1]['cmd'], ['resume', '--last'])
        self.assertEqual(self.events()[-1]['home'], str(self.cxa_home / 'accounts/second'))
        self.cmd('switch', '--resume')
        self.assertEqual(self.events()[-1]['home'], str(self.codex_home))

    def test_switch_no_name_requires_at_least_two_accounts(self):
        self.cmd('init')
        fail = self.cmd('switch', success=False)
        self.assertIn('at least two', fail.stderr)
        self.cmd('add', 'only')
        fail = self.cmd('switch', success=False)
        self.assertIn('at least two', fail.stderr)
        self.assertEqual(json.loads((self.cxa_home / 'active.json').read_text())['active'], 'only')

    def test_switch_no_name_after_removal_and_no_active(self):
        self.cmd('init')
        for name in ('zeta', 'alpha', 'beta'):
            self.cmd('add', name)
        self.cmd('remove', 'beta')  # Last registered account was active.
        self.assertEqual(json.loads((self.cxa_home / 'active.json').read_text()), {'active': None})
        self.assertIn('Active account: zeta', self.cmd('switch').stdout)
        self.assertIn('Active account: alpha', self.cmd('switch').stdout)
        self.cmd('remove', 'zeta')
        self.cmd('add', 'gamma')
        # Newly registered account is appended even when its name sorts earlier.
        self.assertEqual(json.loads((self.cxa_home / 'account-order.json').read_text()),
                         ['alpha', 'gamma'])
        self.cmd('switch', 'alpha')
        self.assertIn('Active account: gamma', self.cmd('switch').stdout)

    def test_switch_no_name_does_not_select_unsafe_auth(self):
        self.cmd('init')
        self.cmd('add', 'first')
        self.cmd('add', 'second')
        self.cmd('switch', 'first')
        (self.cxa_home / 'accounts/second/auth.json').write_text('unexpected')
        self.assertNotEqual(self.cmd('switch', success=False).returncode, 0)
        self.assertEqual(json.loads((self.cxa_home / 'active.json').read_text())['active'], 'first')

    def test_preexisting_accounts_without_order_file_are_supported(self):
        self.cmd('init')
        for name in ('zeta', 'alpha'):
            self.cmd('add', name)
        # Earlier CLI releases did not have order metadata.
        (self.cxa_home / 'account-order.json').unlink()
        self.cmd('switch', 'alpha')
        self.assertIn('Active account: zeta', self.cmd('switch').stdout)
        self.cmd('add', 'beta')
        self.assertEqual(json.loads((self.cxa_home / 'account-order.json').read_text()),
                         ['alpha', 'zeta', 'beta'])
        self.cmd('switch', 'zeta')
        self.assertIn('Active account: beta', self.cmd('switch').stdout)

    def test_session_id_comes_from_canonical_shared_storage(self):
        self.cmd('init')
        self.cmd('add', 'first')
        self.cmd('add', 'second')
        parent = self.codex_home / 'sessions' / '2026' / '10' / '31'
        parent.mkdir(parents=True)
        session_id = '019e1f37-f41d-7092-a8a6-6133763ad522'
        (parent / f'rollout-2026-10-31-{session_id}.jsonl').write_text(json.dumps({
            'type': 'session_meta', 'payload': {'cwd': str(Path.cwd()), 'id': session_id}}) + '\n')
        self.cmd('switch', 'second', '--resume')
        self.assertEqual(self.events()[-1]['cmd'], ['resume', session_id])
        self.assertEqual(self.events()[-1]['home'], str(self.cxa_home / 'accounts' / 'second'))

    def test_import_current_uses_original_home_without_reauthentication(self):
        self.cmd('init')
        self.cmd('import-current', 'original')
        self.assertEqual([x['cmd'] for x in self.events()], [['login', 'status']])
        self.assertEqual(self.events()[0]['home'], str(self.codex_home))
        marker = self.cxa_home / 'accounts/original/canonical-home.json'
        self.assertEqual(json.loads(marker.read_text()), {'use_canonical_home': True})
        self.cmd('run')
        self.assertEqual(self.events()[-1]['home'], str(self.codex_home))
        self.cmd('add', 'secondary')
        self.cmd('switch', 'secondary')
        self.cmd('run')
        self.assertEqual(self.events()[-1]['home'], str(self.cxa_home / 'accounts/secondary'))
        self.cmd('switch', 'original')
        self.cmd('run')
        self.assertEqual(self.events()[-1]['home'], str(self.codex_home))
        self.assertFalse(any(x['cmd'] == ['login'] and x['home'] == str(self.codex_home) for x in self.events()))
        self.assertEqual(self.cmd('import-current', 'duplicate', success=False).returncode, 1)

    def test_remove_active_profile_preserves_shared_data_and_other_account(self):
        self.cmd('init')
        self.cmd('add', 'typo')
        self.cmd('add', 'second')
        self.cmd('switch', 'typo')
        sessions = self.codex_home / 'sessions'
        (sessions / 'important.jsonl').write_text('original work')
        profile = self.cxa_home / 'accounts/typo'
        (profile / 'local-cache.txt').write_text('local data')
        result = self.cmd('remove', 'typo')
        self.assertIn("Removed account 'typo'", result.stdout)
        self.assertFalse(profile.exists())
        self.assertIn('second', self.cmd('list').stdout)
        self.assertNotIn('typo', self.cmd('list').stdout)
        self.assertEqual(json.loads((self.cxa_home / 'active.json').read_text()), {'active': None})
        self.assertEqual((sessions / 'important.jsonl').read_text(), 'original work')
        self.assertTrue((self.codex_home / 'config.toml').exists())
        archive = list((self.cxa_home / 'removed-accounts').glob('typo-*'))
        self.assertEqual(len(archive), 1)
        self.assertEqual((archive[0] / 'local-cache.txt').read_text(), 'local data')
        self.assertTrue((archive[0] / 'sessions').is_symlink())
        self.assertNotIn(['logout'], [x['cmd'] for x in self.events()])
        self.cmd('add', 'correct')
        self.assertIn('correct', self.cmd('list').stdout)
        self.cmd('switch', 'second')
        self.cmd('run')
        self.assertEqual(self.events()[-1]['home'], str(self.cxa_home / 'accounts/second'))

    def test_remove_imported_then_reimport_correct_name_without_login(self):
        self.cmd('init')
        self.cmd('import-current', 'typo')
        self.cmd('remove', 'typo')
        self.cmd('import-current', 'correct')
        self.cmd('run')
        self.assertEqual(self.events()[-1]['home'], str(self.codex_home))
        commands = [x['cmd'] for x in self.events()]
        self.assertEqual(commands.count(['login']), 0)
        self.assertEqual(commands.count(['login', 'status']), 2)
        self.assertNotIn(['logout'], commands)
        self.assertIn('correct', self.cmd('list').stdout)
        self.assertNotIn('typo', self.cmd('list').stdout)

    def test_remove_inactive_does_not_change_active(self):
        self.cmd('init')
        self.cmd('add', 'first')
        self.cmd('add', 'second')
        self.cmd('remove', 'first')
        self.assertEqual(json.loads((self.cxa_home / 'active.json').read_text()), {'active': 'second'})
        self.cmd('run')
        self.assertEqual(self.events()[-1]['home'], str(self.cxa_home / 'accounts/second'))

    def test_remove_managed_with_optional_logout(self):
        self.cmd('init')
        self.cmd('add', 'managed')
        self.cmd('remove', 'managed', '--forget-login')
        self.assertEqual(self.events()[-1]['cmd'], ['logout'])
        self.assertEqual(self.events()[-1]['home'], str(self.cxa_home / 'accounts/managed'))
        self.assertFalse((self.cxa_home / 'accounts/managed').exists())

    def test_remove_imported_refuses_to_logout_original(self):
        self.cmd('init')
        self.cmd('import-current', 'original')
        result = self.cmd('remove', 'original', '--forget-login', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Refusing --forget-login', result.stderr)
        self.assertTrue((self.cxa_home / 'accounts/original').is_dir())
        self.assertFalse(any(x['cmd'] == ['logout'] for x in self.events()))
        self.cmd('run')
        self.assertEqual(self.events()[-1]['home'], str(self.codex_home))

    def test_remove_invalid_unknown_symlink_and_logout_failure(self):
        self.cmd('init')
        self.cmd('add', 'managed')
        for label in ('absent', '../managed'):
            self.assertNotEqual(self.cmd('remove', label, success=False).returncode, 0)
        self.assertTrue((self.cxa_home / 'accounts/managed').is_dir())
        # Logout errors must not unregister the profile.
        self.mock.write_text(self.mock.read_text() + '\nif sys.argv[1:] == ["logout"]: sys.exit(2)\n')
        result = self.cmd('remove', 'managed', '--forget-login', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.cxa_home / 'accounts/managed').is_dir())
        # Even if the logout mock is failing, regular safe removal remains available.
        self.cmd('remove', 'managed')

    def test_remove_disallows_plaintext_auth(self):
        self.cmd('init')
        self.cmd('add', 'first')
        path = self.cxa_home / 'accounts/first/auth.json'
        path.write_text('DO_NOT_COPY')
        failure = self.cmd('remove', 'first', success=False)
        self.assertNotEqual(failure.returncode, 0)
        self.assertTrue(path.exists())
        self.assertFalse((self.cxa_home / 'removed-accounts').exists())

    def test_import_current_refuses_existing_auth_json_without_reading_it(self):
        secret = self.codex_home / 'auth.json'
        secret.write_text('DO_NOT_READ_OR_DELETE')
        self.cmd('init', success=False)
        result = self.cmd('import-current', 'original', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('auth.json', result.stderr)
        self.assertEqual(secret.read_text(), 'DO_NOT_READ_OR_DELETE')
        self.assertFalse((self.cxa_home / 'accounts/original/canonical-home.json').exists())

    def test_import_current_refuses_missing_keyring_login(self):
        self.cmd('init')
        # Mock `codex login status` failure; must not create account metadata.
        self.mock.write_text(self.mock.read_text() + '\nif sys.argv[1:] == ["login", "status"]: sys.exit(1)\n')
        result = self.cmd('import-current', 'original', success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.cxa_home / 'accounts/original').exists())

    def test_fail_closed_on_profile_plaintext(self):
        self.cmd('init')
        self.cmd('add', 'first')
        (self.cxa_home / 'accounts' / 'first' / 'auth.json').write_text('SENSITIVE')
        self.assertNotEqual(self.cmd('run', success=False).returncode, 0)

    def test_reject_file_mode_regression(self):
        self.cmd('init')
        self.cmd('add', 'first')
        (self.codex_home / 'config.toml').write_text('cli_auth_credentials_store = "auto"\n')
        self.assertNotEqual(self.cmd('run', success=False).returncode, 0)

    def test_no_legacy_auth_deleted(self):
        (self.codex_home / 'auth.json').write_text('legacy')
        original = (self.codex_home / 'config.toml').read_text()
        failure = self.cmd('init', success=False)
        self.assertNotEqual(failure.returncode, 0)
        self.assertEqual((self.codex_home / 'auth.json').read_text(), 'legacy')
        self.assertEqual((self.codex_home / 'config.toml').read_text(), original)
        self.assertIn('plaintext credentials', self.cmd('doctor').stdout)


if __name__ == '__main__':
    unittest.main()
