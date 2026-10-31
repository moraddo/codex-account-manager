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
        self.cmd('init')
        self.assertEqual((self.codex_home / 'auth.json').read_text(), 'legacy')
        self.assertIn('plaintext credentials', self.cmd('doctor').stdout)


if __name__ == '__main__':
    unittest.main()
