"""Round-trip and adversarial validation of the CLI's file backup format."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile

SOURCE = Path(__file__).resolve().parents[1] / 'codex_account_manager.py'
spec = importlib.util.spec_from_file_location('cam_impl', SOURCE)
cam = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cam)


class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory()
        self.addCleanup(self.workspace.cleanup)
        self.base = Path(self.workspace.name)
        self.codex = self.base / 'codex'
        self.manager = self.base / 'manager'
        self.codex.mkdir()
        (self.codex / 'config.toml').write_text('cli_auth_credentials_store = "keyring"\nmodel = "test"\n')
        self.env = {**os.environ, 'CAM_CODEX_HOME': str(self.codex), 'CAM_HOME': str(self.manager)}
        self.zip = self.base / 'backup.zip'
        self.sessions = self.codex / 'sessions/2026/10/31'
        self.sessions.mkdir(parents=True)
        (self.sessions / 'session.jsonl').write_text('hello\n')
        (self.codex / 'AGENTS.md').write_text('Test agent instructions\n')
        self.manager.mkdir()
        (self.manager / 'accounts/test/config.toml').parent.mkdir(parents=True)
        (self.manager / 'accounts/test/config.toml').symlink_to(self.codex / 'config.toml')
        (self.manager / 'active.json').write_text('{"active":"test"}')

    def cmd(self, *args, success=True):
        r = subprocess.run([sys.executable, str(SOURCE), *args], env=self.env, capture_output=True, text=True)
        if success:
            self.assertEqual(r.returncode, 0, r.stderr + '\n' + r.stdout)
        return r

    def test_round_trip_restore_both_roots_and_profile_links(self):
        (self.codex / 'auth.json').write_text('OAUTH_SECRET')
        (self.codex / '.env').write_text('MCP_TOKEN=SECRET')
        (self.manager / 'accounts/test/auth.json').write_text('OAUTH_PROFILE')
        self.cmd('backup', str(self.zip))
        with zipfile.ZipFile(self.zip) as z:
            names = z.namelist()
            self.assertIn('codex/config.toml', names)
            self.assertIn('codex/AGENTS.md', names)
            self.assertIn('manager/active.json', names)
            self.assertIn('codex/sessions/2026/10/31/session.jsonl', names)
            self.assertNotIn('codex/auth.json', names)
            self.assertNotIn('codex/.env', names)
            self.assertFalse(any(n.endswith('/auth.json') for n in names))
            self.assertNotIn(b'OAUTH_SECRET', self.zip.read_bytes())
            self.assertNotIn(b'OAUTH_PROFILE', self.zip.read_bytes())
        self.assertEqual(self.zip.stat().st_mode & 0o777, 0o600)

        (self.codex / 'AGENTS.md').write_text('modified\n')
        (self.sessions / 'session.jsonl').unlink()
        (self.manager / 'accounts/test/config.toml').unlink()
        self.cmd('restore', str(self.zip))
        self.assertEqual((self.codex / 'AGENTS.md').read_text(), 'Test agent instructions\n')
        self.assertEqual((self.sessions / 'session.jsonl').read_text(), 'hello\n')
        self.assertEqual((self.codex / 'auth.json').read_text(), 'OAUTH_SECRET')
        self.assertTrue((self.manager / 'accounts/test/config.toml').is_symlink())
        snapshot_dir = self.manager / 'restore-snapshots'
        self.assertEqual(len(list(snapshot_dir.glob('*.zip'))), 1)
        with zipfile.ZipFile(next(snapshot_dir.glob('*.zip'))) as z:
            self.assertIn(b'modified', z.read('codex/AGENTS.md'))
            self.assertNotIn('codex/auth.json', z.namelist())

    def test_backup_restore_remembers_canonical_profile_mapping(self):
        canonical = self.manager / 'accounts/test/canonical-home.json'
        canonical.write_text('{"use_canonical_home": true}\n')
        canonical.chmod(0o600)
        self.cmd('backup', str(self.zip))
        with zipfile.ZipFile(self.zip) as z:
            manifest = json.loads(z.read('manifest.json'))
            self.assertEqual(manifest['canonical_accounts'], ['test'])
            self.assertNotIn('manager/accounts/test/canonical-home.json', z.namelist())
        canonical.unlink()
        self.cmd('restore', str(self.zip))
        self.assertEqual(json.loads(canonical.read_text()), {'use_canonical_home': True})

    def test_dry_run_does_not_change_anything(self):
        self.cmd('backup', str(self.zip))
        (self.codex / 'AGENTS.md').write_text('different')
        result = self.cmd('restore', str(self.zip), '--dry-run')
        self.assertIn('DRY RUN', result.stdout)
        self.assertEqual((self.codex / 'AGENTS.md').read_text(), 'different')
        self.assertFalse((self.manager / 'restore-snapshots').exists())

    def test_nonmatching_hash_aborts_before_writing(self):
        self.cmd('backup', str(self.zip))
        with zipfile.ZipFile(self.zip) as z:
            manifest = json.loads(z.read('manifest.json'))
            data = {i.filename: z.read(i.filename) for i in z.infolist() if i.filename != 'manifest.json'}
        data['codex/AGENTS.md'] = b'!' * len(data['codex/AGENTS.md'])
        with zipfile.ZipFile(self.zip, 'w') as z:
            for n, value in data.items():
                info = zipfile.ZipInfo(n)
                info.create_system = 3
                info.external_attr = (0o100600 << 16)
                z.writestr(info, value)
            z.writestr('manifest.json', json.dumps(manifest))
        (self.codex / 'AGENTS.md').write_text('unchanged current file')
        result = self.cmd('restore', str(self.zip), success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Checksum mismatch', result.stderr)
        self.assertEqual((self.codex / 'AGENTS.md').read_text(), 'unchanged current file')

    def test_zip_slip_and_auth_json_rejected(self):
        for bad_name in ('codex/../../escape', 'codex/auth.json', 'manager/accounts/test/.env'):
            with self.subTest(bad_name=bad_name):
                value = b'danger'
                manifest = {'schema': cam.BACKUP_SCHEMA, 'roots': {}, 'accounts': [], 'files': {
                    bad_name: {'sha256': hashlib.sha256(value).hexdigest(), 'size': len(value)}}}
                with zipfile.ZipFile(self.zip, 'w') as z:
                    info = zipfile.ZipInfo(bad_name)
                    info.external_attr = (0o100600 << 16)
                    z.writestr(info, value)
                    z.writestr('manifest.json', json.dumps(manifest))
                result = self.cmd('restore', str(self.zip), success=False)
                self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / 'escape').exists())

    def test_symlink_destination_rejected(self):
        self.cmd('backup', str(self.zip))
        outside = self.base / 'outside'
        outside.write_text('safe')
        (self.codex / 'AGENTS.md').unlink()
        (self.codex / 'AGENTS.md').symlink_to(outside)
        result = self.cmd('restore', str(self.zip), success=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('symlink', result.stderr.lower())
        self.assertEqual(outside.read_text(), 'safe')

    def test_sqlite_backup_is_restorable(self):
        db = self.codex / 'state_5.sqlite'
        with sqlite3.connect(db) as conn:
            conn.execute('CREATE TABLE items (item TEXT)')
            conn.execute('INSERT INTO items VALUES (?)', ('original',))
        self.cmd('backup', str(self.zip))
        with zipfile.ZipFile(self.zip) as z:
            self.assertIn('codex/state_5.sqlite', z.namelist())
        with sqlite3.connect(db) as conn:
            conn.execute('UPDATE items SET item = ?', ('modified',))
        self.cmd('restore', str(self.zip))
        with sqlite3.connect(db) as conn:
            result = conn.execute('SELECT item FROM items').fetchone()[0]
        self.assertEqual(result, 'original')

    def test_encrypted_zip_command_flow_with_mock_gpg(self):
        # Test that the CLI invokes encryption and decrypts before ZIP validation.
        fake_bin = self.base / 'fake-bin'
        fake_bin.mkdir()
        gpg = fake_bin / 'gpg'
        gpg.write_text('#!/usr/bin/env python3\n'
                       'import sys, shutil\n'
                       'args = sys.argv[1:]\n'
                       'shutil.copyfile(args[-1], args[args.index("--output")+1])\n')
        gpg.chmod(0o700)
        self.env['PATH'] = f'{fake_bin}:{os.environ.get("PATH", "")}'
        encrypted = self.base / 'backup.zip.gpg'
        self.cmd('backup', str(encrypted), '--encrypt')
        self.assertTrue(encrypted.exists())
        (self.codex / 'AGENTS.md').write_text('overwritten')
        self.cmd('restore', str(encrypted))
        self.assertEqual((self.codex / 'AGENTS.md').read_text(), 'Test agent instructions\n')

    def test_external_sqlite_snapshot_and_paths(self):
        sql_home = self.base / 'external-state'
        sql_home.mkdir()
        (self.codex / 'config.toml').write_text(
            f'cli_auth_credentials_store = "keyring"\nsqlite_home = "{sql_home}"\n')
        db = sql_home / 'state_5.sqlite'
        with sqlite3.connect(db) as conn:
            conn.execute('CREATE TABLE state (n INTEGER)')
            conn.execute('INSERT INTO state VALUES (8)')
        (sql_home / 'unrelated.sqlite').write_bytes(b'not a sqlite database')
        self.cmd('backup', str(self.zip))
        with zipfile.ZipFile(self.zip) as z:
            self.assertIn('sqlite/state_5.sqlite', z.namelist())
            self.assertNotIn('sqlite/unrelated.sqlite', z.namelist())
        with sqlite3.connect(db) as conn:
            conn.execute('UPDATE state SET n = 9')
        self.cmd('restore', str(self.zip))
        with sqlite3.connect(db) as conn:
            self.assertEqual(conn.execute('SELECT n FROM state').fetchone()[0], 8)

    @unittest.skipUnless(os.environ.get('CAM_TEST_REAL_GPG'),
                         'Real GPG integration test is optional; set CAM_TEST_REAL_GPG=1')
    def test_encrypted_backup_restore_with_real_gpg(self):
        import shutil
        actual_gpg = shutil.which('gpg')
        if not actual_gpg:
            self.skipTest('GnuPG not installed')
        fake_bin = self.base / 'fake-bin'
        fake_bin.mkdir()
        script = fake_bin / 'gpg'
        # Only in the test, use a deterministic passphrase to avoid GUI prompts.
        script.write_text(f'#!/bin/sh\nexec "{actual_gpg}" --batch --pinentry-mode loopback '
                          '--passphrase test-password "$@"\n')
        script.chmod(0o700)
        gnupg = self.base / 'gnupg'
        gnupg.mkdir(mode=0o700)
        self.env['GNUPGHOME'] = str(gnupg)
        self.env['PATH'] = f'{fake_bin}:{os.environ.get("PATH", "")}'
        encrypted = self.base / 'backup.zip.gpg'
        self.cmd('backup', str(encrypted), '--encrypt')
        self.assertNotIn(b'Test agent instructions', encrypted.read_bytes())
        (self.codex / 'AGENTS.md').write_text('overwritten')
        self.cmd('restore', str(encrypted), '--dry-run')
        self.cmd('restore', str(encrypted))
        self.assertEqual((self.codex / 'AGENTS.md').read_text(), 'Test agent instructions\n')

    def test_backup_no_overwrite_without_explicit_flag(self):
        self.cmd('backup', str(self.zip))
        original = self.zip.read_bytes()
        r = self.cmd('backup', str(self.zip), success=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.zip.read_bytes(), original)
        self.cmd('backup', str(self.zip), '--overwrite')


if __name__ == '__main__':
    unittest.main()
