import json
from importlib.metadata import version as package_version
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CLITests(unittest.TestCase):
    def _run(self, directory, *args):
        return subprocess.run(
            [sys.executable, '-m', 'tailmeta', *map(str, args)],
            cwd=directory,
            capture_output=True,
            text=True,
        )

    def test_installed_module_from_another_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app with spaces.bin'
            path.write_bytes(b'original data')
            run = lambda *args: self._run(directory, *args)
            self.assertEqual(run('read', path).returncode, 1)
            for version in ('1.2.4', '2.0'):
                result = run('stamp', path, '--version', version)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = run('read', path)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'version': version})
                self.assertEqual(run('read', path, '--version-only').stdout.strip(), version)
            self.assertEqual(f'tailmeta {package_version("tailmeta")}', run('--version').stdout.strip())

    def test_keygen_stamp_verify_and_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'app.bin'
            private = root / 'private.pem'
            public = root / 'public.pem'
            path.write_bytes(b'original data')
            run = lambda *args: self._run(directory, *args)

            result = run('keygen', '--private-key', private, '--public-key', public)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(private.is_file())
            self.assertTrue(public.is_file())

            result = run(
                'stamp', path,
                '--version', '1.2.4',
                '--channel', 'stable',
                '--commit', 'abc123',
                '--private-key', private,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            result = run('verify', path, '--public-key', public)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload['version'], '1.2.4')
            self.assertEqual(payload['channel'], 'stable')
            self.assertEqual(payload['commit'], 'abc123')
            self.assertNotIn('signature', payload)

            other = root / 'other.bin'
            other.write_bytes(b'original data')
            result = run('stamp', other, '--version', '1', '--channel', 'a\x1b[31m\x9b\u2028\U000e0001тест')
            self.assertEqual(result.returncode, 0, result.stderr)
            result = run('read', other)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotRegex(result.stdout.strip(), '[\x00-\x1f\x7f-\x9f\u2028\U000e0001]')
            self.assertIn('тест', result.stdout)
            self.assertEqual(json.loads(result.stdout)['channel'], 'a\x1b[31m\x9b\u2028\U000e0001тест')

            missing = run('verify', path, '--public-key', root / 'missing.pem')
            self.assertEqual(missing.returncode, 1)
            self.assertIn('error:', missing.stderr)

            absent = run('stamp', root / 'missing.bin', '--version', '1')
            self.assertEqual(absent.returncode, 1)
            self.assertIn('error:', absent.stderr)
