import json
from importlib.metadata import version as package_version
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class CLITests(unittest.TestCase):
    def test_installed_module_from_another_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app with spaces.bin'
            path.write_bytes(b'original data')
            def run(*args):
                return subprocess.run([sys.executable, '-m', 'tailmeta', *map(str, args)], cwd=directory, capture_output=True, text=True)
            self.assertEqual(run('read', path).returncode, 1)
            for version in ('1.2.4', '2.0'):
                result = run('stamp', path, '--version', version)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = run('read', path)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'version': version})
                self.assertEqual(run('read', path, '--version-only').stdout.strip(), version)
            self.assertEqual(f'tailmeta {package_version("tailmeta")}', run('--version').stdout.strip())
