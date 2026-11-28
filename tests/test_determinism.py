"""Different ways of writing the same metadata must produce byte-identical files.

Every scenario starts from the same original bytes and ends with the same
metadata and format, so the resulting SHA-256 has to match regardless of the
path taken (API or CLI, key order, restamping, format conversion, strip).
"""
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tailmeta import stamp, strip
from tailmeta._core import encode_footer, encode_metadata

META = {'version': '1.2.4', 'channel': 'stable', 'commit': 'abc123', 'build': {'os': 'linux', 'n': 7}}
FLAGS = ['--version', '1.2.4', '--channel', 'stable', '--commit', 'abc123']
HAS_SIGNING = bool(importlib.util.find_spec('cryptography'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class DeterminismTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)
        self.base = self.dir / 'base.bin'
        self.base.write_bytes(b'\x7fELF\x00' + bytes(range(256)) * 64 + 'TAILMETA тест'.encode())
        self.counter = 0
        self.files = {}
        for name, value in {
            'indented': json.dumps(META, indent=4),
            'reversed': json.dumps(dict(reversed(list(META.items())))),
            'other': json.dumps({**META, 'version': '9.9.9', 'commit': 'zzz'}),
            'partial': json.dumps({'build': META['build']}),
        }.items():
            path = self.dir / f'{name}.json'
            path.write_text(value, encoding='utf-8')
            self.files[name] = path
        self.key = None
        if HAS_SIGNING:
            from tailmeta import generate_keys
            generate_keys(self.dir / 'key.pem', self.dir / 'key.pub')
            self.key = str(self.dir / 'key.pem')

    def fresh(self):
        self.counter += 1
        path = self.dir / f'copy{self.counter}.bin'
        shutil.copy(self.base, path)
        return path

    def cli(self, *args, stdin=None):
        subprocess.run([sys.executable, '-m', 'tailmeta', *map(str, args)], check=True,
                       input=stdin, text=True, capture_output=True)

    def scenarios(self, key=None):
        """Yield (name, path) for files that should all end up identical."""
        api = {'private_key': key} if key else {}
        cli = ['--private-key', key] if key else []
        files = self.files

        def run(name, *steps):
            path = self.fresh()
            for step in steps:
                step(path)
            return name, path

        yield run('api: stamp', lambda p: stamp(p, META, **api))
        yield run('api: reversed key order', lambda p: stamp(p, dict(reversed(list(META.items()))), **api))
        yield run('cli: --metadata indented file', lambda p: self.cli('stamp', p, '--metadata', files['indented'], *cli))
        yield run('cli: --metadata stdin', lambda p: self.cli('stamp', p, '--metadata', '-', *cli,
                                                              stdin=files['reversed'].read_text(encoding='utf-8')))
        yield run('cli: partial file + flags', lambda p: self.cli('stamp', p, '--metadata', files['partial'], *FLAGS, *cli))
        yield run('cli: flags override file', lambda p: self.cli('stamp', p, '--metadata', files['other'],
                                                                 '--version', '1.2.4', '--commit', 'abc123', *cli))
        yield run('api: stamp twice', lambda p: stamp(p, META, **api), lambda p: stamp(p, META, **api))
        yield run('api: over a different trailer', lambda p: stamp(p, {'version': '0.0.1', 'junk': 'x' * 5000}),
                  lambda p: stamp(p, META, **api))
        yield run('cli: --format 3', lambda p: self.cli('stamp', p, '--metadata', files['indented'], '--format', '3', *cli))
        yield run('api: over a v2 trailer', lambda p: p.write_bytes(p.read_bytes() + b'{"version":"0"}'
                                                                  + encode_footer(b'{"version":"0"}', 2)),
                  lambda p: stamp(p, META, **api))
        yield run('api: stamp, strip, stamp', lambda p: stamp(p, META, **api), strip, lambda p: stamp(p, META, **api))
        yield run('cli: stamp, strip, stamp', lambda p: self.cli('stamp', p, '--metadata', files['indented']),
                  lambda p: self.cli('strip', p), lambda p: self.cli('stamp', p, '--metadata', files['indented'], *cli))
        yield run('api: chmod 755 first', lambda p: os.chmod(p, 0o755), lambda p: stamp(p, META, **api))

        path = self.fresh()
        link = self.dir / f'link{self.counter}'
        link.symlink_to(path)
        stamp(link, META, **api)
        yield 'api: through a symlink', path

        if HAS_SIGNING:
            yield run('api: over a signed trailer', lambda p: stamp(p, META, private_key=self.key),
                      lambda p: stamp(p, META, **api))

    def assert_identical(self, scenarios, expected=None):
        scenarios = list(scenarios)
        expected = expected or sha(scenarios[0][1])
        for name, path in scenarios:
            with self.subTest(name):
                self.assertEqual(sha(path), expected)

    def test_unsigned_paths_are_identical(self):
        data = encode_metadata(META)
        expected = hashlib.sha256(self.base.read_bytes() + data + encode_footer(data, 3)).hexdigest()
        self.assert_identical(self.scenarios(), expected)

    @unittest.skipUnless(HAS_SIGNING, 'requires signing extra')
    def test_signed_paths_are_identical(self):
        self.assert_identical(self.scenarios(self.key))

    def test_strip_restores_original_bytes(self):
        steps = {
            'unsigned': lambda p: stamp(p, META),
            'cli': lambda p: self.cli('stamp', p, *FLAGS),
        }
        if HAS_SIGNING:
            steps['signed'] = lambda p: stamp(p, META, private_key=self.key)
        scenarios = []
        for name, step in steps.items():
            path = self.fresh()
            step(path)
            strip(path)
            scenarios.append((name, path))
        self.assert_identical(scenarios, sha(self.base))

    def test_different_metadata_changes_hash(self):
        first, second = self.fresh(), self.fresh()
        stamp(first, META)
        stamp(second, {**META, 'version': '1.2.5'})
        self.assertNotEqual(sha(first), sha(second))


if __name__ == '__main__':
    unittest.main()
