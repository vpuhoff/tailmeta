import importlib.util
import json
from importlib.metadata import version as package_version
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tailmeta._core import FOOTER_V2, MAGIC_VERSIONED, encode_footer


def trailer(data):
    return data + encode_footer(data, 2)


class CLITests(unittest.TestCase):
    def _run(self, directory, *args, input=None):
        return subprocess.run(
            [sys.executable, '-m', 'tailmeta', *map(str, args)],
            cwd=directory,
            capture_output=True,
            text=True,
            input=input,
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

    def test_read_escapes_control_characters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'app.bin'
            path.write_bytes(b'original data')
            channel = 'a\x1b[31m\x9b\u2028\U000e0001тест'
            result = self._run(directory, 'stamp', path, '--version', '1', '--channel', channel)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = self._run(directory, 'read', path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotRegex(result.stdout.strip(), '[\x00-\x1f\x7f-\x9f\u2028\U000e0001]')
            self.assertIn('тест', result.stdout)
            self.assertEqual(json.loads(result.stdout)['channel'], channel)

    def test_stamp_metadata_file_strip_and_inspect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'app.bin'
            path.write_bytes(b'original data')
            run = lambda *args, **kw: self._run(directory, *args, **kw)
            source = root / 'metadata.json'
            source.write_text('{"version": "0.9", "build": {"n": 5}, "channel": "x"}', encoding='utf-8')
            result = run('stamp', path, '--metadata', source, '--channel', 'beta', '--format', '2')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(run('read', path).stdout), {'version': '0.9', 'build': {'n': 5}, 'channel': 'beta'})
            result = run('stamp', path, '--metadata', '-', '--version', '1.0', input='{"commit": "abc"}')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(run('read', path).stdout), {'version': '1.0', 'commit': 'abc'})

            result = run('inspect', path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertRegex(result.stdout, r'format version: +2')
            self.assertRegex(result.stdout, r'crc32: +[0-9a-f]{8}')
            self.assertRegex(result.stdout, r'version: +1\.0')
            report = json.loads(run('inspect', path, '--json', '--no-hash').stdout)
            self.assertEqual((report['status'], report['format_version']), ('valid', 2))
            self.assertNotIn('content_sha256', report)

            result = run('strip', path)
            self.assertEqual((result.returncode, result.stderr), (0, ''))
            self.assertEqual(path.read_bytes(), b'original data')
            result = run('strip', path)
            self.assertEqual(result.returncode, 0)
            self.assertIn('metadata not found', result.stderr)
            result = run('inspect', path)
            self.assertEqual(result.returncode, 1)
            self.assertRegex(result.stdout, r'status: +absent')

            path.write_bytes(b'data' + trailer(b'{"sha256":"00","version":1}'))
            result = run('inspect', path)
            self.assertEqual(result.returncode, 1)
            self.assertIn('invalid metadata JSON', result.stdout)
            path.write_bytes(b'data' + FOOTER_V2.pack(0, 0x999, 2, 0, MAGIC_VERSIONED))
            result = run('inspect', path, '--no-hash')
            self.assertIn('invalid metadata length', result.stdout)
            self.assertNotIn('content size', result.stdout)
            path.write_bytes(b'data' + trailer(b'{"sha256":"00","version":"1"}'))
            self.assertIn('DOES NOT match', run('inspect', path).stdout)

            for content, message in (
                ('[1]', 'JSON object'),
                ('{"version": "1", "version": "2"}', 'duplicate key'),
                ('{oops', 'not valid JSON'),
                # Python <= 3.13 fails while parsing the file, 3.14+ while encoding.
                ('{"version": "1", "x": ' + '[' * 100000 + ']' * 100000 + '}', 'nested too deeply'),
                (' ' * (1024 * 1024 + 1), 'exceeds 1 MiB'),
                ('{"channel": "x"}', 'nonempty string version'),
            ):
                source.write_text(content, encoding='utf-8')
                result = run('stamp', path, '--metadata', source)
                self.assertEqual(result.returncode, 1, content[:20])
                self.assertIn(message, result.stderr)
            source.write_bytes(b'\xff')
            self.assertIn('UTF-8', run('stamp', path, '--metadata', source).stderr)

    def test_read_url(self):
        from test_http import Handler, trailer
        from http.server import ThreadingHTTPServer
        import threading
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.body, server.mode, server.ranges = trailer({'version': '7.1'}, size=100), 'ok', []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_address[1]}/app.bin'
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(directory, 'read', url, '--version-only', '--timeout', '5')
            self.assertEqual((result.returncode, result.stdout.strip()), (0, '7.1'), result.stderr)
            server.body = b'no trailer'
            self.assertEqual(self._run(directory, 'read', url).returncode, 1)

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'requires signing extra')
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

            missing = run('verify', path, '--public-key', root / 'missing.pem')
            self.assertEqual(missing.returncode, 1)
            self.assertIn('error:', missing.stderr)

            absent = run('stamp', root / 'missing.bin', '--version', '1')
            self.assertEqual(absent.returncode, 1)
            self.assertIn('error:', absent.stderr)
