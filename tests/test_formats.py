"""Format versioning, compatibility fixtures, strip and inspect."""
import hashlib
import importlib.util
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from tailmeta import UnsupportedFormatError, inspect, read_metadata, stamp, strip
from tailmeta._core import encode_footer

BASE = b'\x7fELF payload'
# Golden v2 trailer: these bytes must stay readable by every future release.
# V1 is the retired format: every operation must keep refusing it.
V1 = BASE + b'{"version":"1.2.4"}' + b'\x00\x00\x00\x13TAILMETA'
V2 = BASE + b'{"version":"1.2.4"}' + struct.pack('>I', zlib.crc32(b'{"version":"1.2.4"}')) + b'\x00\x00\x00\x13\x00\x02\x00\x00TAILMETV'


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'app'
        self.path.write_bytes(BASE)

    def write(self, data):
        self.path.write_bytes(data)

    def test_golden_fixture(self):
        self.write(V2)
        self.assertEqual(read_metadata(self.path), {'version': '1.2.4'})

    def test_v1_is_refused(self):
        for data in (V1, BASE + b'!!' + struct.pack('>I8s', 999, b'TAILMETA'), b'\x00\x00\x00\x00TAILMETA'):
            self.write(data)
            with self.assertRaisesRegex(UnsupportedFormatError, 'v1 is no longer supported'):
                read_metadata(self.path)
            with self.assertRaises(UnsupportedFormatError):
                stamp(self.path, {'version': '2'})
            with self.assertRaises(UnsupportedFormatError):
                strip(self.path)
            report = inspect(self.path)
            self.assertEqual((report['status'], report['format_version']), ('unsupported', 1))
            self.assertNotIn('content_sha256', report)
            self.assertEqual(self.path.read_bytes(), data)

    def test_stamp_writes_v2(self):
        stamp(self.path, {'version': '1.2.4'})
        self.assertEqual(self.path.read_bytes(), V2, 'new trailers use v2')
        stamp(self.path, {'version': '1.2.4'}, format_version=2)
        self.assertEqual(self.path.read_bytes(), V2)

    def test_unknown_format_versions_are_refused(self):
        for version, flags in ((3, 0), (1, 0), (0, 0), (2, 1)):
            data = BASE + b'{"version":"1"}' + struct.pack('>IIHH8s', 0, 15, version, flags, b'TAILMETV')
            self.write(data)
            with self.assertRaises(UnsupportedFormatError):
                read_metadata(self.path)
            with self.assertRaises(UnsupportedFormatError):
                stamp(self.path, {'version': '2'})
            with self.assertRaises(UnsupportedFormatError):
                strip(self.path)
            self.assertEqual(self.path.read_bytes(), data)
            self.assertEqual(inspect(self.path)['status'], 'unsupported')
        for version in (0, 1, 3, 'x'):
            with self.assertRaises(UnsupportedFormatError):
                stamp(self.path, {'version': '1'}, format_version=version)
        with self.assertRaises(UnsupportedFormatError):
            encode_footer(b'', 9)

    def test_v2_corruption(self):
        flipped = bytearray(V2)
        flipped[len(BASE) + 13] ^= 0x01  # '2' -> '3' keeps valid JSON
        for data in (bytes(flipped), b'\x00\x02\x00\x00TAILMETV', b'\x00' * 4 + b'\x00\x02\x00\x00TAILMETV',
                     BASE + b'{}' + struct.pack('>IIHH8s', 0, 999, 2, 0, b'TAILMETV')):
            self.write(data)
            with self.assertRaises(ValueError):
                read_metadata(self.path)
            report = inspect(self.path)
            self.assertEqual(report['status'], 'invalid')
            self.assertIn('error', report)
        self.write(bytes(flipped))
        self.assertIn('checksum', inspect(self.path)['error'])

    def test_strip(self):
        self.assertFalse(strip(self.path))
        self.write(V2)
        self.path.chmod(0o751)
        self.assertTrue(strip(self.path))
        self.assertEqual(self.path.read_bytes(), BASE)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o751)
        self.assertFalse(strip(self.path))
        self.write(BASE + b'!!' + encode_footer(b'!!', 2))
        with self.assertRaises(ValueError):
            strip(self.path)

    def test_inspect(self):
        report = inspect(self.path)
        self.assertEqual(report['status'], 'absent')
        self.assertEqual(report['content_sha256'], hashlib.sha256(BASE).hexdigest())
        self.write(V2)
        report = inspect(self.path)
        self.assertEqual(report['status'], 'valid')
        self.assertEqual(report['format_version'], 2)
        self.assertEqual(report['content_size'], len(BASE))
        self.assertEqual(report['trailer_size'], len(V2) - len(BASE))
        self.assertEqual(report['footer_size'], 20)
        self.assertEqual(report['crc32'], '%08x' % zlib.crc32(b'{"version":"1.2.4"}'))
        self.assertTrue(report['canonical'])
        self.assertFalse(report['signed'])
        self.assertNotIn('sha256_matches', report)
        self.assertNotIn('content_sha256', inspect(self.path, compute_hash=False))
        data = b'{"sha256":"00","version":"1"}'
        self.write(BASE + data + encode_footer(data, 2))
        self.assertFalse(inspect(self.path)['sha256_matches'])
        data = b'{"version": "1"}'
        self.write(BASE + data + encode_footer(data, 2))
        self.assertFalse(inspect(self.path)['canonical'])
        self.write(BASE + b'!!' + encode_footer(b'!!', 2))
        report = inspect(self.path)
        self.assertEqual((report['status'], report['content_size']), ('invalid', len(BASE)))

    def test_inspect_truncated_while_hashing(self):
        from unittest.mock import patch
        from tailmeta import _core

        with patch.object(_core, '_parse', lambda stream, report: report.update(file_size=10**6)):
            with self.assertRaisesRegex(ValueError, 'truncated while hashing'):
                inspect(self.path)

    def test_short_read_is_detected(self):
        from tailmeta._core import _read_exact
        import io
        with self.assertRaisesRegex(ValueError, 'truncated while reading'):
            _read_exact(io.BytesIO(b'ab'), 3)

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'requires signing extra')
    def test_signed_v2_and_inspect(self):
        from tailmeta import generate_keys, verify
        private = Path(self.directory.name) / 'private.pem'
        public = Path(self.directory.name) / 'public.pem'
        generate_keys(private, public)
        stamp(self.path, {'version': '1'}, private, format_version=2)
        self.assertEqual(verify(self.path, public)['version'], '1')
        report = inspect(self.path)
        self.assertTrue(report['signed'])
        self.assertTrue(report['sha256_matches'])
        # The same signed JSON behind a v1 footer is refused, not verified.
        data = self.path.read_bytes()[len(BASE):-20]
        self.write(BASE + data + struct.pack('>I8s', len(data), b'TAILMETA'))
        with self.assertRaises(UnsupportedFormatError):
            verify(self.path, public)


if __name__ == '__main__':
    unittest.main()
