"""Format versioning, compatibility fixtures, strip and inspect."""
import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from tailmeta import UnsupportedFormatError, inspect, read_metadata, stamp, strip
from tailmeta._core import encode_footer, encode_signatures

BASE = b'\x7fELF payload'
JSON = b'{"version":"1.2.4"}'
# Golden trailers: these bytes must stay readable by every future release.
# The same vectors are published in SPEC.md, appendix A.
# V1 is the retired format: every operation must keep refusing it.
V1 = BASE + JSON + b'\x00\x00\x00\x13TAILMETA'
V2 = BASE + JSON + struct.pack('>I', zlib.crc32(JSON)) + b'\x00\x00\x00\x13\x00\x02\x00\x00TAILMETV'
V3 = BASE + JSON + bytes.fromhex('70d369520000001300000000000300005441494c4d455456')
# Signed with the RFC 8032 test 1 key; Ed25519 is deterministic.
RFC8032_SEED = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
V3_SIGNATURE = bytes.fromhex(
    'aee6762f317cb207c12dec3e34ee839aeebcc311604a800c25fe1e72a03837f5'
    '22774ad17103d884170d45bda1b28d837715e2f393e6b808e75829ea5a213905')
V3_SIGNED = (BASE + JSON + bytes.fromhex('000100000040') + V3_SIGNATURE
             + bytes.fromhex('4370327a0000001300000046000300005441494c4d455456'))


def rfc8032_keys(directory):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.from_private_bytes(RFC8032_SEED)
    private, public = Path(directory) / 'rfc-private.pem', Path(directory) / 'rfc-public.pem'
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo))
    return private, public


class FormatTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'app'
        self.path.write_bytes(BASE)

    def write(self, data):
        self.path.write_bytes(data)

    def test_golden_fixtures(self):
        for data in (V2, V3, V3_SIGNED):
            self.write(data)
            self.assertEqual(read_metadata(self.path), {'version': '1.2.4'})
            self.assertTrue(strip(self.path))
            self.assertEqual(self.path.read_bytes(), BASE)

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

    def test_stamp_writes_v3(self):
        stamp(self.path, {'version': '1.2.4'})
        self.assertEqual(self.path.read_bytes(), V3, 'new trailers use v3')
        stamp(self.path, {'version': '1.2.4'}, format_version=3)
        self.assertEqual(self.path.read_bytes(), V3)
        self.write(V2)
        stamp(self.path, {'version': '1.2.4'})
        self.assertEqual(self.path.read_bytes(), V3, 'restamping converts v2 to v3')

    def test_unknown_format_versions_are_refused(self):
        for version, flags in ((4, 0), (1, 0), (0, 0), (2, 1), (3, 1), (3, 0x8000)):
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
        for version in (0, 1, 2, 4, 'x'):
            with self.assertRaises(UnsupportedFormatError):
                stamp(self.path, {'version': '1'}, format_version=version)
        with self.assertRaises(UnsupportedFormatError):
            encode_footer(b'', 9)
        with self.assertRaises(UnsupportedFormatError):
            encode_footer(b'{}', 2, b'signature')

    def test_duplicate_keys_and_non_objects_are_rejected(self):
        for data in (b'{"version":"1","version":"2"}', b'{"version":"1","x":{"a":1,"a":2}}', b'["1"]', b'"1"'):
            self.write(BASE + data + encode_footer(data, 3))
            with self.assertRaisesRegex(ValueError, 'invalid metadata JSON'):
                read_metadata(self.path)

    def test_v3_corruption(self):
        def v3(data, signatures, footer_signatures=None, metadata_length=None):
            footer = encode_footer(data, 3, signatures)
            if footer_signatures is not None or metadata_length is not None:
                crc, length, sig_length = struct.unpack('>III', footer[:12])
                footer = struct.pack('>III', crc, metadata_length or length,
                                     sig_length if footer_signatures is None else footer_signatures) + footer[12:]
            return BASE + data + signatures + footer

        flipped = bytearray(V3_SIGNED)
        flipped[-30] ^= 0x01  # inside the signature, CRC no longer matches
        for data, message in (
            (bytes(flipped), 'checksum'),
            (v3(JSON, b'\x00\x01\x00'), 'invalid signature block'),
            (v3(JSON, b'\x00\x01\x00\x00\x00\x09abc'), 'invalid signature block'),
            (v3(JSON, b'\x00\x01\x00\x00\x00\x00'), 'invalid signature block'),
            (v3(JSON, b'', footer_signatures=10**6), 'invalid signature block length'),
            (v3(JSON, b'', footer_signatures=len(BASE) + 1), 'invalid signature block length'),
            (v3(JSON, b'', metadata_length=10**6), 'invalid metadata length'),
        ):
            self.write(data)
            with self.assertRaisesRegex(ValueError, message):
                read_metadata(self.path)
            with self.assertRaises(ValueError):
                stamp(self.path, {'version': '2'})
            self.assertEqual(self.path.read_bytes(), data)
            self.assertEqual(inspect(self.path)['status'], 'invalid')
        # Unknown algorithms are not an error for readers.
        self.write(v3(JSON, encode_signatures([(0xfff0, b'future')])))
        self.assertEqual(read_metadata(self.path), {'version': '1.2.4'})
        self.assertEqual(inspect(self.path)['signatures'], [{'algorithm': 0xfff0, 'name': 'unknown', 'length': 6}])

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
        self.assertNotIn('signatures', report)
        self.write(V3_SIGNED)
        report = inspect(self.path)
        self.assertEqual((report['format_version'], report['footer_size'], report['signature_length']), (3, 24, 70))
        self.assertEqual(report['trailer_size'], len(V3_SIGNED) - len(BASE))
        self.assertTrue(report['signed'])
        self.assertEqual(report['signatures'], [{'algorithm': 1, 'name': 'ed25519', 'length': 64}])
        self.write(V3)
        report = inspect(self.path)
        self.assertFalse(report['signed'])
        self.assertEqual((report['signature_length'], report['signatures']), (0, []))
        data = b'{"sha256":"00","version":"1"}'
        self.write(BASE + data + encode_footer(data, 3))
        self.assertNotIn('sha256_matches', inspect(self.path), 'v3 binds the hash in the signature, not in JSON')
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
    def test_golden_signed_v3(self):
        from tailmeta import verify
        private, public = rfc8032_keys(self.directory.name)
        stamp(self.path, {'version': '1.2.4'}, private)
        self.assertEqual(self.path.read_bytes(), V3_SIGNED)
        self.assertEqual(verify(self.path, public),
                         {'version': '1.2.4', 'sha256': hashlib.sha256(BASE).hexdigest()})

    @unittest.skipUnless(importlib.util.find_spec('cryptography'), 'requires signing extra')
    def test_signed_v2_is_not_verified(self):
        from tailmeta import verify
        _, public = rfc8032_keys(self.directory.name)
        signed = {'version': '1', 'sha256': hashlib.sha256(BASE).hexdigest(), 'signature': 'A' * 88}
        data = json.dumps(signed, sort_keys=True, separators=(',', ':')).encode()
        for footer in (encode_footer(data, 2), struct.pack('>I8s', len(data), b'TAILMETA')):
            self.write(BASE + data + footer)
            with self.assertRaises(UnsupportedFormatError):
                verify(self.path, public)
        self.write(BASE + data + encode_footer(data, 2))
        self.assertEqual(read_metadata(self.path), signed)
        report = inspect(self.path)
        self.assertTrue(report['signed'])
        self.assertTrue(report['sha256_matches'])

if __name__ == '__main__':
    unittest.main()
