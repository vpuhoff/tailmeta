import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tailmeta._core import FOOTER, MAGIC, MAX_METADATA, encode_footer, encode_metadata, read_metadata, stamp


class TailTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'app'
        self.base = b'\x7fELF\x00binary payload\xff'
        self.path.write_bytes(self.base)
        self.path.chmod(0o755)

    def test_missing_and_short(self):
        for value in (b'', b'a', self.base):
            self.path.write_bytes(value)
            self.assertIsNone(read_metadata(self.path))

    def test_replace_preserves_binary_and_mode(self):
        for metadata in ({'version': '1.2.4', 'channel': 'тест' * 100}, {'version': '2'}, {'version': '3.0.0'}):
            stamp(self.path, metadata)
            self.assertEqual(read_metadata(self.path), metadata)
            data = encode_metadata(metadata)
            self.assertEqual(self.path.read_bytes(), self.base + data + encode_footer(data, 2))
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o755)

    def test_corruption_is_rejected_without_modification(self):
        for data, length in ((b'{}', 0), (b'{}', MAX_METADATA + 1), (b'{}', 999), (b'!!', 2), (b'{}', 2), (b'\xff', 1)):
            original = self.base + data + FOOTER.pack(length, MAGIC)
            self.path.write_bytes(original)
            with self.assertRaises(ValueError):
                read_metadata(self.path)
            with self.assertRaises(ValueError):
                stamp(self.path, {'version': 'new'})
            self.assertEqual(self.path.read_bytes(), original)

    def test_invalid_metadata_is_rejected(self):
        for metadata in ({}, {'version': ''}, {'version': 1}, {'version': 'v' * MAX_METADATA}):
            with self.assertRaises(ValueError):
                stamp(self.path, metadata)
            self.assertEqual(self.path.read_bytes(), self.base)

    def test_deeply_nested_json_is_value_error(self):
        data = b'{"version":"1","x":' + b'[' * 200000 + b']' * 200000 + b'}'
        self.path.write_bytes(self.base + data + FOOTER.pack(len(data), MAGIC))
        with self.assertRaisesRegex(ValueError, 'invalid metadata JSON'):
            read_metadata(self.path)
        nested = []
        for _ in range(200000):
            nested = [nested]
        with self.assertRaisesRegex(ValueError, 'nested too deeply'):
            stamp(self.path, {'version': '1', 'x': nested})

    def test_unsafe_version_characters_are_rejected(self):
        for version in ('1.0\n', '1\x1b]0;x\x07', '1\x9b31m', '1\u202e', '1\u2028', '1\x00', '1\U000e0001'):
            with self.assertRaisesRegex(ValueError, 'control or formatting'):
                stamp(self.path, {'version': version})
            self.assertEqual(self.path.read_bytes(), self.base)
            data = ('{"version":%s}' % json.dumps(version)).encode()
            self.path.write_bytes(self.base + data + FOOTER.pack(len(data), MAGIC))
            with self.assertRaisesRegex(ValueError, 'invalid metadata JSON'):
                read_metadata(self.path)
            self.path.write_bytes(self.base)
        stamp(self.path, {'version': '1.0-тест+ü'})
        self.assertEqual(read_metadata(self.path)['version'], '1.0-тест+ü')

    def test_source_changed_while_stamping(self):
        real_open = Path.open

        def open_and_truncate(path_self, *args, **kwargs):
            stream = real_open(path_self, *args, **kwargs)
            if path_self.resolve() != self.path.resolve():
                return stream
            real_seek = stream.seek

            def seek(offset, whence=0):
                result = real_seek(offset, whence)
                if offset == 0 and whence == 0:
                    os.truncate(path_self, 0)
                return result

            stream.seek = seek
            return stream

        with patch.object(Path, 'open', open_and_truncate):
            with self.assertRaisesRegex(ValueError, 'source changed while stamping'):
                stamp(self.path, {'version': '1'})

    def test_signing_requires_optional_dependency(self):
        from tailmeta import _core

        blocked = {name: None for name in list(sys.modules) if name == 'cryptography' or name.startswith('cryptography.')}
        blocked.setdefault('cryptography', None)
        with patch.dict(sys.modules, blocked):
            with self.assertRaisesRegex(RuntimeError, 'tailmeta\\[signing\\]'):
                _core._crypto()


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "requires signing extra")
class SignedTailTests(TailTests):
    def setUp(self):
        super().setUp()
        from tailmeta._core import generate_keys
        self.private = Path(self.directory.name) / 'private.pem'
        self.public = Path(self.directory.name) / 'public.pem'
        generate_keys(self.private, self.public)

    def test_signed_replace(self):
        from tailmeta._core import verify
        for version in ('1.2.4', '2', '3.0.0'):
            stamp(self.path, {'version': version, 'channel': 'тест' * 100}, self.private)
            metadata = verify(self.path, self.public)
            self.assertEqual(metadata['version'], version)
            self.assertEqual(metadata['sha256'], hashlib.sha256(self.base).hexdigest())
            data = encode_metadata(read_metadata(self.path))
            self.assertEqual(self.path.read_bytes(), self.base + data + encode_footer(data, 2))

    def test_tampering(self):
        from tailmeta._core import verify, generate_keys
        stamp(self.path, {'version': '1.2.4'}, self.private)
        original = self.path.read_bytes()
        variants = [b'X' + original[1:], original.replace(b'1.2.4', b'9.9.9'), self.base, original[:-1]]
        metadata = read_metadata(self.path)
        metadata['signature'] = '!' * 88
        data = encode_metadata(metadata)
        variants.append(self.base + data + FOOTER.pack(len(data), MAGIC))
        for value in variants:
            self.path.write_bytes(value)
            with self.assertRaises(ValueError):
                verify(self.path, self.public)
        self.path.write_bytes(original)
        other_private = self.private.with_name('other-private.pem')
        other_public = self.public.with_name('other-public.pem')
        generate_keys(other_private, other_public)
        with self.assertRaises(ValueError):
            verify(self.path, other_public)
        stamp(self.path, {'version': 'unsigned'})
        with self.assertRaises(ValueError):
            verify(self.path, self.public)

    def test_non_canonical_signed_trailer_is_rejected(self):
        from tailmeta._core import verify
        stamp(self.path, {'version': '1.2.4', 'channel': 'stable'}, self.private)
        metadata = read_metadata(self.path)
        variants = [
            json.dumps(metadata, ensure_ascii=False, sort_keys=True),
            json.dumps(metadata, separators=(',', ':'), sort_keys=True).replace('stable', '\\u0073table'),
            json.dumps(dict(reversed(list(metadata.items()))), separators=(',', ':')),
        ]
        for text in variants:
            data = text.encode()
            self.assertEqual(json.loads(data), metadata)
            self.path.write_bytes(self.base + data + FOOTER.pack(len(data), MAGIC))
            self.assertEqual(read_metadata(self.path), metadata)
            with self.assertRaisesRegex(ValueError, 'canonically'):
                verify(self.path, self.public)

    def test_key_files_and_reserved_fields(self):
        from tailmeta._core import generate_keys
        self.assertEqual(self.private.stat().st_mode & 0o777, 0o600)
        original_key = self.private.read_bytes()
        with self.assertRaises(ValueError):
            generate_keys(self.private, self.public)
        with self.assertRaises(ValueError):
            generate_keys(self.private.with_name('same.pem'), self.private.with_name('same.pem'))
        self.assertEqual(self.private.read_bytes(), original_key)
        for field in ('signature', 'sha256'):
            with self.assertRaises(ValueError):
                stamp(self.path, {'version': 'v', field: 'fake'}, self.private)
        self.assertEqual(self.path.read_bytes(), self.base)

    def test_non_ed25519_key_is_rejected(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from tailmeta._core import load_key

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_private = Path(self.directory.name) / 'rsa-private.pem'
        rsa_public = Path(self.directory.name) / 'rsa-public.pem'
        rsa_private.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        rsa_public.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        with self.assertRaisesRegex(ValueError, 'Ed25519'):
            load_key(rsa_private, private=True)
        with self.assertRaisesRegex(ValueError, 'Ed25519'):
            load_key(rsa_public, private=False)

    def test_non_string_signature_is_rejected(self):
        from tailmeta._core import verify

        metadata = {
            'version': '1',
            'sha256': hashlib.sha256(self.base).hexdigest(),
            'signature': 12345,
        }
        data = encode_metadata(metadata)
        self.path.write_bytes(self.base + data + FOOTER.pack(len(data), MAGIC))
        with self.assertRaisesRegex(ValueError, 'invalid signature encoding'):
            verify(self.path, self.public)

    def test_binary_truncated_during_verification(self):
        from tailmeta._core import verify

        stamp(self.path, {'version': '1'}, self.private)
        real_open = open

        def open_and_truncate(path, mode='r', *args, **kwargs):
            stream = real_open(path, mode, *args, **kwargs)
            if Path(path).resolve() != self.path.resolve():
                return stream
            real_seek = stream.seek

            def seek(offset, whence=0):
                result = real_seek(offset, whence)
                if offset == 0 and whence == 0:
                    os.truncate(path, 0)
                return result

            stream.seek = seek
            return stream

        with patch('builtins.open', open_and_truncate):
            with self.assertRaisesRegex(ValueError, 'binary truncated during verification'):
                verify(self.path, self.public)


if __name__ == '__main__':
    unittest.main()
