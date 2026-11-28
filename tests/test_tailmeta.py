import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch
import io

from tailmeta import _core
from tailmeta._core import encode_signatures
from tailmeta._core import FOOTER_V2, MAGIC_VERSIONED, MAX_METADATA, encode_footer, encode_metadata, read_metadata, stamp


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
            self.assertEqual(self.path.read_bytes(), self.base + data + encode_footer(data, 3))
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o755)

    def test_corruption_is_rejected_without_modification(self):
        for data, length in ((b'{}', 0), (b'{}', MAX_METADATA + 1), (b'{}', 999), (b'!!', 2), (b'{}', 2), (b'\xff', 1)):
            original = self.base + data + FOOTER_V2.pack(zlib.crc32(data), length, 2, 0, MAGIC_VERSIONED)
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
        self.path.write_bytes(self.base + data + encode_footer(data, 2))
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
            self.path.write_bytes(self.base + data + encode_footer(data, 2))
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
            self.assertNotIn('sha256', read_metadata(self.path), 'v3 keeps the hash out of the JSON')
            data = encode_metadata(read_metadata(self.path))
            content = self.path.read_bytes()
            self.assertEqual(content[:len(self.base) + len(data)], self.base + data)
            self.assertEqual(content[len(self.base) + len(data):len(self.base) + len(data) + 6], b'\x00\x01\x00\x00\x00\x40')

    def resign(self, data, signatures):
        """Собрать трейлер v3 с корректным CRC вокруг произвольных данных и подписей."""
        block = encode_signatures(signatures)
        self.path.write_bytes(self.base + data + block + encode_footer(data, 3, block))

    def test_tampering(self):
        from tailmeta._core import verify, generate_keys
        stamp(self.path, {'version': '1.2.4'}, self.private)
        original = self.path.read_bytes()
        trailer = _core._read(io.BytesIO(original))[1]
        (algorithm, signature), = trailer['signatures']
        variants = [b'X' + original[1:], original.replace(b'1.2.4', b'9.9.9'), self.base, original[:-1]]
        metadata = read_metadata(self.path)
        metadata['signature'] = '!' * 88
        data = encode_metadata(metadata)
        variants.append(self.base + data + encode_footer(data, 2))
        for value in variants:
            self.path.write_bytes(value)
            with self.assertRaises(ValueError):
                verify(self.path, self.public)
        for data, signatures, message in (
            (b'{"version":"9.9.9"}', [(algorithm, signature)], 'verification failed'),
            (trailer['raw'], [(algorithm, signature[:-1] + bytes([signature[-1] ^ 1]))], 'verification failed'),
            (trailer['raw'], [(algorithm, signature[:32])], 'verification failed'),
            (trailer['raw'], [(0x0002, signature)], 'no signature for algorithm ed25519'),
            (trailer['raw'], [], 'signed metadata required'),
        ):
            self.resign(data, signatures)
            with self.assertRaisesRegex(ValueError, message):
                verify(self.path, self.public)
        # Entries of other algorithms are skipped, not treated as failures.
        self.resign(trailer['raw'], [(0x0002, signature), (algorithm, signature)])
        self.assertEqual(verify(self.path, self.public)['version'], '1.2.4')
        self.path.write_bytes(original)
        other_private = self.private.with_name('other-private.pem')
        other_public = self.public.with_name('other-public.pem')
        generate_keys(other_private, other_public)
        with self.assertRaises(ValueError):
            verify(self.path, other_public)
        stamp(self.path, {'version': 'unsigned'})
        with self.assertRaises(ValueError):
            verify(self.path, self.public)

    def test_several_signatures(self):
        from tailmeta._core import generate_keys, verify
        other_private = self.private.with_name('other-private.pem')
        other_public = self.public.with_name('other-public.pem')
        generate_keys(other_private, other_public)
        stamp(self.path, {'version': '1'}, self.private)
        first = _core._read(io.BytesIO(self.path.read_bytes()))[1]
        stamp(self.path, {'version': '1'}, other_private)
        second = _core._read(io.BytesIO(self.path.read_bytes()))[1]
        self.resign(first['raw'], first['signatures'] + second['signatures'])
        for public in (self.public, other_public):
            self.assertEqual(verify(self.path, public)['version'], '1')

    def test_non_canonical_json_is_signed_as_is(self):
        """v3 подписывает байты как есть: каноническая запись не требуется."""
        from tailmeta._core import load_key, signed_message_v3, verify
        data = b'{ "version" : "1.2.4",\n  "channel": "\\u0073table" }'
        digest = hashlib.sha256(self.base).digest()
        signature = load_key(self.private, private=True).sign(signed_message_v3(_core.ED25519, digest, data))
        self.resign(data, [(_core.ED25519, signature)])
        self.assertEqual(verify(self.path, self.public),
                         {'version': '1.2.4', 'channel': 'stable', 'sha256': digest.hex()})
        self.assertFalse(_core.inspect(self.path)['canonical'])
        self.resign(data.replace(b'\n', b' '), [(_core.ED25519, signature)])
        with self.assertRaisesRegex(ValueError, 'verification failed'):
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


class ExecutablePathTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'app'
        self.path.write_bytes(b'\x7fELF payload')
        stamp(self.path, {'version': '7.0'})
        self.link = Path(self.directory.name) / 'link'
        self.link.symlink_to(self.path)

    def test_plain_python_requires_path(self):
        from tailmeta import _core, executable_path
        with patch.object(_core, '_is_nuitka', return_value=False), patch.object(sys, 'frozen', False, create=True):
            with self.assertRaisesRegex(TypeError, 'path is required'):
                executable_path()
            with self.assertRaisesRegex(TypeError, 'path is required'):
                read_metadata()

    def test_nuitka_uses_argv0(self):
        from tailmeta import _core
        with patch.object(_core, '_is_nuitka', return_value=True), patch.object(sys, 'argv', [str(self.link)]):
            self.assertEqual(_core.executable_path(), self.path.resolve())
            self.assertEqual(read_metadata()['version'], '7.0')

    def test_nuitka_detected_from_main_module(self):
        from tailmeta import _core
        main = type(sys)('__main__')
        main.__compiled__ = object()
        with patch.dict(sys.modules, {'__main__': main}):
            self.assertTrue(_core._is_nuitka())
        with patch.dict(sys.modules, {'__main__': type(sys)('__main__')}):
            self.assertFalse(_core._is_nuitka())

    def test_frozen_uses_executable(self):
        from tailmeta import _core
        with patch.object(_core, '_is_nuitka', return_value=False), patch.object(sys, 'frozen', True, create=True), \
                patch.object(sys, 'executable', str(self.link)):
            self.assertEqual(_core.executable_path(), self.path.resolve())
            self.assertEqual(read_metadata()['version'], '7.0')

    def test_verify_requires_public_key(self):
        from tailmeta._core import verify
        with self.assertRaisesRegex(TypeError, 'requires public_key'):
            verify(self.path)

    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "requires signing extra")
    def test_verify_defaults_to_own_binary(self):
        from tailmeta import _core
        private = Path(self.directory.name) / 'private.pem'
        public = Path(self.directory.name) / 'public.pem'
        _core.generate_keys(private, public)
        stamp(self.path, {'version': '8.0'}, private)
        with patch.object(_core, '_is_nuitka', return_value=True), patch.object(sys, 'argv', [str(self.link)]):
            self.assertEqual(_core.verify(public_key=public)['version'], '8.0')


if __name__ == '__main__':
    unittest.main()
