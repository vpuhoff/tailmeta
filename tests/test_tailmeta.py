import importlib.util
import tempfile
import unittest
from pathlib import Path
from tailmeta._core import FOOTER, MAGIC, MAX_METADATA, encode_metadata, read_metadata, stamp


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
            self.assertEqual(self.path.read_bytes(), self.base + data + FOOTER.pack(len(data), MAGIC))
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

@unittest.skipUnless(importlib.util.find_spec("cryptography"), "requires signing extra")
class SignedTailTests(TailTests):
    def setUp(self):
        super().setUp()
        from tailmeta._core import generate_keys
        self.private = Path(self.directory.name) / 'private.pem'
        self.public = Path(self.directory.name) / 'public.pem'
        generate_keys(self.private, self.public)

    def test_signed_replace(self):
        import hashlib
        from tailmeta._core import verify
        for version in ('1.2.4', '2', '3.0.0'):
            stamp(self.path, {'version': version, 'channel': 'тест' * 100}, self.private)
            metadata = verify(self.path, self.public)
            self.assertEqual(metadata['version'], version)
            self.assertEqual(metadata['sha256'], hashlib.sha256(self.base).hexdigest())
            data = encode_metadata(read_metadata(self.path))
            self.assertEqual(self.path.read_bytes(), self.base + data + FOOTER.pack(len(data), MAGIC))

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

    def test_key_files_and_reserved_fields(self):
        from tailmeta._core import generate_keys
        self.assertEqual(self.private.stat().st_mode & 0o777, 0o600)
        original_key = self.private.read_bytes()
        with self.assertRaises(ValueError):
            generate_keys(self.private, self.public)
        self.assertEqual(self.private.read_bytes(), original_key)
        for field in ('signature', 'sha256'):
            with self.assertRaises(ValueError):
                stamp(self.path, {'version': 'v', field: 'fake'}, self.private)
        self.assertEqual(self.path.read_bytes(), self.base)


if __name__ == '__main__':
    unittest.main()
