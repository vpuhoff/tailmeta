"""Формат v1: [бинарник][UTF-8 JSON][uint32 big endian][TAILMETA]."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import unicodedata

MAGIC = b"TAILMETA"
FOOTER = struct.Struct(">I8s")
MAX_METADATA = 1024 * 1024
# Управляющие и форматирующие символы (C0/C1, bidi, разделители строк)
# недопустимы в version: она печатается в терминал и подставляется в скрипты.
UNSAFE_CATEGORIES = frozenset(("Cc", "Cf", "Zl", "Zp"))


def is_unsafe_char(char):
    return unicodedata.category(char) in UNSAFE_CATEGORIES


def encode_metadata(metadata):
    if not isinstance(metadata, dict) or not isinstance(metadata.get("version"), str) or not metadata["version"].strip():
        raise ValueError("metadata must contain a nonempty string version")
    if any(map(is_unsafe_char, metadata["version"])):
        raise ValueError("version must not contain control or formatting characters")
    try:
        data = json.dumps(metadata, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except RecursionError as exc:
        raise ValueError("metadata is nested too deeply") from exc
    if len(data) > MAX_METADATA:
        raise ValueError("metadata exceeds 1 MiB")
    return data


def _read(stream):
    """Вернуть (metadata, начало трейлера, канонична ли запись JSON)."""
    size = stream.seek(0, os.SEEK_END)
    if size < FOOTER.size:
        return None, size, False
    stream.seek(-FOOTER.size, os.SEEK_END)
    length, magic = FOOTER.unpack(stream.read(FOOTER.size))
    if magic != MAGIC:
        return None, size, False
    if not 0 < length <= min(MAX_METADATA, size - FOOTER.size):
        raise ValueError("invalid metadata length")
    start = size - FOOTER.size - length
    stream.seek(start)
    raw = stream.read(length)
    try:
        metadata = json.loads(raw.decode("utf-8"))
        canonical = encode_metadata(metadata) == raw
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid metadata JSON") from exc
    return metadata, start, canonical


def read_metadata(path):
    """Прочитать недоверенные данные без проверки подписи."""
    with open(path, "rb") as stream:
        return _read(stream)[0]


def _crypto():
    try:
        from cryptography import exceptions
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:
        raise RuntimeError('Signing requires the optional dependency: pip install "tailmeta[signing]"') from exc
    return exceptions, serialization, ed25519


def load_key(path, private=False):
    _, serialization, ed25519 = _crypto()
    data = Path(path).read_bytes()
    key = (serialization.load_pem_private_key(data, password=None) if private
           else serialization.load_pem_public_key(data))
    expected = ed25519.Ed25519PrivateKey if private else ed25519.Ed25519PublicKey
    if not isinstance(key, expected):
        raise ValueError("an Ed25519 key is required")
    return key


def generate_keys(private_path, public_path):
    _, serialization, ed25519 = _crypto()
    private_path, public_path = Path(private_path), Path(public_path)
    if private_path.resolve() == public_path.resolve() or private_path.exists() or public_path.exists():
        raise ValueError("key paths must be distinct and must not already exist")
    key = ed25519.Ed25519PrivateKey.generate()
    private_data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public_data = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with os.fdopen(os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(private_data)
    with public_path.open("xb") as stream:
        stream.write(public_data)


def signing_bytes(metadata):
    return MAGIC + b"\x00" + encode_metadata(metadata)


def verify(path, public_key):
    """Проверить подпись всех полей и SHA-256 исходной части файла."""
    exceptions, _, _ = _crypto()
    key = load_key(public_key)
    with open(path, "rb") as stream:
        metadata, base_size, canonical = _read(stream)
        if metadata is None or "signature" not in metadata:
            raise ValueError("signed metadata required")
        if not canonical:
            raise ValueError("signed metadata is not canonically encoded")
        signed = dict(metadata)
        signature = signed.pop("signature")
        if not isinstance(signature, str):
            raise ValueError("invalid signature encoding")
        try:
            key.verify(base64.b64decode(signature, validate=True), signing_bytes(signed))
        except (exceptions.InvalidSignature, ValueError) as exc:
            raise ValueError("signature verification failed") from exc
        digest = hashlib.sha256()
        stream.seek(0)
        remaining = base_size
        while remaining:
            chunk = stream.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise ValueError("binary truncated during verification")
            digest.update(chunk)
            remaining -= len(chunk)
        if signed.get("sha256") != digest.hexdigest():
            raise ValueError("binary SHA-256 mismatch")
        return signed


def stamp(path, metadata, private_key=None):
    """Заменяет существующий хвост через временный файл и atomic replace."""
    data = encode_metadata(metadata)
    if "sha256" in metadata or "signature" in metadata:
        raise ValueError("sha256 and signature are generated fields")
    key = load_key(private_key, private=True) if private_key is not None else None
    path = Path(path).resolve(strict=True)
    temporary = None
    try:
        with path.open("rb") as source:
            _, base_size, _ = _read(source)
            source.seek(0)
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as target:
                temporary = Path(target.name)
                remaining = base_size
                digest = hashlib.sha256()
                while remaining:
                    chunk = source.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        raise ValueError("source changed while stamping")
                    target.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                if key is not None:
                    signed = dict(metadata, sha256=digest.hexdigest())
                    signature = base64.b64encode(key.sign(signing_bytes(signed))).decode("ascii")
                    data = encode_metadata(dict(signed, signature=signature))
                target.write(data)
                target.write(FOOTER.pack(len(data), MAGIC))
                target.flush()
                os.fsync(target.fileno())
        shutil.copymode(path, temporary)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
