"""Форматы трейлера.

v2: [данные][UTF-8 JSON][uint32 CRC32][uint32 длина][uint16 версия][uint16 флаги][TAILMETV]

Устаревший v1 ([данные][UTF-8 JSON][uint32 длина][TAILMETA]) больше не
поддерживается: его магия распознаётся, и любая операция отказывает с
UnsupportedFormatError, как для неизвестной версии.

Последние 12 байт версионированного трейлера ([версия][флаги][TAILMETV])
стабильны для всех будущих версий: читатель всегда может узнать версию
формата и отказаться от неизвестной, а не принять её за отсутствие трейлера.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unicodedata
import zlib

# Магия устаревшего v1; также префикс подписываемого сообщения.
MAGIC = b"TAILMETA"
MAGIC_VERSIONED = b"TAILMETV"
FOOTER_V2 = struct.Struct(">IIHH8s")
VERSION_TAIL = struct.Struct(">HH8s")
FORMAT_VERSIONS = (2,)
DEFAULT_FORMAT = 2
MAX_METADATA = 1024 * 1024
CHUNK = 1024 * 1024
# Управляющие и форматирующие символы (C0/C1, bidi, разделители строк)
# недопустимы в version: она печатается в терминал и подставляется в скрипты.
UNSAFE_CATEGORIES = frozenset(("Cc", "Cf", "Zl", "Zp"))


class UnsupportedFormatError(ValueError):
    """Трейлер tailmeta распознан, но его версия формата не поддерживается."""


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


def encode_footer(data, format_version):
    if format_version == 2:
        return FOOTER_V2.pack(zlib.crc32(data), len(data), 2, 0, MAGIC_VERSIONED)
    raise UnsupportedFormatError(f"unsupported format version: {format_version!r}")


def _read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("file truncated while reading trailer")
    return data


def _parse(stream, report=None):
    """Найти трейлер. Вернуть None или словарь с его границами и сырым JSON.

    Если передан report, он заполняется по мере разбора, чтобы inspect мог
    показать, на каком шаге трейлер оказался повреждён.
    """
    report = {} if report is None else report
    size = stream.seek(0, os.SEEK_END)
    report["file_size"] = size
    if size < VERSION_TAIL.size:
        return None
    stream.seek(-VERSION_TAIL.size, os.SEEK_END)
    tail = _read_exact(stream, VERSION_TAIL.size)
    if tail[-8:] == MAGIC:
        report["format_version"] = 1
        raise UnsupportedFormatError("trailer format v1 is no longer supported")
    if tail[-8:] != MAGIC_VERSIONED:
        return None
    format_version, flags, _ = VERSION_TAIL.unpack(tail)
    report["format_version"] = format_version
    if format_version != 2:
        raise UnsupportedFormatError(f"unsupported format version: {format_version}")
    if flags:
        raise UnsupportedFormatError(f"unsupported trailer flags: {flags:#06x}")
    footer_size = FOOTER_V2.size
    if size < footer_size:
        raise ValueError("invalid metadata length")
    stream.seek(-footer_size, os.SEEK_END)
    checksum, length, _, _, _ = FOOTER_V2.unpack(_read_exact(stream, footer_size))
    report.update(footer_size=footer_size, metadata_length=length, crc32=f"{checksum:08x}")
    if not 0 < length <= min(MAX_METADATA, size - footer_size):
        raise ValueError("invalid metadata length")
    start = size - footer_size - length
    report.update(content_size=start, trailer_offset=start, trailer_size=length + footer_size)
    stream.seek(start)
    raw = _read_exact(stream, length)
    if zlib.crc32(raw) != checksum:
        raise ValueError("metadata checksum mismatch")
    return {"format_version": format_version, "start": start, "raw": raw}


def _decode(raw):
    try:
        metadata = json.loads(raw.decode("utf-8"))
        canonical = encode_metadata(metadata) == raw
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid metadata JSON") from exc
    return metadata, canonical


def _read(stream):
    """Вернуть (metadata, начало трейлера, канонична ли запись JSON, версия формата)."""
    trailer = _parse(stream)
    if trailer is None:
        return None, stream.seek(0, os.SEEK_END), False, None
    metadata, canonical = _decode(trailer["raw"])
    return metadata, trailer["start"], canonical, trailer["format_version"]


def _is_nuitka():
    # __compiled__ есть в глобалах каждого модуля, скомпилированного Nuitka;
    # __main__ проверяется на случай, если сам tailmeta не скомпилирован.
    return "__compiled__" in globals() or hasattr(sys.modules.get("__main__"), "__compiled__")


def executable_path():
    """Путь к исполняемому файлу текущего собранного приложения.

    Nuitka (onefile и standalone) подменяет sys.argv[0] абсолютным путём к
    самому бинарнику, даже при запуске через PATH, симлинк или exec -a;
    sys.executable в onefile указывает на распакованную копию во временной
    папке, где трейлера нет. PyInstaller и cx_Freeze выставляют sys.frozen,
    и sys.executable у них — внешний исполняемый файл. В обычном Python
    бинарника нет, поэтому путь нужно передать явно.
    """
    if _is_nuitka():
        return Path(sys.argv[0]).resolve()
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    raise TypeError("path is required when not running as a compiled Nuitka or frozen application")


def read_metadata(path=None):
    """Прочитать недоверенные данные без проверки подписи.

    Без path читается собственный бинарник приложения (см. executable_path).
    """
    if path is None:
        path = executable_path()
    with open(path, "rb") as stream:
        return _read(stream)[0]


def _hash_prefix(stream, size, error):
    digest = hashlib.sha256()
    stream.seek(0)
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, CHUNK))
        if not chunk:
            raise ValueError(error)
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def inspect(path, compute_hash=True):
    """Подробно описать трейлер, не бросая исключений на повреждённых данных.

    status: "absent", "valid", "invalid" или "unsupported". Метаданные не
    проверяются на подлинность: совпадение sha256 означает только целостность.
    """
    report = {"path": str(path), "status": "absent"}
    with open(path, "rb") as stream:
        try:
            trailer = _parse(stream, report)
            if trailer is None:
                report["content_size"] = report["file_size"]
            else:
                report["status"] = "valid"
                metadata, canonical = _decode(trailer["raw"])
                report.update(
                    canonical=canonical,
                    signed="signature" in metadata,
                    fields=sorted(metadata),
                    metadata=metadata,
                )
        except UnsupportedFormatError as exc:
            report.update(status="unsupported", error=str(exc))
        except ValueError as exc:
            report.update(status="invalid", error=str(exc))
        if compute_hash and "content_size" in report:
            report["content_sha256"] = _hash_prefix(stream, report["content_size"], "file truncated while hashing")
            if "sha256" in report.get("metadata", {}):
                report["sha256_matches"] = report["metadata"]["sha256"] == report["content_sha256"]
    return report


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
    # Одинаково для всех версий формата: подпись не зависит от вида футера.
    return MAGIC + b"\x00" + encode_metadata(metadata)


def verify(path=None, public_key=None):
    """Проверить подпись всех полей и SHA-256 исходной части файла.

    Без path проверяется собственный бинарник приложения (см. executable_path).
    """
    if public_key is None:
        raise TypeError("verify() requires public_key")
    if path is None:
        path = executable_path()
    exceptions, _, _ = _crypto()
    key = load_key(public_key)
    with open(path, "rb") as stream:
        metadata, base_size, canonical, _ = _read(stream)
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
        if signed.get("sha256") != _hash_prefix(stream, base_size, "binary truncated during verification"):
            raise ValueError("binary SHA-256 mismatch")
        return signed


def _rewrite(path, make_tail):
    """Скопировать исходные данные без трейлера во временный файл и атомарно заменить.

    make_tail(digest, format_version) возвращает байты нового трейлера или None,
    если файл менять не нужно.
    """
    path = Path(path).resolve(strict=True)
    temporary = None
    try:
        with path.open("rb") as source:
            _, base_size, _, current_format = _read(source)
            tail = make_tail(None, current_format)
            if tail is None:
                return False
            source.seek(0)
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as target:
                temporary = Path(target.name)
                remaining = base_size
                digest = hashlib.sha256()
                while remaining:
                    chunk = source.read(min(remaining, CHUNK))
                    if not chunk:
                        raise ValueError("source changed while stamping")
                    target.write(chunk)
                    digest.update(chunk)
                    remaining -= len(chunk)
                target.write(make_tail(digest.hexdigest(), current_format))
                target.flush()
                os.fsync(target.fileno())
        shutil.copymode(path, temporary)
        os.replace(temporary, path)
        return True
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def stamp(path, metadata, private_key=None, format_version=None):
    """Заменить существующий трейлер.

    format_version=None означает DEFAULT_FORMAT.
    """
    data = encode_metadata(metadata)
    if "sha256" in metadata or "signature" in metadata:
        raise ValueError("sha256 and signature are generated fields")
    if format_version is not None:
        encode_footer(b"", format_version)
    key = load_key(private_key, private=True) if private_key is not None else None

    def make_tail(digest, current_format):
        chosen = format_version or DEFAULT_FORMAT
        if digest is None:
            return b""
        payload = data
        if key is not None:
            signed = dict(metadata, sha256=digest)
            signature = base64.b64encode(key.sign(signing_bytes(signed))).decode("ascii")
            payload = encode_metadata(dict(signed, signature=signature))
        return payload + encode_footer(payload, chosen)

    _rewrite(path, make_tail)


def strip(path):
    """Удалить трейлер. Вернуть False, если его не было (файл не меняется)."""
    return _rewrite(path, lambda digest, current_format: None if current_format is None else b"")
