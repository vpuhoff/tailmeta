"""Форматы трейлера. Полная спецификация — SPEC.md.

v3: [данные][UTF-8 JSON][блок подписей][uint32 CRC32][uint32 длина JSON]
    [uint32 длина блока подписей][uint16 версия = 3][uint16 флаги][TAILMETV]
v2: [данные][UTF-8 JSON][uint32 CRC32][uint32 длина][uint16 версия = 2][uint16 флаги][TAILMETV]

v3 подписывает сырые байты JSON в том виде, в каком они лежат в файле, вместе
с идентификатором алгоритма и хешем содержимого: каноническая сериализация JSON
для проверки подписи не нужна. v2 только читается, обрезается и перезаписывается
в v3; его подписи (внутри JSON) больше не проверяются.

Устаревший v1 ([данные][UTF-8 JSON][uint32 длина][TAILMETA]) больше не
поддерживается: его магия распознаётся, и любая операция отказывает с
UnsupportedFormatError, как для неизвестной версии.

Последние 12 байт версионированного трейлера ([версия][флаги][TAILMETV])
стабильны для всех будущих версий: читатель всегда может узнать версию
формата и отказаться от неизвестной, а не принять её за отсутствие трейлера.
"""
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

# Магия выведенного из употребления v1.
MAGIC = b"TAILMETA"
MAGIC_VERSIONED = b"TAILMETV"
FOOTER_V2 = struct.Struct(">IIHH8s")
FOOTER_V3 = struct.Struct(">IIIHH8s")
VERSION_TAIL = struct.Struct(">HH8s")
# Запись блока подписей v3: [uint16 алгоритм][uint32 длина подписи][подпись].
SIGNATURE_ENTRY = struct.Struct(">HI")
# Версии, которые пишет stamp; READABLE_FORMATS — которые читаются.
FORMAT_VERSIONS = (3,)
READABLE_FORMATS = (2, 3)
DEFAULT_FORMAT = 3
MAX_METADATA = 1024 * 1024
MAX_SIGNATURES = 64 * 1024
# Реестр алгоритмов подписи v3 (SPEC.md). Идентификатор задаёт и схему подписи,
# и хеш содержимого; значения не переиспользуются.
ED25519 = 0x0001
ALGORITHMS = {ED25519: "ed25519"}
SIGNING_CONTEXT_V3 = b"tailmeta/v3/signature\x00"
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


def encode_footer(data, format_version, signatures=b""):
    if format_version == 3:
        return FOOTER_V3.pack(zlib.crc32(data + signatures), len(data), len(signatures), 3, 0, MAGIC_VERSIONED)
    if format_version == 2 and not signatures:
        return FOOTER_V2.pack(zlib.crc32(data), len(data), 2, 0, MAGIC_VERSIONED)
    raise UnsupportedFormatError(f"unsupported format version: {format_version!r}")


def encode_signatures(entries):
    return b"".join(SIGNATURE_ENTRY.pack(algorithm, len(signature)) + signature for algorithm, signature in entries)


def decode_signatures(block):
    """Разобрать блок подписей v3 в список (алгоритм, подпись).

    Неизвестные алгоритмы не ошибка: их записи пропускаются при проверке.
    """
    entries, offset = [], 0
    while offset < len(block):
        if len(block) - offset < SIGNATURE_ENTRY.size:
            raise ValueError("invalid signature block")
        algorithm, length = SIGNATURE_ENTRY.unpack_from(block, offset)
        offset += SIGNATURE_ENTRY.size
        if not 0 < length <= len(block) - offset:
            raise ValueError("invalid signature block")
        entries.append((algorithm, block[offset:offset + length]))
        offset += length
    return entries


def signed_message_v3(algorithm, content_digest, raw):
    """Сообщение подписи v3: контекст, алгоритм, SHA-256 содержимого и сырые байты JSON."""
    return SIGNING_CONTEXT_V3 + struct.pack(">H", algorithm) + content_digest + raw


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
    if format_version not in READABLE_FORMATS:
        raise UnsupportedFormatError(f"unsupported format version: {format_version}")
    if flags:
        raise UnsupportedFormatError(f"unsupported trailer flags: {flags:#06x}")
    footer = FOOTER_V3 if format_version == 3 else FOOTER_V2
    if size < footer.size:
        raise ValueError("invalid metadata length")
    stream.seek(-footer.size, os.SEEK_END)
    fields = footer.unpack(_read_exact(stream, footer.size))
    checksum, length = fields[:2]
    signature_length = fields[2] if format_version == 3 else 0
    report.update(footer_size=footer.size, metadata_length=length, crc32=f"{checksum:08x}")
    if format_version == 3:
        report["signature_length"] = signature_length
    available = size - footer.size
    if not 0 < length <= min(MAX_METADATA, available):
        raise ValueError("invalid metadata length")
    if signature_length > min(MAX_SIGNATURES, available - length):
        raise ValueError("invalid signature block length")
    start = available - length - signature_length
    report.update(content_size=start, trailer_offset=start, trailer_size=size - start)
    stream.seek(start)
    body = _read_exact(stream, length + signature_length)
    if zlib.crc32(body) != checksum:
        raise ValueError("metadata checksum mismatch")
    signatures = decode_signatures(body[length:]) if format_version == 3 else None
    if signatures is not None:
        report["signatures"] = [
            {"algorithm": algorithm, "name": ALGORITHMS.get(algorithm, "unknown"), "length": len(signature)}
            for algorithm, signature in signatures
        ]
    return {"format_version": format_version, "start": start, "raw": body[:length], "signatures": signatures}


def _unique_keys(pairs):
    # Дубликаты ключей запрещены: разные парсеры выбирают разное значение, и
    # подписанные байты показали бы разным читателям разные данные.
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate key in metadata")
    return result


def _decode(raw):
    try:
        metadata = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_keys)
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a JSON object")
        canonical = encode_metadata(metadata) == raw
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid metadata JSON") from exc
    return metadata, canonical


def _read(stream):
    """Вернуть (metadata, trailer): metadata None, если трейлера нет.

    trailer всегда содержит start (конец исходного содержимого) и format_version
    (None без трейлера), а при наличии трейлера — raw, signatures и canonical.
    """
    trailer = _parse(stream)
    if trailer is None:
        return None, {"start": stream.seek(0, os.SEEK_END), "format_version": None}
    metadata, trailer["canonical"] = _decode(trailer["raw"])
    return metadata, trailer


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
                signed = bool(trailer["signatures"]) if trailer["format_version"] == 3 else "signature" in metadata
                report.update(
                    canonical=canonical,
                    signed=signed,
                    fields=sorted(metadata),
                    metadata=metadata,
                )
        except UnsupportedFormatError as exc:
            report.update(status="unsupported", error=str(exc))
        except ValueError as exc:
            report.update(status="invalid", error=str(exc))
        if compute_hash and "content_size" in report:
            report["content_sha256"] = _hash_prefix(stream, report["content_size"], "file truncated while hashing")
            if report.get("format_version") == 2 and "sha256" in report.get("metadata", {}):
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


def _verify_v3(stream, key, exceptions, metadata, trailer):
    if not trailer["signatures"]:
        raise ValueError("signed metadata required")
    # Алгоритм определяется ключом проверяющего, а не файлом: запись с другим
    # идентификатором никогда не проверяется этим ключом.
    candidates = [signature for algorithm, signature in trailer["signatures"] if algorithm == ED25519]
    if not candidates:
        raise ValueError("no signature for algorithm ed25519")
    digest = _hash_prefix(stream, trailer["start"], "binary truncated during verification")
    message = signed_message_v3(ED25519, bytes.fromhex(digest), trailer["raw"])
    for signature in candidates:
        try:
            key.verify(signature, message)
            break
        except exceptions.InvalidSignature:
            continue
    else:
        raise ValueError("signature verification failed")
    return dict(metadata, sha256=digest)


def verify(path=None, public_key=None):
    """Проверить подпись метаданных и SHA-256 исходной части файла.

    Возвращает проверенные поля и sha256 содержимого (без signature).
    Без path проверяется собственный бинарник приложения (см. executable_path).
    """
    if public_key is None:
        raise TypeError("verify() requires public_key")
    if path is None:
        path = executable_path()
    exceptions, _, _ = _crypto()
    key = load_key(public_key)
    with open(path, "rb") as stream:
        metadata, trailer = _read(stream)
        if metadata is None:
            raise ValueError("signed metadata required")
        if trailer["format_version"] != 3:
            raise UnsupportedFormatError("signatures in trailer format v2 are not supported; restamp the file")
        return _verify_v3(stream, key, exceptions, metadata, trailer)


def _rewrite(path, make_tail):
    """Скопировать исходные данные без трейлера во временный файл и атомарно заменить.

    make_tail(digest, format_version) возвращает байты нового трейлера или None,
    если файл менять не нужно.
    """
    path = Path(path).resolve(strict=True)
    temporary = None
    try:
        with path.open("rb") as source:
            _, trailer = _read(source)
            base_size, current_format = trailer["start"], trailer["format_version"]
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
    if format_version is not None and format_version not in FORMAT_VERSIONS:
        raise UnsupportedFormatError(f"unsupported format version: {format_version!r}")
    key = load_key(private_key, private=True) if private_key is not None else None

    def make_tail(digest, current_format):
        chosen = format_version or DEFAULT_FORMAT
        if digest is None:
            return b""
        signatures = b""
        if key is not None:
            signature = key.sign(signed_message_v3(ED25519, bytes.fromhex(digest), data))
            signatures = encode_signatures([(ED25519, signature)])
        return data + signatures + encode_footer(data, chosen, signatures)

    _rewrite(path, make_tail)


def strip(path):
    """Удалить трейлер. Вернуть False, если его не было (файл не меняется)."""
    return _rewrite(path, lambda digest, current_format: None if current_format is None else b"")
