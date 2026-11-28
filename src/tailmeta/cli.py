"""Command-line interface for tailmeta."""
import argparse
import json
import sys
from . import __version__
from ._core import DEFAULT_FORMAT, FORMAT_VERSIONS, MAX_METADATA, generate_keys, inspect, is_unsafe_char, read_metadata, stamp, strip, verify
from ._http import read_metadata_url


def _escape(char):
    if not is_unsafe_char(char):
        return char
    code = ord(char)
    if code > 0xFFFF:
        code -= 0x10000
        return f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}"
    return f"\\u{code:04x}"


def escape(text):
    return "".join(map(_escape, text))


def dump_json(value):
    """JSON с читаемым Unicode, но без сырых управляющих символов терминала."""
    return escape(json.dumps(value, ensure_ascii=False))


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key in metadata file: {key!r}")
        result[key] = value
    return result


def load_metadata_file(path):
    """Прочитать JSON-объект из файла или из stdin ("-")."""
    if path == "-":
        data = sys.stdin.buffer.read(MAX_METADATA + 1)
    else:
        with open(path, "rb") as stream:
            data = stream.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError("metadata file exceeds 1 MiB")
    try:
        value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_reject_duplicates)
    except UnicodeError as exc:
        raise ValueError("metadata file is not valid UTF-8") from exc
    except RecursionError as exc:
        raise ValueError("metadata file is nested too deeply") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"metadata file is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("metadata file must contain a JSON object")
    return value


def format_report(report):
    def yes(value):
        return "yes" if value else "no"

    lines = [("path", escape(report["path"])), ("status", report["status"])]
    if "error" in report:
        lines.append(("error", escape(report["error"])))
    lines.append(("file size", report["file_size"]))
    if "format_version" in report:
        lines.append(("format version", report["format_version"]))
    if "content_size" in report:
        lines.append(("content size", report["content_size"]))
    if "trailer_offset" in report:
        lines.append(("trailer offset", report["trailer_offset"]))
        parts = [f'metadata {report["metadata_length"]}']
        if "signature_length" in report:
            parts.append(f'signatures {report["signature_length"]}')
        parts.append(f'footer {report["footer_size"]}')
        lines.append(("trailer size", f'{report["trailer_size"]} ({" + ".join(parts)})'))
    if "crc32" in report:
        lines.append(("crc32", report["crc32"]))
    if "canonical" in report:
        lines.append(("canonical JSON", yes(report["canonical"])))
        lines.append(("signed", yes(report["signed"])))
    for entry in report.get("signatures", ()):
        lines.append(("signature", f'{entry["name"]} (algorithm {entry["algorithm"]:#06x}, {entry["length"]} bytes)'))
    if "content_sha256" in report:
        lines.append(("content sha256", report["content_sha256"]))
    if "sha256_matches" in report:
        lines.append(("sha256 field", "matches content" if report["sha256_matches"] else "DOES NOT match content"))
    if "metadata" in report:
        lines.append(("fields", escape(", ".join(report["fields"]))))
        lines.append(("version", escape(report["metadata"]["version"])))
    return "\n".join(f"{label + ':':<16}{value}" for label, value in lines)


def main():
    parser = argparse.ArgumentParser(prog="tailmeta", description=__doc__)
    parser.add_argument("--version", action="version", version=f"tailmeta {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    writer = commands.add_parser("stamp", help="write or replace the trailer")
    writer.add_argument("path")
    writer.add_argument("--version", help="required unless --metadata provides it")
    writer.add_argument("--commit")
    writer.add_argument("--channel")
    writer.add_argument("--metadata", metavar="FILE", help='JSON object with metadata fields ("-" reads stdin); flags override its fields')
    writer.add_argument("--format", type=int, choices=FORMAT_VERSIONS, help=f"trailer format version (default: {DEFAULT_FORMAT})")
    writer.add_argument("--private-key", help="optionally sign with an Ed25519 private PEM key")
    checker = commands.add_parser("verify", help="verify a signed trailer")
    checker.add_argument("path")
    checker.add_argument("--public-key", required=True)
    generator = commands.add_parser("keygen", help="generate an Ed25519 key pair")
    generator.add_argument("--private-key", required=True)
    generator.add_argument("--public-key", required=True)
    reader = commands.add_parser("read", help="print untrusted metadata of a file or http(s) URL")
    reader.add_argument("path", help="local path, or an http:// or https:// URL read with Range requests")
    reader.add_argument("--version-only", action="store_true")
    reader.add_argument("--timeout", type=float, default=30, help="network timeout in seconds for URLs")
    remover = commands.add_parser("strip", help="remove the trailer, restoring the original bytes")
    remover.add_argument("path")
    analyzer = commands.add_parser("inspect", help="describe the trailer in detail")
    analyzer.add_argument("path")
    analyzer.add_argument("--json", action="store_true", help="print the report as JSON")
    analyzer.add_argument("--no-hash", action="store_true", help="skip hashing the file content")
    args = parser.parse_args()
    try:
        if args.command == "stamp":
            metadata = load_metadata_file(args.metadata) if args.metadata is not None else {}
            metadata.update({key: getattr(args, key) for key in ("version", "commit", "channel") if getattr(args, key) is not None})
            stamp(args.path, metadata, args.private_key, args.format)
        elif args.command == "verify":
            print(dump_json(verify(args.path, args.public_key)))
        elif args.command == "keygen":
            generate_keys(args.private_key, args.public_key)
        elif args.command == "strip":
            if not strip(args.path):
                print("metadata not found, file unchanged", file=sys.stderr)
        elif args.command == "inspect":
            report = inspect(args.path, compute_hash=not args.no_hash)
            print(dump_json(report) if args.json else format_report(report))
            if report["status"] != "valid":
                parser.exit(1)
        else:
            if args.path.startswith(("http://", "https://")):
                metadata = read_metadata_url(args.path, args.timeout)
            else:
                metadata = read_metadata(args.path)
            if metadata is None:
                parser.exit(1, "metadata not found\n")
            print(metadata["version"] if args.version_only else dump_json(metadata))
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
