"""Command-line interface for tailmeta."""
import argparse
import json
from . import __version__
from ._core import generate_keys, read_metadata, stamp, verify


def main():
    parser = argparse.ArgumentParser(prog="tailmeta", description=__doc__)
    parser.add_argument("--version", action="version", version=f"tailmeta {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    writer = commands.add_parser("stamp")
    writer.add_argument("path")
    writer.add_argument("--version", required=True)
    writer.add_argument("--commit")
    writer.add_argument("--channel")
    writer.add_argument("--private-key", help="optionally sign with an Ed25519 private PEM key")
    checker = commands.add_parser("verify")
    checker.add_argument("path")
    checker.add_argument("--public-key", required=True)
    generator = commands.add_parser("keygen")
    generator.add_argument("--private-key", required=True)
    generator.add_argument("--public-key", required=True)
    reader = commands.add_parser("read")
    reader.add_argument("path")
    reader.add_argument("--version-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "stamp":
            stamp(args.path, {key: getattr(args, key) for key in ("version", "commit", "channel") if getattr(args, key) is not None}, args.private_key)
        elif args.command == "verify":
            print(json.dumps(verify(args.path, args.public_key), ensure_ascii=False))
        elif args.command == "keygen":
            generate_keys(args.private_key, args.public_key)
        else:
            metadata = read_metadata(args.path)
            if metadata is None:
                parser.exit(1, "metadata not found\n")
            print(metadata["version"] if args.version_only else json.dumps(metadata, ensure_ascii=False))
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"error: {exc}\n")


if __name__ == "__main__":
    main()
