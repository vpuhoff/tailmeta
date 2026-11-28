#!/usr/bin/env python3
"""Nuitka example: read the version; verify only when explicitly requested.

Self-verification demonstrates the API but is not a security boundary: an
attacker who can replace this binary can also remove the check. Verify from a
trusted component (installer, updater) that holds its own public key.
"""
import argparse
import sys
from tailmeta import read_metadata, verify


def get_embedded_version(public_key=None):
    # Without a path both functions read this executable itself.
    metadata = verify(public_key=public_key) if public_key else read_metadata()
    return metadata["version"] if metadata else "unknown"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-key", help="verify signature before reading the version")
    args = parser.parse_args()
    try:
        print(f"version={get_embedded_version(args.public_key)}")
    except (OSError, ValueError, RuntimeError) as exc:
        sys.exit(f"verification failed: {exc}")
