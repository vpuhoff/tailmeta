"""Compatibility shim. Prefer `python -m tailmeta` and `from tailmeta import ...`."""
from tailmeta import generate_keys, read_metadata, stamp, verify
from tailmeta.cli import main

if __name__ == "__main__":
    main()
