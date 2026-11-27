# tailmeta

Store version information and metadata in the trailer of a built file. Assign
versions after building, read them without running the application, and update
them without rebuilding. Ed25519 signing is optional.

Requires Python 3.10+. The base installation has no third-party dependencies.
Published on [PyPI](https://pypi.org/project/tailmeta/).

## Installation

```bash
python -m pip install tailmeta
# With signing support:
python -m pip install 'tailmeta[signing]'
```

From the project directory (development):

```bash
python -m pip install .
python -m pip install '.[signing]'
```

## Command-line usage

```bash
python -m tailmeta stamp app.bin --version 1.2.4
python -m tailmeta read app.bin
python -m tailmeta read app.bin --version-only
python -m tailmeta stamp app.bin --version 1.2.5 --channel stable --commit abc123
python -m tailmeta --version
```

Installation also provides the `tailmeta` command with the same arguments.
`stamp` requires an existing file, preserves its original bytes, and replaces
any previous tailmeta trailer. Repeated writes do not accumulate metadata.
`read` does not verify authenticity, even when the trailer is signed.
The `read` command exits with code 1 when metadata is absent. File, format,
and verification errors also produce exit code 1.

## Python API

```python
from tailmeta import read_metadata, stamp

stamp("app.bin", {"version": "1.2.4", "channel": "stable"})
metadata = read_metadata("app.bin")
print(metadata["version"] if metadata else "unknown")
```

`stamp(path, metadata, private_key=None)` accepts a dictionary containing a
required nonempty `version` string and optional additional JSON fields.
`sha256` and `signature` are reserved and generated during signing.
`read_metadata(path)` returns a dictionary, or `None` if no trailer is found.
A recognized but malformed trailer raises `ValueError`; file errors raise
`OSError`. Paths may be strings or `pathlib.Path` objects.

## Optional signing

```bash
python -m tailmeta keygen --private-key private.pem --public-key public.pem
python -m tailmeta stamp app.bin --version 1.2.4 --private-key private.pem
python -m tailmeta verify app.bin --public-key public.pem
```

```python
from tailmeta import generate_keys, stamp, verify

generate_keys("private.pem", "public.pem")
stamp("app.bin", {"version": "1.2.4"}, private_key="private.pem")
metadata = verify("app.bin", public_key="public.pem")
```

Install the `signing` extra to use these operations. Without it, version reads
and writes still work; signing operations report the missing dependency.
`verify` checks the signature over all metadata fields and the SHA-256 hash of
the original file content, then returns the verified fields without
`signature`. Unsigned files are rejected.

Ed25519 keys use PEM encoding. Private keys are created unencrypted with mode
0600. `keygen` refuses to overwrite existing keys.
Running `stamp` again without a key replaces a signed trailer with an unsigned
one. Signing authenticates the current bytes without checking any previous
signature.

## Trailer format v1

```text
[original file][UTF-8 JSON][JSON length: uint32 big endian][TAILMETA: 8 bytes]
```

The trailer ends with the eight magic bytes `TAILMETA`.
JSON is limited to 1 MiB. Keys are sorted, and serialization uses
`ensure_ascii=False`, `allow_nan=False`, and `separators=(",", ":")`.
The signed message is `b"TAILMETA\x00" + JSON`, excluding the `signature` field.
This uses Python JSON serialization, not JCS. The signature is Base64-encoded;
`sha256` is the hexadecimal SHA-256 digest of the original content before the
JSON trailer.

Writing copies the original content into a temporary file in the same directory
and atomically replaces the destination, preserving its permission bits.
Symbolic links are resolved to their targets. Ownership, ACLs, extended
attributes, and hard-link relationships are not explicitly preserved.
Concurrent writes are unsupported. Damaged magic bytes cannot be distinguished
from an absent trailer.

## Nuitka example

`examples/nuitka/main.py` reads the version of its own onefile executable and
prints `unknown` when metadata is absent. Signature verification is enabled
explicitly with `--public-key`.

```bash
make deps
make build
make stamp VERSION=1.2.4
make version
make run

# Optional: generate demo keys and sign the executable.
make keygen
make sign VERSION=1.2.4
make verify
./dist/main.bin --public-key demo-keys/public.pem
```

The Makefile uses `.venv/bin/python`. `make deps` installs the package in editable
mode with the `signing` extra, along with the tools for the Nuitka example.
The example requires gcc and a system installation of `patchelf`
(on Ubuntu: `sudo apt-get install gcc patchelf`).
