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
python -m tailmeta stamp app.bin --metadata metadata.json --version 1.2.6
python -m tailmeta inspect app.bin
python -m tailmeta strip app.bin
python -m tailmeta read https://example.com/downloads/app.bin
python -m tailmeta --version
```

Installation also provides the `tailmeta` command with the same arguments.
`stamp` requires an existing file, preserves its original bytes, and replaces
any previous tailmeta trailer. Repeated writes do not accumulate metadata.
`read` does not verify authenticity, even when the trailer is signed.
The `read` command exits with code 1 when metadata is absent. File, format,
and verification errors also produce exit code 1.

`stamp --metadata FILE` loads a JSON object from `FILE` (`-` reads stdin) and
uses it as the metadata. `--version`, `--commit` and `--channel` override the
fields of the same name, and `--version` may be omitted when the file provides
it. The file must be UTF-8 JSON of at most 1 MiB without duplicate keys.
`stamp --format {1,2}` selects the trailer format (see below); without it the
format of the existing trailer is kept, and new trailers use v2.

`strip` removes the trailer and restores the original bytes, using the same
atomic replacement as `stamp`. A file without a trailer is left untouched
(exit code 0, a note on stderr). A damaged or unsupported trailer is an error,
because its boundaries cannot be trusted.

`inspect` prints a diagnostic report: file and content sizes, trailer offset
and size, format version, CRC32 (v2), whether the JSON is canonical, whether
the trailer is signed, the SHA-256 of the content and whether it matches the
`sha256` field, and the field names. Damaged trailers are reported with the
step that failed instead of only an error message. `--json` prints the report
as JSON, `--no-hash` skips hashing large files. The exit code is 0 only for a
valid trailer. A matching `sha256` shows integrity, not authenticity: use
`verify` for that.

`read` also accepts an `http://` or `https://` URL. The trailer is read with
HTTP Range requests: one request for the last 64 KiB, plus one more when the
metadata is larger, so the file itself is not downloaded. The server must
answer with `206 Partial Content`; servers that ignore `Range` or compress the
response are rejected instead of downloading the whole file. `--timeout`
sets the network timeout in seconds (default 30). Signatures cannot be
verified this way, since `verify` hashes the full content.

## Python API

```python
from tailmeta import read_metadata, stamp

stamp("app.bin", {"version": "1.2.4", "channel": "stable"})
metadata = read_metadata("app.bin")
print(metadata["version"] if metadata else "unknown")
```

`stamp(path, metadata, private_key=None)` accepts a dictionary containing a
required nonempty `version` string and optional additional JSON fields.
The `version` string must not contain control or formatting characters
(Unicode categories Cc, Cf, Zl, Zp: newlines, escape sequences, bidi
overrides); trailers with such a version are rejected on read as well.
`sha256` and `signature` are reserved and generated during signing.
`read_metadata(path)` returns a dictionary, or `None` if no trailer is found.
A recognized but malformed trailer raises `ValueError`; file errors raise
`OSError`. Paths may be strings or `pathlib.Path` objects.

```python
from tailmeta import inspect, read_metadata_url, strip

stamp("app.bin", {"version": "1.2.4"}, format_version=2)
report = inspect("app.bin")            # dict; report["status"] == "valid"
strip("app.bin")                       # True if a trailer was removed
read_metadata_url("https://example.com/app.bin", timeout=10)
```

`stamp(..., format_version=None)` keeps the current format, or uses v2 for a
file without a trailer. `inspect(path, compute_hash=True)` never raises on a
damaged trailer: `status` is `absent`, `valid`, `invalid` or `unsupported`,
and `error` explains the last two. `read_metadata_url(url, timeout=30)` returns
the same untrusted data as `read_metadata`; network errors raise `OSError`.
A trailer with an unknown format version or flags raises
`UnsupportedFormatError`, a subclass of `ValueError`.

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
`signature`. Unsigned files are rejected, as are signed trailers whose JSON
bytes differ from the canonical encoding described below.

Ed25519 keys use PEM encoding. Private keys are created unencrypted with mode
0600. `keygen` refuses to overwrite existing keys.
Running `stamp` again without a key replaces a signed trailer with an unsigned
one. Signing authenticates the current bytes without checking any previous
signature.

## Security model

- `read` and `read_metadata` return **untrusted** data. Anyone who can modify
  the file can write any metadata. Use `verify` when authenticity matters.
  The CLI escapes control characters in JSON output, and `--version-only`
  prints only versions that passed the character check above.
- `verify` proves that the trailer and the original bytes were signed by the
  holder of the private key. Run it in a **trusted** component (installer,
  updater, release pipeline) that ships its own copy of the public key.
  A program that verifies itself, like the Nuitka example below, is not a
  security boundary: whoever can replace the binary can also remove the check
  or point it at a different key.
- There is no rollback protection: every binary that was ever signed keeps
  verifying. Compare the verified `version` against the installed one if
  downgrades must be refused.
- Keep the private key outside the repository and the build output; it is
  stored unencrypted, so protect it with file permissions or a secret store.

## Trailer formats

```text
v1: [original file][UTF-8 JSON][length: uint32][TAILMETA]
v2: [original file][UTF-8 JSON][CRC32: uint32][length: uint32][format: uint16 = 2][flags: uint16 = 0][TAILMETV]
```

All integers are big endian. v1 ends with the magic bytes `TAILMETA` and has
no version field. v2 and every later format end with `TAILMETV`, preceded by
the format version and flags: these last 12 bytes keep the same layout in all
future versions, so a reader always learns the version before interpreting
anything else. The layout before them belongs to the specific version.
In v2 the CRC32 (zlib polynomial) covers the JSON bytes and detects
corruption that still leaves valid JSON. Flags are reserved; v2 requires
zero.

A reader that finds `TAILMETV` with a format version or flags it does not
know raises `UnsupportedFormatError`. `stamp` and `strip` refuse such files
instead of discarding data written by a newer release.

### Compatibility matrix

| Trailer in the file       | tailmeta ≤ 0.1.5           | tailmeta ≥ 0.2            |
|---------------------------|----------------------------|---------------------------|
| none                      | read: not found            | read: not found           |
| v1 (`TAILMETA`)           | read, stamp, verify        | read, stamp, strip, inspect, verify |
| v2 (`TAILMETV`, format 2) | treated as absent¹         | read, stamp, strip, inspect, verify |
| `TAILMETV`, format ≥ 3    | treated as absent¹         | `UnsupportedFormatError`; stamp/strip refuse |

| tailmeta ≥ 0.3 writes       | when                                   |
|-----------------------------|----------------------------------------|
| v2                          | default for files without a trailer, or `--format 2` |
| the existing trailer format | `stamp` without `--format`             |
| v1                          | `--format 1` / `format_version=1`      |

tailmeta 0.2.0 wrote v1 by default; since 0.3.0 new trailers use v2.

¹ Older releases do not know the `TAILMETV` magic: `read` reports that no
metadata was found, and `stamp` appends a v1 trailer after the v2 one instead
of replacing it. Pass `--format 1` if a consumer still runs ≤ 0.1.5.

The signature covers the JSON only, so a signed trailer stays valid when its
footer is converted between v1 and v2. `tests/test_formats.py` contains the
exact bytes of both formats; they must keep reading in every release.

### Encoding

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
explicitly with `--public-key`. This demonstrates the API only: see the
security model above for why self-verification does not stop tampering.

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
