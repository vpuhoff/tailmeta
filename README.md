# tailmeta

Store version information and metadata in the trailer of a built file. Assign
versions after building, read them without running the application, and update
them without rebuilding. Ed25519 signing is optional.

Requires Python 3.10+. Published on [PyPI](https://pypi.org/project/tailmeta/).
The binary format is specified in [SPEC.md](SPEC.md).

## Principles

- **No mandatory third-party dependencies.** Reading, writing, stripping,
  inspecting and HTTP reads use only the Python standard library.
- **Cryptography is optional.** Signing and verification need the `signing`
  extra (`cryptography`); everything else works without it.
- **No home-grown cryptography.** Signatures are Ed25519 from a maintained
  library; tailmeta only defines what is signed.
- **A minimal dependency tree.** The optional extra adds one direct
  dependency.
- **An open binary format.** [SPEC.md](SPEC.md) describes every byte, with test
  vectors, so the format does not depend on this implementation.
- **Independent implementations are possible.** Verification needs no JSON
  canonicalization: signatures cover the stored bytes, so a reader in any
  language with an Ed25519 and SHA-256 library can verify a file.

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
`stamp` always writes trailer format v3 (`--format 3` is accepted for
explicitness) and replaces a v2 trailer with a v3 one. A file with a retired
v1 trailer is refused (see below).

`strip` removes the trailer and restores the original bytes, using the same
atomic replacement as `stamp`. A file without a trailer is left untouched
(exit code 0, a note on stderr). A damaged or unsupported trailer is an error,
because its boundaries cannot be trusted.

`inspect` prints a diagnostic report: file and content sizes, trailer offset
and size, format version, CRC32, whether the JSON is canonical, whether the
trailer is signed and with which algorithms (v3), the SHA-256 of the content
and, for v2, whether it matches the `sha256` field, and the field names.
Damaged trailers are reported with the step that failed instead of only an
error message. `--json` prints the report as JSON, `--no-hash` skips hashing
large files. The exit code is 0 only for a valid trailer. A matching `sha256` shows integrity, not authenticity: use
`verify` for that.

`read` also accepts an `http://` or `https://` URL. The trailer is read with
HTTP Range requests: one request for the last 64 KiB, plus one more when the
metadata is larger, so the file itself is not downloaded. The server must
answer with `206 Partial Content`; servers that ignore `Range` or compress the
response are rejected instead of downloading the whole file. `--timeout`
sets the network timeout in seconds (default 30). Signatures cannot be
verified this way, since `verify` hashes the full content.

The requests must all see the same file. A strong `ETag` from the first
response is sent back in `If-Range`, so a server whose file was replaced
answers `200` and the read is aborted. Every response must also repeat the
`ETag`, `Last-Modified` and total size of the first one; any difference,
including a header that appears or disappears, raises `remote file changed
while reading`. This covers weak ETags and servers that ignore `If-Range`.
Behind a CDN or load balancer whose nodes report different ETags for the same
file, reads that need a second request fail rather than risk mixing versions.

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
`sha256` and `signature` are reserved field names.
`read_metadata(path=None)` returns a dictionary, or `None` if no trailer is found.
A recognized but malformed trailer raises `ValueError`; file errors raise
`OSError`. Paths may be strings or `pathlib.Path` objects.

```python
from tailmeta import inspect, read_metadata_url, strip

stamp("app.bin", {"version": "1.2.4"}, format_version=2)
report = inspect("app.bin")            # dict; report["status"] == "valid"
strip("app.bin")                       # True if a trailer was removed
read_metadata_url("https://example.com/app.bin", timeout=10)
```

`stamp(..., format_version=None)` writes v3; `format_version=3` is the only
accepted value. `inspect(path, compute_hash=True)` never raises on a
damaged trailer: `status` is `absent`, `valid`, `invalid` or `unsupported`,
and `error` explains the last two. `read_metadata_url(url, timeout=30)` returns
the same untrusted data as `read_metadata`; network errors raise `OSError`.
A v1 trailer, or one with an unknown format version or flags, raises
`UnsupportedFormatError`, a subclass of `ValueError`. Metadata with duplicate
keys is rejected as malformed.

### Reading the running executable

Inside a compiled application, `read_metadata()` and
`verify(public_key="public.pem")` can be called without a path: they read the
application's own executable, as returned by `executable_path()`.

```python
from tailmeta import read_metadata

metadata = read_metadata()   # this executable
print(metadata["version"] if metadata else "unknown")
```

- **Nuitka** (onefile and standalone): `sys.argv[0]`. Nuitka replaces it with
  the absolute, symlink-resolved path of the binary, also when the program is
  started by name from `PATH`, through a symlink or with a custom `argv[0]`.
  `sys.executable` and `__file__` are not used: in onefile mode they point to
  the unpacked copy in a temporary directory, which has no trailer.
- **PyInstaller, cx_Freeze** and other tools that set `sys.frozen`:
  `sys.executable`.
- **Plain Python**: there is no executable to read, so a missing path raises
  `TypeError`.

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
`verify` checks the Ed25519 signature over the stored metadata bytes and the
SHA-256 hash of the original content, then returns the verified fields plus
`sha256`, the hex digest of the verified content. Unsigned files are rejected.

In v3 the signature is not part of the JSON. It lives in a binary signature
block after the metadata, tagged with an algorithm identifier (`0x0001` =
Ed25519 over SHA-256), and signs the metadata bytes exactly as stored, so no
JSON canonicalization is involved. The algorithm is chosen by the verifier's
key, never by the file. A block may hold several signatures (key rotation, a
future second algorithm); `verify` accepts the file if one of the entries for
its algorithm is valid and ignores the others.

Signatures written by tailmeta 0.3.x (format v2, inside the JSON) are not
verified: `verify` raises `UnsupportedFormatError`. Stamp the file again with
the private key to sign it in v3.

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

The full byte-level specification, including the signature algorithm registry,
the signed message, verification rules and test vectors, is in
[SPEC.md](SPEC.md). In short:

```text
v3: [original file][UTF-8 JSON][signature block][CRC32: uint32][JSON length: uint32]
    [signature block length: uint32][format: uint16 = 3][flags: uint16 = 0][TAILMETV]
signature block: zero or more [algorithm: uint16][length: uint32][signature]
v2: [original file][UTF-8 JSON][CRC32: uint32][length: uint32][format: uint16 = 2][flags: uint16 = 0][TAILMETV]
```

All integers are big endian. v2 and every later format end with `TAILMETV`,
preceded by the format version and flags: these last 12 bytes keep the same
layout in all future versions, so a reader always learns the version before
interpreting anything else. The CRC32 detects accidental damage; it covers the
JSON and, in v3, the signature block. Flags are reserved and must be zero.

A reader that finds `TAILMETV` with a format version or flags it does not
know raises `UnsupportedFormatError`. `stamp` and `strip` refuse such files
instead of discarding data written by a newer release. New signature
algorithms do not need a new format version: readers skip entries with
identifiers they do not know.

### Legacy v1

v1 (`[original file][UTF-8 JSON][length: uint32][TAILMETA]`, no checksum or
version field) is deprecated and no longer supported. Its magic is still
recognized, so a v1 trailer is never mistaken for the end of the content:
`read`, `verify`, `stamp`, `strip` and the API raise `UnsupportedFormatError`
and leave the file unchanged, and `inspect` reports `status: unsupported` with
`format version: 1`. `--format 1` / `format_version=1` are rejected. To
migrate a v1 file, strip it with tailmeta < 0.4 and stamp it again.

### Compatibility matrix

| Trailer in the file       | tailmeta ≤ 0.1.5    | 0.3.x                   | this release              |
|---------------------------|---------------------|-------------------------|---------------------------|
| none                      | read: not found     | read: not found         | read: not found           |
| v1 (`TAILMETA`)           | read, stamp, verify | read, stamp, verify     | `UnsupportedFormatError`; stamp/strip refuse |
| v2 (`TAILMETV`, format 2) | treated as absent¹  | read, stamp, verify     | read, strip, inspect; stamp writes v3; verify refuses |
| v3 (`TAILMETV`, format 3) | treated as absent¹  | `UnsupportedFormatError` | read, stamp, strip, inspect, verify |
| `TAILMETV`, format ≥ 4    | treated as absent¹  | `UnsupportedFormatError` | `UnsupportedFormatError`; stamp/strip refuse |

tailmeta 0.2.0 wrote v1 by default, 0.3.0 switched new trailers to v2, and
current releases write only v3. Consumers on 0.3.x refuse v3 files with an
error instead of misreading them; upgrade readers before stamping releases
with this version.

¹ Older releases do not know the `TAILMETV` magic: `read` reports that no
metadata was found, and `stamp` appends a v1 trailer after the newer one instead
of replacing it. Consumers still on ≤ 0.1.5 must be upgraded.

`tests/test_formats.py` contains the exact bytes of v3 (unsigned and signed
with the RFC 8032 test key) and v2, which must keep reading in every release,
and of v1, which must keep being refused.

### Encoding

JSON is limited to 1 MiB and the signature block to 64 KiB. `stamp` sorts
keys and serializes with `ensure_ascii=False`, `allow_nan=False` and
`separators=(",", ":")`, so the same metadata always produces the same bytes.
v3 verification does not depend on this encoding.

Writing copies the original content into a temporary file in the same directory
and atomically replaces the destination, preserving its permission bits.
Symbolic links are resolved to their targets. Ownership, ACLs, extended
attributes, and hard-link relationships are not explicitly preserved.
Concurrent writes are unsupported. Damaged magic bytes cannot be distinguished
from an absent trailer.

## Nuitka example

`examples/nuitka/main.py` reads the version of its own onefile executable
with `read_metadata()` (no path) and
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
