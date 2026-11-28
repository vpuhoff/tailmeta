# tailmeta trailer format

Status: stable. Version: format 3 (current), format 2 (read-only legacy, unsigned).

This document specifies the bytes tailmeta appends to a file, so that the
format can be read, written and verified by independent implementations in any
language. The Python package in this repository is one implementation; where it
and this document disagree, the disagreement is a bug in one of them and should
be reported.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as described in
RFC 2119 and RFC 8174.

## 1. Overview

A tailmeta trailer is appended to an arbitrary file (the *content*), typically
a compiled executable. The content is never modified. The trailer holds:

- a JSON object with metadata (at least a `version` string);
- in format 3, an optional block of detached signatures;
- a fixed-size footer that ends the file and lets a reader find everything
  else by reading backwards from the end.

```text
format 3:
+-----------+----------------+------------------+---------------------+
|  content  | metadata JSON  | signature block  |   footer (24 B)     |
+-----------+----------------+------------------+---------------------+
            |<-- M bytes --->|<---- S bytes --->|
```

Because the content is a prefix of the file, removing the trailer restores the
original bytes exactly, and a reader needs only the last few kilobytes of the
file (see section 8 for reading over HTTP).

All integers are unsigned and **big endian**.

## 2. Stable tail

Every versioned trailer ends with the same 12 bytes:

| Offset from end | Size | Field          | Value                     |
|-----------------|------|----------------|---------------------------|
| -12             | 2    | format version | `uint16`                  |
| -10             | 2    | flags          | `uint16`                  |
| -8              | 8    | magic          | ASCII `TAILMETV` (`54 41 49 4c 4d 45 54 56`) |

This layout is frozen for all future format versions. Everything before it is
defined by the format version. A reader therefore always learns the version
before interpreting anything else.

A reader:

1. MUST treat a file shorter than 12 bytes, or one whose last 8 bytes are
   neither `TAILMETV` nor `TAILMETA` (section 7.2), as having **no trailer**.
2. MUST refuse (report "unsupported", not "absent") a trailer whose format
   version it does not implement, or whose flags contain any bit it does not
   implement. Formats 2 and 3 define no flags, so flags MUST be zero.
3. MUST NOT treat an unsupported trailer as absent. A writer MUST NOT modify,
   replace or strip a file with an unsupported trailer, since it cannot know
   where the content ends.

## 3. Format 3

### 3.1 Footer

The footer is the last 24 bytes of the file:

| Offset from end | Size | Field                  |
|-----------------|------|------------------------|
| -24             | 4    | CRC32                  |
| -20             | 4    | metadata length `M`    |
| -16             | 4    | signature block length `S` |
| -12             | 2    | format version = `3`   |
| -10             | 2    | flags = `0`            |
| -8              | 8    | magic `TAILMETV`       |

- **CRC32** is the CRC-32 used by zlib, PNG and gzip (ISO 3309, reflected
  polynomial `0xEDB88320`, initial value and final XOR `0xFFFFFFFF`) computed
  over the `M + S` bytes that follow the content (metadata JSON followed by the
  signature block). It detects accidental damage only; it is not a security
  mechanism.
- `M` MUST satisfy `1 ≤ M ≤ 1 048 576` (1 MiB).
- `S` MUST satisfy `0 ≤ S ≤ 65 536` (64 KiB). `S = 0` means unsigned.
- `M + S + 24` MUST NOT exceed the file size.

The content occupies bytes `[0, file_size − 24 − S − M)`.

### 3.2 Metadata

The `M` metadata bytes are a JSON text (RFC 8259) encoded as UTF-8 without a
byte order mark. Readers MUST reject the trailer if:

- the bytes are not valid UTF-8 or not valid JSON;
- the top-level value is not an object;
- any object, at any depth, contains the same key twice;
- the value of `version` is missing, is not a string, is empty or consists
  only of whitespace, or contains a character of Unicode general category
  Cc, Cf, Zl or Zp (control characters, format characters such as bidi
  overrides, line and paragraph separators);
- the JSON contains `NaN`, `Infinity` or `-Infinity`.

Other fields are free-form JSON. The names `sha256` and `signature` are
reserved: writers MUST NOT emit them in format 3 (they carry meaning in
format 2, and `sha256` is the name under which an implementation reports the
verified content hash).

Writers SHOULD produce a deterministic encoding so that the same metadata
always yields the same bytes. The reference implementation sorts keys by code
point, uses `,` and `:` without whitespace, and writes non-ASCII characters
literally. **Verification does not depend on this encoding**: a signature
covers the metadata bytes exactly as stored (section 4.3), and a reader MUST
NOT re-serialize the JSON before verifying.

### 3.3 Signature block

The signature block is a sequence of zero or more entries, with no padding
between or after them:

| Size | Field                      |
|------|----------------------------|
| 2    | algorithm identifier `uint16` |
| 4    | signature length `L` `uint32` |
| L    | signature bytes            |

`L` MUST be at least 1, and the entries MUST exactly fill the `S` bytes. A
block that ends inside an entry header or an entry body is invalid, and the
whole trailer MUST be rejected.

Several entries allow signing with more than one key (key rotation) or with
more than one algorithm (migration to a new algorithm, hybrid schemes). The
order of entries carries no meaning. Entries are independent: each signs the
same message for its own algorithm (section 4.3).

Readers that only read metadata (no verification) MUST accept entries with
unknown algorithm identifiers.

## 4. Signatures (format 3)

### 4.1 Algorithm registry

An algorithm identifier names a complete *suite*: the signature scheme, its
parameters and the hash used for the content digest. Identifiers are never
reused or redefined.

| Identifier | Name      | Signature scheme                    | Content digest | `L` |
|------------|-----------|-------------------------------------|----------------|-----|
| `0x0000`   | —         | reserved, never valid               | —              | —   |
| `0x0001`   | `ed25519` | Ed25519, pure (RFC 8032, §5.1)      | SHA-256        | 64  |
| `0x0002`–`0x7FFF` | — | unassigned, for future registration in this document | | |
| `0x8000`–`0xFFFF` | — | private use; MUST NOT appear in published files | | |

New algorithms are added by revising this table; they do not need a new
format version, because readers skip entries they do not know.

### 4.2 Keys

Ed25519 public keys are 32 bytes (RFC 8032). The reference implementation
stores them as PEM `SubjectPublicKeyInfo` (RFC 8410) and private keys as
unencrypted PEM PKCS#8, but the key file format is not part of this
specification; only the raw key matters for verification.

The trailer does not identify the signing key. The verifier is configured
with the key(s) it trusts.

### 4.3 Signed message

For an entry with algorithm identifier `A` and content digest function `H`
from the registry, the signed message is the concatenation of:

| Size | Field |
|------|-------|
| 22   | context: ASCII `tailmeta/v3/signature` followed by one `0x00` byte |
| 2    | `A` as `uint16` |
| `|H|` | `H(content)`: raw digest of the content bytes (32 bytes for SHA-256) |
| M    | the metadata bytes, exactly as stored in the file |

All fields before the metadata have a fixed size for a given `A`, so the
encoding is unambiguous without a length prefix.

Including `A` binds every signature to its suite, so an entry cannot be
relabeled as another algorithm. The context string separates tailmeta
signatures from signatures the same key may produce for other purposes.

The signature block itself, the footer and the CRC are not signed. They
are either derived from signed data or checked structurally.

### 4.4 Signing

To sign, a writer computes `H(content)`, builds the message from
section 4.3 and appends one entry per (algorithm, key) to the signature
block. Ed25519 signatures are deterministic, so the same key, content and
metadata always produce the same file.

### 4.5 Verification

A verifier configured with a trusted public key of algorithm `A`:

1. parses the trailer (section 3), rejecting it on any structural or CRC
   error;
2. selects the entries whose identifier equals `A`. The verifier's key
   determines the algorithm; the file never does. If the block is empty, the
   file is unsigned. If no entry has identifier `A`, verification fails;
3. computes `H(content)` over the content bytes;
4. builds the message (section 4.3) and accepts the file if **at least one**
   selected entry is a valid signature by the trusted key. Ed25519
   verification MUST follow RFC 8032 §5.1.7, including the rejection of
   non-canonical `S` values;
5. only then interprets the metadata JSON (section 3.2).

Entries with other identifiers are ignored. A verifier that trusts several
keys repeats steps 2–4 per key under its own policy (any one, all, a
threshold).

Successful verification proves that the holder of the private key signed this
exact content and these exact metadata bytes. It does not prove that the
version is the newest (see Security considerations).

## 5. Format 2 (read-only legacy)

Format 2 was written by tailmeta 0.3.x. New files MUST use format 3. Readers
MAY read format 2 metadata; verifiers MUST NOT accept a format 2 trailer as
signed.

```text
[content][metadata JSON: M bytes][CRC32: uint32][M: uint32][format: uint16 = 2][flags: uint16 = 0][TAILMETV]
```

The footer is 20 bytes, the CRC covers the metadata only, and there is no
signature block. Metadata rules are those of section 3.2. Format 2 files may
contain `sha256` and `signature` fields from the retired in-JSON signature
scheme. They are ordinary untrusted data: that scheme depended on
re-serializing the JSON canonically, which format 3 was designed to avoid. A
writer that restamps a format 2 file writes format 3.

## 6. Writing

A writer that stamps a file:

1. reads the existing trailer, if any, and determines where the content ends.
   If the trailer is damaged or unsupported, it MUST stop without changing the
   file;
2. writes the content, the metadata, the signature block and the footer to a
   new file, and replaces the original atomically;
3. never appends a trailer after an existing one: stamping replaces the
   trailer, so repeated stamping does not accumulate data.

Stripping is the same operation with no new trailer.

## 7. Other magic values

### 7.1 Unknown future formats

A file ending in `TAILMETV` with a format version other than 2 or 3 is
unsupported (section 2).

### 7.2 Retired format 1

Format 1 (`[content][JSON][M: uint32][TAILMETA]`, no checksum or version
field) was written by tailmeta ≤ 0.2. It is no longer supported. A reader
that finds `TAILMETA` as the last 8 bytes MUST report the trailer as
unsupported rather than absent, so that format 1 metadata is never mistaken
for the end of the content.

## 8. Reading over HTTP

A trailer can be read from a remote file with HTTP Range requests
(RFC 9110 §14) without downloading the content:

1. Request the last 64 KiB: `Range: bytes=-65536`, `Accept-Encoding: identity`.
   The response MUST be `206 Partial Content` with a `Content-Range` whose
   end is `total − 1`. A `200` response means that the server ignores
   `Range`; the client SHOULD abort instead of downloading the whole file. A
   response with a `Content-Encoding` other than `identity` MUST be rejected,
   because byte offsets would not refer to the file.
2. If the metadata and signature block do not fit in that block, request the
   remaining range.
3. Every response after the first MUST describe the same representation:
   - if the first response carried a strong `ETag`, the client sends it in
     `If-Range`. A server that sees a different current ETag answers `200`
     with the whole file, which the client treats as "file changed" and
     aborts;
   - the client compares `ETag`, `Last-Modified` and the total size from
     `Content-Range` of every response with the first one, and aborts on any
     difference, including a validator that appears or disappears. This also
     covers weak ETags, which `If-Range` does not accept, and servers that
     ignore `If-Range`.

Without these checks, a file replaced between requests could produce a
trailer stitched together from two different versions. The CRC would usually
catch this, but it is not designed to.

Signatures cannot be verified this way, since verification hashes the full
content.

## 9. Security considerations

- Metadata read without verification is **untrusted**: anyone who can write to
  the file can write any metadata. Display it with control characters escaped.
- A program that verifies its own executable is not a security boundary:
  whoever can replace the binary can also remove the check. Verify in a
  separate trusted component that holds its own copy of the public key.
- There is no rollback protection: every file that was ever signed keeps
  verifying. Compare the verified `version` against the installed one if
  downgrades must be refused.
- The CRC is not a MAC. Only signatures provide authenticity.
- Size limits (1 MiB metadata, 64 KiB signatures) bound the memory a reader
  needs for a hostile file. Readers SHOULD also bound JSON nesting depth.

## Appendix A. Test vectors

Content (12 bytes): `7f 45 4c 46 20 70 61 79 6c 6f 61 64` (`\x7fELF payload`).
Metadata (19 bytes): `{"version":"1.2.4"}`.
SHA-256 of the content:
`95e76dc683cf084f10bc438d2d6a1b29019f918574ac21ad57e25202f59bf03f`.

### A.1 Format 3, unsigned

Trailer appended to the content (hex, metadata then footer):

```text
7b2276657273696f6e223a22312e322e34227d
70d36952 00000013 00000000 0003 0000 5441494c4d455456
```

### A.2 Format 3, signed with Ed25519

Key: RFC 8032 §7.1 TEST 1. Private seed
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`, public key
`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`.

Signed message (hex):

```text
7461696c6d6574612f76332f7369676e617475726500
0001
95e76dc683cf084f10bc438d2d6a1b29019f918574ac21ad57e25202f59bf03f
7b2276657273696f6e223a22312e322e34227d
```

Trailer (metadata, signature entry, footer):

```text
7b2276657273696f6e223a22312e322e34227d
0001 00000040
aee6762f317cb207c12dec3e34ee839aeebcc311604a800c25fe1e72a03837f5
22774ad17103d884170d45bda1b28d837715e2f393e6b808e75829ea5a213905
4370327a 00000013 00000046 0003 0000 5441494c4d455456
```

### A.3 Format 2, unsigned

```text
7b2276657273696f6e223a22312e322e34227d
70d36952 00000013 0002 0000 5441494c4d455456
```

These vectors are checked byte for byte by `tests/test_formats.py`.
