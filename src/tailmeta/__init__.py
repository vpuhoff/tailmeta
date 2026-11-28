"""Version metadata in file trailers, with optional Ed25519 signatures."""
from ._core import (
    DEFAULT_FORMAT,
    FORMAT_VERSIONS,
    UnsupportedFormatError,
    executable_path,
    generate_keys,
    inspect,
    read_metadata,
    stamp,
    strip,
    verify,
)
from ._http import read_metadata_url

from ._version import __version__
__all__ = [
    "DEFAULT_FORMAT",
    "FORMAT_VERSIONS",
    "UnsupportedFormatError",
    "executable_path",
    "generate_keys",
    "inspect",
    "read_metadata",
    "read_metadata_url",
    "stamp",
    "strip",
    "verify",
]
