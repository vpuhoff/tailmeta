"""Version metadata in file trailers, with optional Ed25519 signatures."""
from ._core import generate_keys, read_metadata, stamp, verify

from ._version import __version__
__all__ = ["generate_keys", "read_metadata", "stamp", "verify"]
