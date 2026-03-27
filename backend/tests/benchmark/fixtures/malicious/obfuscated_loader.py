"""Malicious: Heavily obfuscated payload loader."""
import zlib
import base64

_0x4f2a = base64.b64decode(
    "eJzLSM3JyVcozy/KSQEAGgsEHQ=="
)
_0x3b1c = zlib.decompress(_0x4f2a)
exec(compile(_0x3b1c, '<string>', 'exec'))
