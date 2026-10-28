"""Identity files (`rhp-cli keygen` writes them; Src/rhp/security/identity_file.cpp reads them):

    # comment
    name = "dev"
    psk = "base64 of 32 bytes"           # the key the host's keyring holds for `name`
    signing_key = "base64 of 32 bytes"   # optional: the Ed25519 seed that signs scripts
    signer = "dev"                       # optional: the name the host trusts the public key under

Since Stage 13b `rhp-cli keygen` keeps the signing key in a file of its own beside the identity
(`dev.rhpsign`: `signer`, `signing_key`, `env`); `Identity.load` reads it when the identity has no
signing key. A signing key sealed with a passphrase ("argon2i:...") needs Argon2i, which Python's
standard library lacks: such an identity loads without a signing key (it can still connect).
An `env = "dev|prod"` field is accepted and ignored.

The private parts are never printed (repr() shows the name and signer only).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass, field
from typing import Optional, Union
import os

from ._errors import RhpError

__all__ = ["Identity", "SCRIPT_DOMAIN", "sign_script"]

# What a script signature covers: this domain, then the script's UTF-8 source (security/signer.hpp).
SCRIPT_DOMAIN = b"rhp/script\x00"

_KEY_SIZE = 32

try:  # `cryptography` when installed (constant-time, fast); else RFC 8032 in pure Python
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed25519PrivateKey  # type: ignore
    from cryptography.hazmat.primitives import serialization as _serialization  # type: ignore

    def _ed25519_sign(seed: bytes, message: bytes) -> bytes:
        return _Ed25519PrivateKey.from_private_bytes(seed).sign(message)

    def _ed25519_public(seed: bytes) -> bytes:
        key = _Ed25519PrivateKey.from_private_bytes(seed).public_key()
        return key.public_bytes(_serialization.Encoding.Raw, _serialization.PublicFormat.Raw)

except ImportError:  # pragma: no cover - depends on the environment
    from . import _ed25519

    def _ed25519_sign(seed: bytes, message: bytes) -> bytes:
        return _ed25519.sign(seed, message)

    def _ed25519_public(seed: bytes) -> bytes:
        return _ed25519.public_key(seed)


def _fields(text: str, what: str) -> dict:
    """`key = "value"` lines ('#' comments) as {key: (value, line number)}."""
    fields = {}
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise RhpError("invalid_argument", 'line %d: expected `key = "value"`' % number, what)
        key, value = (part.strip() for part in line.split("=", 1))
        if len(value) < 2 or value[0] != '"' or value[-1] != '"':
            raise RhpError("invalid_argument", 'line %d: expected `key = "value"`' % number, what)
        fields[key] = (value[1:-1], number)
    return fields


def _decode_key(text: str, what: str, line: int) -> bytes:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RhpError("invalid_argument", "line %d: %s is not base64 (%s)" % (line, what, exc), "identity file") from None
    if len(raw) != _KEY_SIZE:
        raise RhpError("invalid_argument", "line %d: %s must be %d bytes, got %d" % (line, what, _KEY_SIZE, len(raw)), "identity file")
    return raw


@dataclass(frozen=True)
class Identity:
    """Who a client is: a key name and pre-shared key, and optionally the key that signs its scripts."""

    name: str
    psk: bytes = field(repr=False)
    signing_key: Optional[bytes] = field(default=None, repr=False)  # Ed25519 seed
    signer: str = ""  # the name hosts trust the signing key under; defaults to `name`

    def __post_init__(self):
        if not self.name:
            raise RhpError("invalid_argument", "an identity needs a name", "identity")
        if len(self.psk) != _KEY_SIZE:
            raise RhpError("invalid_argument", "a pre-shared key is %d bytes" % _KEY_SIZE, "identity")
        if self.signing_key is not None and len(self.signing_key) != _KEY_SIZE:
            raise RhpError("invalid_argument", "an Ed25519 private key is a %d-byte seed" % _KEY_SIZE, "identity")
        if not self.signer:
            object.__setattr__(self, "signer", self.name)

    @classmethod
    def parse(cls, text: str) -> "Identity":
        fields = _fields(text, "identity file")
        if "name" not in fields or "psk" not in fields:
            raise RhpError("invalid_argument", "an identity file needs `name` and `psk`", "identity file")
        psk = _decode_key(fields["psk"][0], "psk", fields["psk"][1])
        signing = _decode_key(fields["signing_key"][0], "signing_key", fields["signing_key"][1]) if "signing_key" in fields else None
        signer = fields["signer"][0] if "signer" in fields else ""
        return cls(fields["name"][0], psk, signing, signer)

    @classmethod
    def load(cls, path: Union[str, "os.PathLike[str]"]) -> "Identity":
        with open(path, encoding="utf-8") as fh:
            identity = cls.parse(fh.read())
        signing_path = os.path.splitext(os.fspath(path))[0] + ".rhpsign"
        if identity.signing_key is not None or not os.path.exists(signing_path):
            return identity
        with open(signing_path, encoding="utf-8") as fh:
            fields = _fields(fh.read(), "signing key file")
        if "signing_key" not in fields or fields["signing_key"][0].startswith("argon2i:"):
            return identity
        seed = _decode_key(fields["signing_key"][0], "signing_key", fields["signing_key"][1])
        signer = fields["signer"][0] if "signer" in fields else identity.name
        return cls(identity.name, identity.psk, seed, signer)

    def public_key(self) -> Optional[bytes]:
        """The Ed25519 public key a host's trusted-signers file lists for this identity."""
        return _ed25519_public(self.signing_key) if self.signing_key is not None else None

    def sign(self, source: str):
        """The signature value a host verifies for `source`, or None without a signing key."""
        return sign_script(self, source)

    def fingerprint(self) -> str:
        """A short, non-secret id of the pre-shared key (for logs)."""
        return hashlib.blake2b(self.psk, digest_size=6).hexdigest()


def sign_script(identity: Identity, source: str):
    if identity.signing_key is None:
        return None
    signature = _ed25519_sign(identity.signing_key, SCRIPT_DOMAIN + source.encode("utf-8"))
    return {"signer": identity.signer, "sig": signature}
