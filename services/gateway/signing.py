"""ECDSA (P-256) signing over audit-row hashes (ARCHITECTURE.md §4.8, item 11).

The hash chain alone only proves internal consistency — an attacker with Postgres
write access can regenerate a self-consistent chain from a tampered point forward.
Signing each row's curr_hash with a key held only by the gateway process closes that
gap: the verifier checks both the chain math AND the signature on every row.

Keypair is minted once via scripts/generate_signing_key.py; loaders raise on a
missing or invalid file so the gateway fails startup (§5, fail closed).
"""

import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def load_private_key(path: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"{path} is not an EC private key")
    return key


def load_public_key(path: str) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise TypeError(f"{path} is not an EC public key")
    return key


def sign(private_key: ec.EllipticCurvePrivateKey, curr_hash: str) -> bytes:
    """DER-encoded ECDSA-SHA256 signature over the row's curr_hash."""
    return private_key.sign(curr_hash.encode(), ec.ECDSA(hashes.SHA256()))


def verify(public_key: ec.EllipticCurvePublicKey, signature: bytes, curr_hash: str) -> bool:
    try:
        public_key.verify(signature, curr_hash.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def private_pem(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_pem(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"sha256:{hashlib.sha256(der).hexdigest()}"
