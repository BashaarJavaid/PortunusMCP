"""Mint the audit-log ECDSA signing keypair (ARCHITECTURE.md §4.8, ROADMAP item 11).

Writes the P-256 private key to secrets/audit_signing_key.pem (gateway-only) and the
public key to secrets/audit_signing_key.pub.pem (verifier daemon). Refuses to overwrite
an existing key — rotating the key mid-chain would invalidate every prior signature.

Usage: python scripts/generate_signing_key.py
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.gateway.audit_keys import AuditKeyStore

SECRETS_DIR = Path(__file__).parent.parent / "secrets"
PRIVATE_PATH = SECRETS_DIR / "audit_signing_key.pem"
PUBLIC_PATH = SECRETS_DIR / "audit_signing_key.pub.pem"
PUBLIC_DIR = SECRETS_DIR / "public"

if PRIVATE_PATH.exists():
    print(f"refusing to overwrite existing key: {PRIVATE_PATH}")
    sys.exit(1)

SECRETS_DIR.mkdir(exist_ok=True)
private_key = ec.generate_private_key(ec.SECP256R1())
PRIVATE_PATH.write_bytes(
    private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
PRIVATE_PATH.chmod(0o600)
PUBLIC_PATH.write_bytes(
    private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
)
_, key_id = AuditKeyStore(str(PRIVATE_PATH), str(PUBLIC_DIR)).initialize()
print(f"private key: {PRIVATE_PATH}")
print(f"public key:  {PUBLIC_PATH}")
print(f"key id:      {key_id}")
