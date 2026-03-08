"""
Encryption utilities for the credential vault.

- Master password is hashed with bcrypt (one-way, for verification).
- Vault passwords are encrypted with Fernet (AES-128-CBC), using a key
  derived from the master password via PBKDF2-HMAC-SHA256.
"""

import base64
import os

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ---------------------------------------------------------------------------
# Master-password hashing (bcrypt)
# ---------------------------------------------------------------------------

def hash_master_password(password: str) -> str:
    """Return a bcrypt hash of the master password."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_master_password(password: str, hashed: str) -> bool:
    """Check a plaintext master password against its bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


# ---------------------------------------------------------------------------
# Encryption-key derivation (PBKDF2 → Fernet key)
# ---------------------------------------------------------------------------

_KDF_ITERATIONS = 480_000  # OWASP-recommended minimum for PBKDF2-SHA256


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 32-byte Fernet-compatible key from a master password + salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def generate_salt() -> bytes:
    """Generate a cryptographically secure random 16-byte salt."""
    return os.urandom(16)


# ---------------------------------------------------------------------------
# Credential encryption / decryption (Fernet)
# ---------------------------------------------------------------------------

def encrypt_password(plaintext: str, key: bytes) -> str:
    """Encrypt a credential password and return the ciphertext as a string."""
    f = Fernet(key)
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_password(ciphertext: str, key: bytes) -> str:
    """Decrypt a stored credential password back to plaintext."""
    f = Fernet(key)
    return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
