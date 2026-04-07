"""
encryption.py — Zero-Knowledge encryption module.

Security Architecture
---------------------
• Master password hashing  : Argon2id (memory-hard, side-channel resistant)
• Key derivation           : PBKDF2-HMAC-SHA256 → Fernet-compatible key
• Vault encryption         : Fernet (AES-128-CBC + HMAC-SHA256)

The master password is NEVER stored — only its Argon2 hash.
All vault data is encrypted with a key derived from the master password,
so even a full database leak reveals nothing without the master password.
"""

import os
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Argon2id hasher with secure defaults
_ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def generate_salt() -> bytes:
    """Return a cryptographically random 16-byte salt."""
    return os.urandom(16)


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a Fernet-compatible key from *master_password* and *salt*
    using PBKDF2-HMAC-SHA256 with 100 000 iterations.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------

def encrypt(plaintext: str, key: bytes) -> str:
    """Encrypt *plaintext* with Fernet *key*; return the cipher-text as a UTF-8 string."""
    f = Fernet(key)
    return f.encrypt(plaintext.encode()).decode()


def decrypt(cipher_text: str, key: bytes) -> str:
    """Decrypt a Fernet *cipher_text* with the given *key*; return the plaintext string."""
    f = Fernet(key)
    return f.decrypt(cipher_text.encode()).decode()


# ---------------------------------------------------------------------------
# Master-password hashing — Argon2id (Zero-Knowledge)
# ---------------------------------------------------------------------------

def hash_master_password(password: str) -> str:
    """
    Hash the master password using Argon2id.

    Returns an encoded hash string containing the algorithm parameters,
    salt, and hash — suitable for storage and later verification.
    """
    return _ph.hash(password)


def verify_master_password(password: str, stored_hash: str) -> bool:
    """Return True if *password* matches the Argon2 *stored_hash*."""
    try:
        return _ph.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
