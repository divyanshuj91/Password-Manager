"""
encryption.py — Fernet-based encryption with PBKDF2 key derivation.

Provides functions to:
  • Derive a Fernet key from a master password + salt (PBKDF2-HMAC-SHA256).
  • Encrypt / decrypt arbitrary strings.
  • Hash/verify the master password (SHA-256) for login checks.
"""

import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


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
# Master-password hashing (for login verification)
# ---------------------------------------------------------------------------

def hash_master_password(password: str) -> str:
    """Return a SHA-256 hex-digest of the master password."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_master_password(password: str, stored_hash: str) -> bool:
    """Return True if *password* matches the *stored_hash*."""
    return hash_master_password(password) == stored_hash
