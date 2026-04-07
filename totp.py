"""
totp.py — Time-based One-Time Password (TOTP) module.

Provides Google-Authenticator-compatible 2FA functionality:
  • Generate / store TOTP secrets
  • Produce live 6-digit codes (RFC 6238)
  • Create scannable QR codes for authenticator apps
  • Verify user-entered codes
"""

import io
import time
import base64

import pyotp
import qrcode


def generate_totp_secret() -> str:
    """Generate a new random Base32-encoded TOTP secret."""
    return pyotp.random_base32()


def get_totp_code(secret: str) -> str:
    """Return the current 6-digit TOTP code for the given *secret*."""
    totp = pyotp.TOTP(secret)
    return totp.now()


def get_time_remaining() -> int:
    """Return seconds remaining until the current TOTP code expires (0-29)."""
    return 30 - int(time.time() % 30)


def verify_totp(secret: str, code: str) -> bool:
    """Verify a user-entered *code* against the *secret*. Allows ±1 window."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_qr_base64(secret: str, issuer: str, account: str) -> str:
    """
    Generate a QR code image for provisioning a TOTP secret
    into an authenticator app (Google Authenticator, Authy, etc.).

    Returns the QR image as a Base64-encoded PNG string.
    """
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=account, issuer_name=issuer)

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()
