"""
auth.py — JWT-based session management for the web API.

Flow
----
1. User logs in → server verifies Argon2 hash
2. Server derives Fernet encryption key from master password + salt
3. Server stores encryption key in an in-memory session (keyed by session ID)
4. Server returns a signed JWT containing the session ID
5. Subsequent requests send JWT → server looks up encryption key from session

Security: The encryption key is NEVER sent to the client.
         It lives only in server memory for the duration of the session.
"""

import secrets
from datetime import datetime, timedelta, timezone

from jose import jwt, JWTError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SECRET_KEY = secrets.token_hex(32)  # regenerated each server start
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

# ---------------------------------------------------------------------------
# In-memory session store  { session_id → encryption_key (bytes) }
# ---------------------------------------------------------------------------

_sessions: dict[str, bytes] = {}


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(session_id: str) -> str:
    """Create a signed JWT containing the *session_id*."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": session_id, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str) -> str | None:
    """Decode *token* and return the session_id, or None if invalid/expired."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def create_session(encryption_key: bytes) -> str:
    """Store *encryption_key* in a new session; return the session ID."""
    session_id = secrets.token_hex(16)
    _sessions[session_id] = encryption_key
    return session_id


def get_session_key(session_id: str) -> bytes | None:
    """Return the encryption key for *session_id*, or None."""
    return _sessions.get(session_id)


def destroy_session(session_id: str):
    """Remove a session (lock vault / logout)."""
    _sessions.pop(session_id, None)
