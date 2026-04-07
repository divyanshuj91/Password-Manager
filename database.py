"""
database.py — SQLAlchemy ORM wrapper for the password vault.

Models
------
Master  : id, password_hash, salt          (single row — master credentials)
Entry   : id, website, username, encrypted_password, totp_secret, created_at

Architecture Note
-----------------
Uses SQLAlchemy ORM so the codebase is **PostgreSQL-ready** while keeping
SQLite for portability (single-file database, no server required).
To migrate: change DATABASE_URL to a PostgreSQL connection string.
"""

import os
from datetime import datetime, timezone

from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, DateTime
from sqlalchemy.orm import DeclarativeBase, Session

# ---------------------------------------------------------------------------
# Database setup — swap the URL for PostgreSQL when ready
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


class Master(Base):
    __tablename__ = "master"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    password_hash = Column(String, nullable=False)
    salt          = Column(LargeBinary, nullable=False)


class Entry(Base):
    __tablename__ = "entries"

    id                 = Column(Integer, primary_key=True, autoincrement=True)
    website            = Column(String, nullable=False)
    username           = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    totp_secret        = Column(String, nullable=True)       # encrypted TOTP secret
    created_at         = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_db():
    """Create all tables if they do not already exist."""
    Base.metadata.create_all(engine)


# ---------------------------------------------------------------------------
# Master password helpers
# ---------------------------------------------------------------------------

def master_exists() -> bool:
    """Return True if a master password has already been configured."""
    with Session(engine) as session:
        return session.query(Master).count() > 0


def set_master(password_hash: str, salt: bytes):
    """Store the master password hash and salt (first-time signup)."""
    with Session(engine) as session:
        session.add(Master(password_hash=password_hash, salt=salt))
        session.commit()


def get_master():
    """Return (password_hash, salt) for the stored master password, or None."""
    with Session(engine) as session:
        row = session.query(Master).first()
        if row is None:
            return None
        return (row.password_hash, row.salt)


# ---------------------------------------------------------------------------
# Credential entries  (backward-compatible API for the desktop app)
# ---------------------------------------------------------------------------

def add_entry(website: str, username: str, encrypted_password: str,
              totp_secret: str = None):
    """Insert a new credential entry into the vault."""
    with Session(engine) as session:
        session.add(Entry(
            website=website,
            username=username,
            encrypted_password=encrypted_password,
            totp_secret=totp_secret,
        ))
        session.commit()


def get_all_entries():
    """Return a list of all credential rows as (id, website, username, encrypted_password)."""
    with Session(engine) as session:
        rows = session.query(Entry).order_by(Entry.created_at.desc()).all()
        return [(e.id, e.website, e.username, e.encrypted_password) for e in rows]


def get_all_entries_full():
    """Return full entry dicts including TOTP and timestamp data."""
    with Session(engine) as session:
        rows = session.query(Entry).order_by(Entry.created_at.desc()).all()
        return [
            {
                "id": e.id,
                "website": e.website,
                "username": e.username,
                "encrypted_password": e.encrypted_password,
                "totp_secret": e.totp_secret,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in rows
        ]


def get_entry(entry_id: int):
    """Return a single entry dict by ID, or None."""
    with Session(engine) as session:
        e = session.query(Entry).filter(Entry.id == entry_id).first()
        if e is None:
            return None
        return {
            "id": e.id,
            "website": e.website,
            "username": e.username,
            "encrypted_password": e.encrypted_password,
            "totp_secret": e.totp_secret,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }


def update_totp_secret(entry_id: int, totp_secret: str):
    """Set or update the encrypted TOTP secret for an entry."""
    with Session(engine) as session:
        entry = session.query(Entry).filter(Entry.id == entry_id).first()
        if entry:
            entry.totp_secret = totp_secret
            session.commit()


def delete_entry(entry_id: int):
    """Delete a credential entry by its primary-key *entry_id*."""
    with Session(engine) as session:
        entry = session.query(Entry).filter(Entry.id == entry_id).first()
        if entry:
            session.delete(entry)
            session.commit()
