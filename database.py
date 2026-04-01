"""
database.py — SQLite3 wrapper for the password vault.

Tables
------
master   : id, password_hash, salt   (single row — the master credentials)
entries  : id, website, username, encrypted_password

All functions operate on ``vault.db`` located next to this script.
"""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.db")


def _connect():
    """Return a new connection to the vault database."""
    return sqlite3.connect(DB_PATH)


# Initialisation


def init_db():
    """Create the master and entries tables if they do not already exist."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS master (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash   TEXT NOT NULL,
            salt            BLOB NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS entries (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            website             TEXT NOT NULL,
            username            TEXT NOT NULL,
            encrypted_password  TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# Master password helpers


def master_exists() -> bool:
    """Return True if a master password has already been configured."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM master")
    count = cur.fetchone()[0]
    conn.close()
    return count > 0


def set_master(password_hash: str, salt: bytes):
    """Store the master password hash and salt (first-time signup)."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO master (password_hash, salt) VALUES (?, ?)",
        (password_hash, salt),
    )
    conn.commit()
    conn.close()


def get_master():
    """Return (password_hash, salt) for the stored master password, or None."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT password_hash, salt FROM master LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row  # (password_hash: str, salt: bytes) or None


# Credential entries


def add_entry(website: str, username: str, encrypted_password: str):
    """Insert a new credential entry into the vault."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO entries (website, username, encrypted_password) VALUES (?, ?, ?)",
        (website, username, encrypted_password),
    )
    conn.commit()
    conn.close()


def get_all_entries():
    """Return a list of all credential rows as (id, website, username, encrypted_password)."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute("SELECT id, website, username, encrypted_password FROM entries")
    rows = cur.fetchall()
    conn.close()
    return rows


def delete_entry(entry_id: int):
    """Delete a credential entry by its primary-key *entry_id*."""
    conn = _connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
