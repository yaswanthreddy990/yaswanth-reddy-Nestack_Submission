
import re
import time
import getpass
import sqlite3
import bcrypt

from database import get_db


def create_admin():

    username = input("Enter admin username: ").strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
        print("Invalid username.")
        return

    password = getpass.getpass("Enter admin password: ")
    confirm = getpass.getpass("Confirm admin password: ")

    if password != confirm:
        print("Passwords do not match.")
        return

    password_bytes = password.encode("utf-8")

    if not 12 <= len(password_bytes) <= 72:
        print("Password must be 12-72 bytes long.")
        return

    password_hash = bcrypt.hashpw(
        password_bytes,
        bcrypt.gensalt(rounds=12)
    ).decode("utf-8")

    try:
        with get_db() as conn:

            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if existing:
                print("Username already exists. No role changes made.")
                return

            conn.execute(
                """
                INSERT INTO users
                (username, password_hash, role, created_at)
                VALUES (?, ?, 'admin', ?)
                """,
                (username, password_hash, int(time.time()))
            )

        print("Admin account created successfully!")

    except sqlite3.IntegrityError:
        print("Could not create admin account.")


if __name__ == "__main__":
    create_admin()
