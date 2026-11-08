
import hashlib
import re
import secrets
import time

import bcrypt
from flask import Flask, jsonify, request

from database import get_db, init_db


app = Flask(__name__)
# Limit incoming request bodies to 16 KB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024


@app.errorhandler(413)
def handle_request_too_large(error):
    return jsonify({
        "error": "Request body is too large"
    }), 400

# Security settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60
SESSION_LIFETIME = 12 * 60 * 60
MAX_PASSWORD_BYTES = 72


def read_json():
    """Accept only valid JSON objects."""

    if not request.is_json:
        return None, (jsonify({"error": "JSON content type required"}), 400)

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None, (jsonify({"error": "Invalid JSON body"}), 400)

    return data, None


def validate_credentials(username, password):
    """Validate username and password types and lengths."""

    if not isinstance(username, str) or not isinstance(password, str):
        return False

    username = username.strip()

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
        return False

    password_bytes = password.encode("utf-8")

    if not 8 <= len(password_bytes) <= MAX_PASSWORD_BYTES:
        return False

    return True


@app.route("/register", methods=["POST"])
def register():

    data, error = read_json()

    if error:
        return error

    # Never allow clients to choose their own role
    if "role" in data:
        return jsonify({"error": "Role assignment is not permitted"}), 403

    if set(data.keys()) != {"username", "password"}:
        return jsonify({"error": "Only username and password are accepted"}), 400

    username = data["username"]
    password = data["password"]

    if not validate_credentials(username, password):
        return jsonify({"error": "Invalid username or password format"}), 400

    username = username.strip()

    # Hash password with bcrypt and a unique salt
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    ).decode("utf-8")

    created_at = int(time.time())

    try:
        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, 'user', ?)
                """,
                (username, password_hash, created_at)
            )

            user_id = cursor.lastrowid

    except Exception as exc:
        import sqlite3

        if isinstance(exc, sqlite3.IntegrityError):
            return jsonify({"error": "Username already exists"}), 409

        raise

    return jsonify({
        "message": "Account created successfully",
        "user_id": user_id
    }), 201


@app.route("/login", methods=["POST"])
def login():

    data, error = read_json()

    if error:
        return error

    if set(data.keys()) != {"username", "password"}:
        return jsonify({"error": "Username and password are required"}), 400

    username = data["username"]
    password = data["password"]

    if not validate_credentials(username, password):
        return jsonify({"error": "Invalid username or password format"}), 400

    username = username.strip()
    now = int(time.time())

    with get_db() as conn:

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        # Use the same response for unknown users and bad passwords
        if user is None:
            return jsonify({"error": "Invalid username or password"}), 401

        # Check account lockout
        if user["locked_until"] is not None:

            if now < user["locked_until"]:
                return jsonify({"error": "Account temporarily locked"}), 429

            # Lockout period has expired; reset the counter
            conn.execute(
                """
                UPDATE users
                SET failed_attempts = 0, locked_until = NULL
                WHERE id = ?
                """,
                (user["id"],)
            )

            failed_attempts = 0

        else:
            failed_attempts = user["failed_attempts"]

        # Verify submitted password against stored bcrypt hash
        password_is_valid = bcrypt.checkpw(
            password.encode("utf-8"),
            user["password_hash"].encode("utf-8")
        )

        if not password_is_valid:

            failed_attempts += 1

            if failed_attempts >= MAX_FAILED_ATTEMPTS:

                lock_until = now + LOCKOUT_SECONDS

                conn.execute(
                    """
                    UPDATE users
                    SET failed_attempts = ?, locked_until = ?
                    WHERE id = ?
                    """,
                    (failed_attempts, lock_until, user["id"])
                )

                return jsonify({"error": "Account temporarily locked"}), 429

            conn.execute(
                """
                UPDATE users
                SET failed_attempts = ?
                WHERE id = ?
                """,
                (failed_attempts, user["id"])
            )

            return jsonify({"error": "Invalid username or password"}), 401

        # Successful login: reset failed attempts
        conn.execute(
            """
            UPDATE users
            SET failed_attempts = 0, locked_until = NULL
            WHERE id = ?
            """,
            (user["id"],)
        )

        # Remove expired sessions
        conn.execute(
            "DELETE FROM sessions WHERE expires_at <= ?",
            (now,)
        )

        # Generate an unpredictable opaque session token
        session_token = secrets.token_urlsafe(32)

        # Store only the SHA-256 hash of the session token
        token_hash = hashlib.sha256(
            session_token.encode("utf-8")
        ).hexdigest()

        expires_at = now + SESSION_LIFETIME

        conn.execute(
            """
            INSERT INTO sessions (user_id, token_hash, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (user["id"], token_hash, now, expires_at)
        )

    return jsonify({
        "message": "Login successful",
        "session_token": session_token,
        "token_type": "Bearer",
        "expires_in": SESSION_LIFETIME
    }), 200

def get_current_user():
    """Verify the Bearer token against the server-side session."""

    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:].strip()

    if not token or len(token) > 200:
        return None

    # Hash the supplied token
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    now = int(time.time())

    with get_db() as conn:
        session = conn.execute(
            """
            SELECT users.id, users.username, users.role
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
            AND sessions.expires_at > ?
            """,
            (token_hash, now)
        ).fetchone()

    if session is None:
        return None

    return {
        "id": session["id"],
        "username": session["username"],
        "role": session["role"]
    }


@app.route("/records", methods=["POST"])

@app.route("/records", methods=["POST"])
def create_record():

    user = get_current_user()

    if user is None:
        return jsonify({"error": "Authentication required"}), 401

    data, error = read_json()

    if error:
        return error

    if set(data.keys()) != {"title", "body"}:
        return jsonify({"error": "Title and body are required"}), 400

    title = data["title"]
    body = data["body"]

    if not isinstance(title, str) or not isinstance(body, str):
        return jsonify({"error": "Title and body must be strings"}), 400

    title = title.strip()

    if not title or len(title) > 100:
        return jsonify({"error": "Title must contain 1-100 characters"}), 400

    if not body.strip() or len(body) > 5000:
        return jsonify({"error": "Body must contain 1-5000 characters"}), 400

    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO records (user_id, title, body, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user["id"], title, body, int(time.time()))
        )

        record_id = cursor.lastrowid

    return jsonify({
        "message": "Record created successfully",
        "record_id": record_id
    }), 201

    """Verify the Bearer token against the server-side session."""

    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:].strip()

    if not token or len(token) > 200:
        return None

    # Hash the token before looking it up in the database
    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    now = int(time.time())

    with get_db() as conn:
        session = conn.execute(
            """
            SELECT users.id, users.username, users.role
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
            AND sessions.expires_at > ?
            """,
            (token_hash, now)
        ).fetchone()

    if session is None:
        return None

    return {
        "id": session["id"],
        "username": session["username"],
        "role": session["role"]
    }


@app.route("/records/<int:record_id>", methods=["GET"])
def get_record(record_id):

    user = get_current_user()

    if user is None:
        return jsonify({"error": "Authentication required"}), 401

    with get_db() as conn:
        record = conn.execute(
            """
            SELECT id, user_id, title, body, created_at
            FROM records
            WHERE id = ?
            """,
            (record_id,)
        ).fetchone()

    if record is None:
        return jsonify({"error": "Record not found"}), 404

    # Admin can read all records.
    # Normal users can read only their own records.
    if user["role"] != "admin" and record["user_id"] != user["id"]:
        return jsonify({"error": "Record not found"}), 404

    return jsonify({
        "id": record["id"],
        "title": record["title"],
        "body": record["body"],
        "created_at": record["created_at"]
    }), 200

if __name__ == "__main__":

    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
