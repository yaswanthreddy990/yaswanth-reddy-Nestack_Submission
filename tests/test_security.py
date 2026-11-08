
import hashlib
import time

import bcrypt
import pytest

import database
from database import get_db, init_db
from app import app as flask_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Give each test its own temporary database
    test_db = tmp_path / "test_records.db"
    monkeypatch.setattr(database, "DB_PATH", test_db)

    init_db()
    flask_app.config.update(TESTING=True)

    with flask_app.test_client() as test_client:
        yield test_client


def register(client, username, password="StrongPassword@2026"):
    return client.post(
        "/register",
        json={"username": username, "password": password}
    )


def login(client, username, password="StrongPassword@2026"):
    response = client.post(
        "/login",
        json={"username": username, "password": password}
    )

    assert response.status_code == 200, response.get_json()
    return response.get_json()["session_token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def test_password_is_hashed(client):
    password = "StrongPassword@2026"

    response = register(client, "alice", password)

    assert response.status_code == 201

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            ("alice",)
        ).fetchone()

    assert user["password_hash"] != password
    assert user["password_hash"].startswith("$2b$")
    assert user["role"] == "user"


def test_user_cannot_register_as_admin(client):
    response = client.post(
        "/register",
        json={
            "username": "attacker",
            "password": "StrongPassword@2026",
            "role": "admin"
        }
    )

    assert response.status_code == 403


def test_session_token_is_stored_as_hash(client):
    register(client, "alice")
    token = login(client, "alice")

    token_hash = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()

    with get_db() as conn:
        session = conn.execute(
            "SELECT token_hash FROM sessions"
        ).fetchone()

    assert session["token_hash"] == token_hash
    assert session["token_hash"] != token


def test_user_cannot_read_another_users_record(client):
    register(client, "alice")
    register(client, "bob")

    alice_token = login(client, "alice")
    bob_token = login(client, "bob")

    created = client.post(
        "/records",
        headers=auth_header(alice_token),
        json={
            "title": "Alice private record",
            "body": "This belongs to Alice"
        }
    )

    assert created.status_code == 201
    record_id = created.get_json()["record_id"]

    # Alice can read her own record
    own_response = client.get(
        f"/records/{record_id}",
        headers=auth_header(alice_token)
    )

    assert own_response.status_code == 200

    # Bob cannot read Alice's record
    attack_response = client.get(
        f"/records/{record_id}",
        headers=auth_header(bob_token)
    )

    assert attack_response.status_code == 404


def test_admin_can_read_any_users_record(client):
    register(client, "alice")
    user_token = login(client, "alice")

    created = client.post(
        "/records",
        headers=auth_header(user_token),
        json={
            "title": "Admin test record",
            "body": "Admin should be able to read this"
        }
    )

    record_id = created.get_json()["record_id"]

    # Provision an admin directly in the test database
    admin_password = "AdminStrongPassword@2026"
    admin_hash = bcrypt.hashpw(
        admin_password.encode("utf-8"),
        bcrypt.gensalt(rounds=12)
    ).decode("utf-8")

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO users
            (username, password_hash, role, created_at)
            VALUES (?, ?, 'admin', ?)
            """,
            ("admin_test", admin_hash, int(time.time()))
        )

    admin_token = login(
        client,
        "admin_test",
        admin_password
    )

    response = client.get(
        f"/records/{record_id}",
        headers=auth_header(admin_token)
    )

    assert response.status_code == 200


def test_login_lockout_after_five_failures(client):
    register(client, "lockout_user")

    wrong_password = {
        "username": "lockout_user",
        "password": "WrongPassword@2026"
    }

    for attempt in range(1, 5):
        response = client.post("/login", json=wrong_password)
        assert response.status_code == 401

    fifth_attempt = client.post("/login", json=wrong_password)

    assert fifth_attempt.status_code == 429

    # Correct password must also be rejected during lockout
    locked_login = client.post(
        "/login",
        json={
            "username": "lockout_user",
            "password": "StrongPassword@2026"
        }
    )

    assert locked_login.status_code == 429


def test_unauthenticated_access_is_rejected(client):
    response = client.get("/records/1")

    assert response.status_code == 401


def test_invalid_record_input_is_rejected(client):
    register(client, "alice")
    token = login(client, "alice")

    response = client.post(
        "/records",
        headers=auth_header(token),
        json={
            "title": 12345,
            "body": "Invalid title type"
        }
    )

    assert response.status_code == 400


def test_invalid_session_token_is_rejected(client):
    response = client.get(
        "/records/1",
        headers=auth_header("invalid-session-token")
    )

    assert response.status_code == 401
def test_oversized_request_is_rejected(client):

    oversized_body = (
        b'{"padding":"' + b'A' * (20 * 1024) + b'"}'
    )

    response = client.post(
        "/register",
        data=oversized_body,
        content_type="application/json"
    )

    assert response.status_code == 400