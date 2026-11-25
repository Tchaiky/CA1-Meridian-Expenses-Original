import sqlite3

import pytest

import app as app_module

flask_app = app_module.app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # Use a temporary db.
    test_db = tmp_path / "test_expenses.db"
    monkeypatch.setattr(app_module, "DB", str(test_db))

    connection = sqlite3.connect(test_db)

    connection.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            name TEXT,
            role TEXT
        );

        CREATE TABLE claims (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            merchant TEXT,
            amount REAL,
            note TEXT,
            status TEXT
        );
    """)

    users = [
        ("jdoe", "password1", "Jane Doe", "staff"),
        ("rsmith", "letmein", "Rob Smith", "staff"),
        ("achen", "Summer2026", "Ada Chen", "finance"),
        ("admin", "admin", "System Admin", "admin"),
    ]

    for username, password, name, role in users:
        password_hash = app_module.hash_pw(password)
        connection.execute(
            "INSERT INTO users (username, password, name, role) "
            "VALUES (?, ?, ?, ?)",
            (username, password_hash, name, role),
        )

    connection.execute(
        "INSERT INTO claims "
        "(id, user_id, merchant, amount, note, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (1, 1, "Dublin Coach", 24.50, "Client visit", "pending"),
    )

    connection.commit()
    connection.close()

    flask_app.config["TESTING"] = True

    with flask_app.test_client() as test_client:
        yield test_client


USERS = {
    "jane": {"username": "jdoe", "password": "password1"},
    "rob": {"username": "rsmith", "password": "letmein"},
    "admin": {"username": "admin", "password": "admin"},
}


def login(client, user):
    response = client.post(
        "/login",
        data=USERS[user],
        follow_redirects=True,
    )
    assert response.status_code == 200


# CWE-639: Authorisation Bypass Through User-Controlled Key

@pytest.mark.parametrize(
    "user, claim_id, expected_status",
    [
        ("jane", 1, 200),
        ("rob", 1, 403),
        ("admin", 1, 200),
    ],
)
def test_horizontal_access_control(client, user, claim_id, expected_status):
    login(client, user)

    response = client.get(f"/claim/{claim_id}")

    assert response.status_code == expected_status

    if user == "rob":
        assert b"Dublin Coach" not in response.data
        assert b"Client visit" not in response.data

    if user == "admin":
        assert b"Dublin Coach" in response.data


def test_anonymous_user_cannot_access_claim(client):
    response = client.get("/claim/1")
    assert response.status_code == 302


def test_nonexistent_claim_returns_404(client):
    login(client, "rob")

    response = client.get("/claim/999")
    assert response.status_code == 404