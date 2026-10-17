from conftest import PW, login, register
from models import LoginAttempt, SecurityEvent, User
from extensions import db


def test_register_login_logout(app, client):
    assert register(client, "alice").status_code == 302
    r = login(client, "alice")
    assert r.status_code == 302 and r.headers["Location"].endswith("/dashboard")
    assert client.get("/dashboard").status_code == 200
    assert client.post("/logout").status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_password_is_hashed_and_public_key_stored(app, client):
    register(client, "alice")
    with app.app_context():
        u = User.query.filter_by(username="alice").one()
        assert PW not in u.password_hash and u.password_hash.startswith(("scrypt:", "pbkdf2:"))
        assert len(u.public_key) == 44


def test_registration_validation(client):
    assert register(client, "ab").status_code == 400
    assert register(client, "bad name!").status_code == 400
    assert register(client, "alice", "short1").status_code == 400
    assert register(client, "alice", "1234567890123").status_code == 400
    assert register(client, "alice", "xxalicexx-123").status_code == 400
    r = client.post("/register", data={"username": "alice", "password": PW, "confirm": "different-Passw0rd"})
    assert r.status_code == 400


def test_duplicate_username_case_insensitive(client):
    register(client, "alice")
    assert register(client, "ALICE").status_code == 409


def test_invalid_login_generic_message(client):
    register(client, "alice")
    a = login(client, "alice", "wrong-Passw0rd!")
    b = login(client, "nobody", "wrong-Passw0rd!")
    assert a.status_code == b.status_code == 401
    assert b"Invalid username or password." in a.data and b"Invalid username or password." in b.data


def test_login_throttle(app, client):
    register(client, "alice")
    codes = [login(client, "alice", "wrong-Passw0rd!").status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    r = login(client, "alice")  # even the right password is refused while locked
    assert r.status_code == 429 and "Retry-After" in r.headers
    with app.app_context():
        assert SecurityEvent.query.filter_by(event_type="login_throttled").count() >= 1


def test_success_resets_failure_counter(client):
    register(client, "alice")
    for _ in range(4):
        login(client, "alice", "wrong-Passw0rd!")
    assert login(client, "alice").status_code == 302
    client.post("/logout")
    for _ in range(4):
        assert login(client, "alice", "wrong-Passw0rd!").status_code == 401


def test_logout_invalidates_old_cookie(app):
    c1 = app.test_client()
    register(c1, "alice")
    login(c1, "alice")
    cookie = c1.get_cookie("session").value
    assert c1.get("/api/me").status_code == 200
    c1.post("/logout")
    c2 = app.test_client()
    c2.set_cookie("session", cookie)
    assert c2.get("/api/me").status_code == 401


def test_account_session_revoke_and_password_change(app):
    first = app.test_client()
    register(first, "alice")
    login(first, "alice")
    second = app.test_client()
    login(second, "alice")
    assert first.get("/account").status_code == 200
    assert first.post("/account/sessions/revoke-others").status_code == 302
    assert first.get("/api/me").status_code == 200
    assert second.get("/api/me").status_code == 401
    changed = first.post("/account/password", data={
        "current_password": PW, "new_password": "New-Strong-Passw0rd!", "confirm_password": "New-Strong-Passw0rd!"
    })
    assert changed.status_code == 302 and changed.headers["Location"].endswith("/login")
    assert first.get("/api/me").status_code == 401
    assert login(first, "alice", "New-Strong-Passw0rd!").status_code == 302


def test_open_redirect_blocked(client):
    register(client, "alice")
    r = login(client, "alice", query_string={"next": "https://evil.example/x"})
    assert r.headers["Location"].endswith("/dashboard")
    client.post("/logout")
    r = login(client, "alice", query_string={"next": "//evil.example"})
    assert r.headers["Location"].endswith("/dashboard")
    client.post("/logout")
    r = login(client, "alice", query_string={"next": "/inbox"})
    assert r.headers["Location"].endswith("/inbox")


def test_protected_routes_require_auth(client):
    for path in ("/dashboard", "/inbox", "/sent", "/compose", "/events", "/lab", "/status", "/messages/1"):
        r = client.get(path)
        assert r.status_code == 302 and "/login" in r.headers["Location"], path
    for path in ("/api/me", "/api/messages", "/api/stats", "/api/messages/1", "/api/messages/1/envelope"):
        assert client.get(path).status_code == 401, path
    assert client.post("/api/messages", json={}).status_code == 401
    assert client.post("/lab/run/all").status_code == 401
    health = client.get("/api/health")
    assert health.status_code == (200 if health.get_json()["key_check"]["permissions_checked"] else 503)


def test_admin_flag_only_for_configured_name(app, client):
    register(client, "admin")
    register(client, "bob")
    with app.app_context():
        assert User.query.filter_by(username="admin").one().is_admin
        assert not User.query.filter_by(username="bob").one().is_admin
