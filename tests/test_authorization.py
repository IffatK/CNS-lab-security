from conftest import new_user, send, login, register
from models import SecurityEvent


def test_idor_blocked_everywhere(app):
    a, b, c = new_user(app, "alice"), new_user(app, "bob"), new_user(app, "carol")
    mid = send(a, "bob", "private").get_json()["id"]
    for path in (f"/api/messages/{mid}", f"/api/messages/{mid}/envelope", f"/messages/{mid}"):
        assert c.get(path).status_code == 404, path
        assert b.get(path).status_code == 200, path
    assert c.get("/api/messages/9999").status_code == 404  # indistinguishable from forbidden
    assert c.get("/api/messages?box=inbox").get_json()["messages"] == []
    assert c.get("/api/messages?box=sent").get_json()["messages"] == []
    with app.app_context():
        ev = SecurityEvent.query.filter_by(event_type="access_denied").all()
        assert len(ev) >= 3 and all("private" not in e.detail for e in ev)


def test_id_enumeration_yields_nothing(app):
    a, c = new_user(app, "alice"), new_user(app, "carol"); new_user(app, "bob")
    for _ in range(3):
        send(a, "bob", "x")
    assert [c.get(f"/api/messages/{i}").status_code for i in range(1, 8)] == [404] * 7


def test_verify_endpoint_requires_auth_and_valid_json(app):
    anon = app.test_client()
    assert anon.post("/api/verify", json={}).status_code == 401
    a = new_user(app, "alice")
    assert a.post("/api/verify", json={"x": 1}).status_code == 400


def test_events_visibility_scoped(app):
    admin, bob = new_user(app, "admin"), new_user(app, "bob")
    carol = app.test_client(); register(carol, "carol"); login(carol, "carol", "wrong-Passw0rd!")
    assert b"carol" in admin.get("/events").data      # admin sees everyone
    assert b"carol" not in bob.get("/events").data     # normal user does not
