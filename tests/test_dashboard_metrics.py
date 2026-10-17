from conftest import login, new_user, send
from extensions import db
from models import LoginAttempt, SecurityNotification
from models.base import utcnow


def test_dashboard_metrics_are_real_and_user_scoped(app):
    alice = new_user(app, "alice")
    bob = new_user(app, "bob")
    assert send(alice, "bob", "signed dashboard message").status_code == 201
    assert send(bob, "alice", "reply").status_code == 201
    with app.app_context():
        db.session.add(LoginAttempt(username="alice", ip="127.0.0.1", success=True, created_at=utcnow()))
        db.session.add(LoginAttempt(username="alice", ip="127.0.0.1", success=False, created_at=utcnow()))
        db.session.commit()
    result = alice.get("/api/dashboard/metrics?days=7")
    assert result.status_code == 200
    data = result.get_json()
    assert data["integrity"]["verified"] == 2
    assert sum(point["count"] for point in data["logins"]["successful"]) >= 1
    assert sum(point["count"] for point in data["logins"]["failed"]) == 1
    # The API carries event names and aggregate values, never message plaintext.
    assert "signed dashboard message" not in result.get_data(as_text=True)
    assert alice.get("/api/dashboard/metrics?days=custom&date_from=2026-01-01&date_to=2026-10-16").status_code == 200
    assert alice.get("/api/dashboard/metrics?days=custom&date_from=2026-10-16&date_to=2025-01-01").status_code == 400
    assert alice.get("/events?date_from=2026-10-16").status_code == 400
    report = alice.get("/events.csv?date_from=2026-10-16&date_to=2026-10-16")
    assert report.status_code == 200 and b"report_generated_at_utc" in report.data


def test_dashboard_diagnostics_and_notifications(app):
    client = new_user(app, "alice")
    assert login(app.test_client(), "alice", "incorrect-password").status_code == 401
    diagnostics = client.get("/api/diagnostics").get_json()
    names = {item["name"] for item in diagnostics["components"]}
    assert {"Flask application", "Database and schema", "CSRF protection", "ClamAV scanner", "Private file storage",
            "HTTPS and certificates", "Session cookie and current protocol"} <= names
    assert all("checked_at" in item and "detail" in item for item in diagnostics["components"])
    assert next(item for item in diagnostics["components"] if item["name"] == "CSRF protection")["status"] == "HEALTHY"
    page = client.get("/notifications")
    assert page.status_code == 200 and b"Failed sign-in attempt" in page.data
    with app.app_context():
        notification = SecurityNotification.query.one()
        n_id = notification.id
        assert notification.read_at is None
    assert client.post(f"/notifications/{n_id}/read").status_code == 302
    with app.app_context():
        assert db.session.get(SecurityNotification, n_id).read_at is not None


def test_relay_event_creates_notification_for_message_owner(app):
    from models import InterceptedMessage
    from services.security_log import log_event
    alice = new_user(app, "alice")
    new_user(app, "bob")
    with app.app_context():
        item = InterceptedMessage(sender_username="alice", recipient_username="bob", original_body="x",
                                  source_ip="127.0.0.1", status="dropped")
        db.session.add(item)
        db.session.commit()
        log_event("attacker_dropped_message", "warning", username=item.sender_username,
                  detail="test event")
    page = alice.get("/notifications")
    assert page.status_code == 200 and b"Lab relay dropped a message" in page.data
    bob = app.test_client()
    login(bob, "bob")
    assert b"Lab relay dropped a message" not in bob.get("/notifications").data


def test_dashboard_metrics_requires_authentication(app):
    response = app.test_client().get("/api/dashboard/metrics")
    assert response.status_code == 401
