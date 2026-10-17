import sqlite3

from conftest import make_app
from sqlalchemy import inspect, text


def test_additive_upgrade_backs_up_existing_instance_once(tmp_path):
    instance = tmp_path / "instance"
    instance.mkdir()
    database = instance / "cns_lab.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE legacy_marker (value TEXT NOT NULL)")
        conn.execute("INSERT INTO legacy_marker VALUES ('preserve-me')")
        conn.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE intercepted_messages (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE security_findings (id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL, key VARCHAR(80) NOT NULL, title VARCHAR(180) NOT NULL, severity VARCHAR(16) NOT NULL, confidence VARCHAR(16) NOT NULL, category VARCHAR(48) NOT NULL, affected VARCHAR(2048) NOT NULL DEFAULT '', evidence TEXT NOT NULL DEFAULT '', explanation TEXT NOT NULL DEFAULT '', impact TEXT NOT NULL DEFAULT '', remediation TEXT NOT NULL DEFAULT '', source VARCHAR(160) NOT NULL DEFAULT 'local scanner', verification VARCHAR(24) NOT NULL DEFAULT 'observed', created_at DATETIME NOT NULL)")
    app = make_app(tmp_path)
    with app.app_context():
        inspector = inspect(app.extensions["sqlalchemy"].engine)
        assert "protection" in {c["name"] for c in inspector.get_columns("messages")}
        assert "envelope_json" in {c["name"] for c in inspector.get_columns("intercepted_messages")}
        assert "security_notifications" in inspector.get_table_names()
        assert {"remediation_steps_json", "verification_steps_json"}.issubset(
            {c["name"] for c in inspector.get_columns("security_findings")})
        assert app.extensions["sqlalchemy"].session.execute(text("SELECT value FROM legacy_marker")).scalar_one() == "preserve-me"
    backups = list((instance / "backups").iterdir())
    assert len(backups) == 1
    with sqlite3.connect(backups[0] / "cns_lab.db") as conn:
        assert conn.execute("SELECT value FROM legacy_marker").fetchone() == ("preserve-me",)
    assert (backups[0] / "keys" / "aes_master.key").is_file()
    with app.app_context():
        app.extensions["sqlalchemy"].session.remove()
        app.extensions["sqlalchemy"].engine.dispose()
