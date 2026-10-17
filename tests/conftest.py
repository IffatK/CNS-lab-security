import pytest

from app import create_app
from extensions import db

PW = "Str0ng-Passw0rd!"


def make_app(tmp_path, csrf=False, **extra):
    cfg = {"TESTING": True, "SECRET_KEY": "test-secret-key", "INSTANCE_DIR": str(tmp_path / "instance"),
           "AUTO_INIT_KEYS": True, "WTF_CSRF_ENABLED": csrf, "ADMIN_USERNAMES": ["admin"],
           # Tests must not inherit the developer's .env HTTPS listener and
           # fail before reaching their isolated HTTP fixtures. TLS-specific
           # tests opt in with explicit cert/key paths below.
           "REQUIRE_HTTPS": False, "TLS_CERT_FILE": None, "TLS_KEY_FILE": None}
    cfg.update(extra)
    app = create_app(cfg)
    with app.app_context():
        db.create_all()
    return app


@pytest.fixture
def app(tmp_path):
    a = make_app(tmp_path)
    yield a
    with a.app_context():
        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def csrf_app(tmp_path):
    a = make_app(tmp_path, csrf=True)
    yield a
    with a.app_context():
        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()


def register(c, user, pw=PW):
    return c.post("/register", data={"username": user, "password": pw, "confirm": pw})


def login(c, user, pw=PW, **kw):
    return c.post("/login", data={"username": user, "password": pw}, **kw)


def new_user(app, user):
    c = app.test_client()
    assert register(c, user).status_code == 302
    assert login(c, user).status_code == 302
    return c


def send(c, to, body):
    return c.post("/api/messages", json={"recipient": to, "body": body})
