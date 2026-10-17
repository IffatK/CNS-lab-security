from extensions import db
from models.base import utcnow


class SecurityEvent(db.Model):
    __tablename__ = "security_events"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    event_type = db.Column(db.String(40), nullable=False, index=True)
    severity = db.Column(db.String(10), nullable=False, default="info")
    user_id = db.Column(db.Integer, nullable=True, index=True)
    username = db.Column(db.String(64), nullable=True)
    ip = db.Column(db.String(45), nullable=True)
    detail = db.Column(db.String(500), nullable=False, default="")


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    username = db.Column(db.String(64), nullable=False, index=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    success = db.Column(db.Boolean, nullable=False)


class UserSession(db.Model):
    __tablename__ = "user_sessions"
    id = db.Column(db.Integer, primary_key=True)
    sid_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    ip = db.Column(db.String(45), nullable=False, default="unknown")
    user_agent = db.Column(db.String(300), nullable=False, default="unknown")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    revoked_at = db.Column(db.DateTime, nullable=True)


class SecurityNotification(db.Model):
    __tablename__ = "security_notifications"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    event_id = db.Column(db.Integer, db.ForeignKey("security_events.id"), unique=True, nullable=False)
    title = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    read_at = db.Column(db.DateTime, nullable=True)
    event = db.relationship("SecurityEvent")
