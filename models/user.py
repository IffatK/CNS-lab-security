from flask_login import UserMixin

from extensions import db
from models.base import utcnow


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)  # stored lowercase
    password_hash = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.String(64), nullable=False)  # base64 Ed25519 public key
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    session_epoch = db.Column(db.Integer, nullable=False, default=0)  # bump = invalidate all sessions
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
