from extensions import db
from models.base import utcnow


class MalwareScan(db.Model):
    __tablename__ = "malware_scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(16), nullable=False, index=True)
    engine = db.Column(db.String(120), nullable=False, default="unavailable")
    definitions = db.Column(db.String(120), nullable=False, default="unknown")
    detection = db.Column(db.String(255), nullable=False, default="")
    error = db.Column(db.String(255), nullable=False, default="")
    duration_ms = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)


class SharedFile(db.Model):
    __tablename__ = "shared_files"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    storage_key = db.Column(db.String(64), unique=True, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    mime_type = db.Column(db.String(120), nullable=False, default="application/octet-stream")
    scan_status = db.Column(db.String(16), nullable=False, default="failed")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    owner = db.relationship("User", foreign_keys=[owner_id])
    shares = db.relationship("FileShare", back_populates="file", foreign_keys="FileShare.file_id")


class FileShare(db.Model):
    __tablename__ = "file_shares"
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("shared_files.id"), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    file = db.relationship("SharedFile", back_populates="shares", foreign_keys=[file_id])
    recipient = db.relationship("User", foreign_keys=[recipient_id])
