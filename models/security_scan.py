from extensions import db
from models.base import utcnow


class SecurityScan(db.Model):
    __tablename__ = "security_scans"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    scan_type = db.Column(db.String(16), nullable=False, index=True)
    target = db.Column(db.String(2048), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="queued", index=True)
    progress = db.Column(db.Integer, nullable=False, default=0)
    cancel_requested = db.Column(db.Boolean, nullable=False, default=False)
    authorized = db.Column(db.Boolean, nullable=False, default=False)
    consent_reputation = db.Column(db.Boolean, nullable=False, default=False)
    risk_score = db.Column(db.Integer, nullable=True)
    risk_level = db.Column(db.String(16), nullable=False, default="unknown")
    summary_json = db.Column(db.Text, nullable=False, default="{}")
    config_json = db.Column(db.Text, nullable=False, default="{}")
    error = db.Column(db.String(500), nullable=False, default="")
    duration_ms = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    findings = db.relationship("SecurityFinding", back_populates="scan", cascade="all, delete-orphan",
                               order_by="SecurityFinding.id")


class SecurityFinding(db.Model):
    __tablename__ = "security_findings"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("security_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    key = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(180), nullable=False)
    severity = db.Column(db.String(16), nullable=False, index=True)
    confidence = db.Column(db.String(16), nullable=False)
    category = db.Column(db.String(48), nullable=False, index=True)
    affected = db.Column(db.String(2048), nullable=False, default="")
    evidence = db.Column(db.Text, nullable=False, default="")
    explanation = db.Column(db.Text, nullable=False, default="")
    impact = db.Column(db.Text, nullable=False, default="")
    remediation = db.Column(db.Text, nullable=False, default="")
    remediation_steps_json = db.Column(db.Text, nullable=False, default="[]")
    verification_steps_json = db.Column(db.Text, nullable=False, default="[]")
    source = db.Column(db.String(160), nullable=False, default="local scanner")
    verification = db.Column(db.String(24), nullable=False, default="observed")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    scan = db.relationship("SecurityScan", back_populates="findings")
