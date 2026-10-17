from extensions import db
from models.base import utcnow
from services.crypto import Envelope, b64d, b64e
import json

class LabSettings(db.Model):
    __tablename__ = "lab_settings"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False, index=True)
    protection_enabled = db.Column(db.Boolean, nullable=False, default=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow, onupdate=utcnow)

class LabCapture(db.Model):
    __tablename__ = "lab_captures"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    username = db.Column(db.String(64), nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    recipient = db.Column(db.String(64), nullable=False)
    protection = db.Column(db.String(16), nullable=False)  # plaintext or protected
    visible_content = db.Column(db.Text, nullable=True)    # populated only in explicit unprotected lab mode
    wire_preview = db.Column(db.Text, nullable=False, default="")
    message_id = db.Column(db.Integer, nullable=True)
    status = db.Column(db.String(24), nullable=False, default="accepted")


class InterceptedMessage(db.Model):
    """Messages deliberately held for manual editing in the isolated MITM lab."""
    __tablename__ = "intercepted_messages"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    sender_username = db.Column(db.String(64), nullable=False)
    recipient_username = db.Column(db.String(64), nullable=False)
    original_body = db.Column(db.Text, nullable=False)
    edited_body = db.Column(db.Text, nullable=True)
    source_ip = db.Column(db.String(45), nullable=False, default="unknown")
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending, forwarded, dropped
    delivered_message_id = db.Column(db.Integer, nullable=True)
    envelope_json = db.Column(db.LargeBinary, nullable=True)
    recipient_protected = db.Column(db.Boolean, nullable=False, default=False)

    def set_envelope(self, env: Envelope):
        self.envelope_json = json.dumps({
            "msg_uuid": env.msg_uuid, "sender_id": env.sender_id, "recipient_id": env.recipient_id,
            "created_at": env.created_at, "alg": env.alg, "nonce": b64e(env.nonce),
            "ciphertext": b64e(env.ciphertext), "signature": b64e(env.signature),
        }, sort_keys=True, separators=(",", ":")).encode("ascii")

    def get_envelope(self):
        if not self.envelope_json:
            return None
        data = json.loads(bytes(self.envelope_json).decode("ascii"))
        return Envelope(data["msg_uuid"], int(data["sender_id"]), int(data["recipient_id"]),
                        data["created_at"], data["alg"], b64d(data["nonce"]),
                        b64d(data["ciphertext"]), b64d(data["signature"]))
