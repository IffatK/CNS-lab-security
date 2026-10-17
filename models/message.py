from extensions import db
from services.crypto import Envelope, ALG


class Message(db.Model):
    __tablename__ = "messages"
    id = db.Column(db.Integer, primary_key=True)
    msg_uuid = db.Column(db.String(36), unique=True, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    created_at = db.Column(db.String(32), nullable=False, index=True)  # ISO-8601 string, part of signed metadata
    alg = db.Column(db.String(40), nullable=False, default=ALG)
    nonce = db.Column(db.LargeBinary, nullable=False, unique=True)
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    signature = db.Column(db.LargeBinary, nullable=False)
    # protected = protected message flow; plaintext_relay = deliberately visible MITM lab traffic.
    protection = db.Column(db.String(32), nullable=False, default="protected")
    relay_ip = db.Column(db.String(45), nullable=True)
    relay_report = db.Column(db.Boolean, nullable=False, default=False)

    sender = db.relationship("User", foreign_keys=[sender_id])
    recipient = db.relationship("User", foreign_keys=[recipient_id])

    @classmethod
    def from_envelope(cls, env: Envelope):
        return cls(msg_uuid=env.msg_uuid, sender_id=env.sender_id, recipient_id=env.recipient_id,
                   created_at=env.created_at, alg=env.alg, nonce=env.nonce,
                   ciphertext=env.ciphertext, signature=env.signature)

    def to_envelope(self) -> Envelope:
        """Rebuilt from DB columns, so tampering with any column breaks verification."""
        return Envelope(msg_uuid=self.msg_uuid, sender_id=self.sender_id, recipient_id=self.recipient_id,
                        created_at=self.created_at, alg=self.alg, nonce=bytes(self.nonce),
                        ciphertext=bytes(self.ciphertext), signature=bytes(self.signature))
