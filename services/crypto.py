"""AES-256-GCM authenticated encryption + Ed25519 signatures over a canonical envelope.

Scheme (encrypt-then-sign):
  nonce      = 12 random bytes (os.urandom) per message
  core_meta  = {v, msg_id, sender_id, recipient_id, created_at, alg}
  ciphertext = AES-256-GCM(master_key, nonce, plaintext, AAD = canonical(core_meta))
  signature  = Ed25519(sender_priv, DOMAIN || canonical(core_meta + nonce) || "\\n" || ciphertext)
Verification always happens BEFORE decryption.
"""
import base64
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALG = "AES-256-GCM+Ed25519"
VERSION = 1
NONCE_LEN = 12
SIG_LEN = 64
DOMAIN = b"CNSLAB-ENVELOPE-V1\n"


class CryptoError(Exception):
    pass


class SignatureError(CryptoError):
    pass


class DecryptionError(CryptoError):
    pass


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception as exc:
        raise CryptoError("invalid base64") from exc


def canonical(meta: dict) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only."""
    return json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@dataclass
class Envelope:
    msg_uuid: str
    sender_id: int
    recipient_id: int
    created_at: str
    alg: str
    nonce: bytes
    ciphertext: bytes
    signature: bytes

    def core_meta(self) -> dict:
        return {"v": VERSION, "msg_id": self.msg_uuid, "sender_id": int(self.sender_id),
                "recipient_id": int(self.recipient_id), "created_at": self.created_at, "alg": self.alg}

    def aad(self) -> bytes:
        return canonical(self.core_meta())

    def signed_bytes(self) -> bytes:
        meta = dict(self.core_meta())
        meta["nonce"] = b64e(self.nonce)
        return DOMAIN + canonical(meta) + b"\n" + self.ciphertext


def public_key_from_b64(s: str) -> Ed25519PublicKey:
    raw = b64d(s)
    if len(raw) != 32:
        raise CryptoError("bad public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def public_key_b64(priv: Ed25519PrivateKey) -> str:
    return b64e(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def encrypt_and_sign(master_key: bytes, sender_priv: Ed25519PrivateKey, sender_id: int,
                     recipient_id: int, plaintext: str) -> Envelope:
    if len(master_key) != 32:
        raise CryptoError("AES-256 key must be 32 bytes")
    env = Envelope(
        msg_uuid=str(uuid.uuid4()), sender_id=sender_id, recipient_id=recipient_id,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), alg=ALG,
        nonce=os.urandom(NONCE_LEN), ciphertext=b"", signature=b"")
    env.ciphertext = AESGCM(master_key).encrypt(env.nonce, plaintext.encode("utf-8"), env.aad())
    env.signature = sender_priv.sign(env.signed_bytes())
    return env


def encrypt_unprotected(master_key: bytes, sender_id: int, recipient_id: int, plaintext: str) -> Envelope:
    """Encrypt a deliberately unsigned plaintext-relay delivery for storage at rest."""
    if len(master_key) != 32:
        raise CryptoError("AES-256 key must be 32 bytes")
    env = Envelope(
        msg_uuid=str(uuid.uuid4()), sender_id=sender_id, recipient_id=recipient_id,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), alg=ALG,
        nonce=os.urandom(NONCE_LEN), ciphertext=b"", signature=b"")
    env.ciphertext = AESGCM(master_key).encrypt(env.nonce, plaintext.encode("utf-8"), env.aad())
    return env


def reencrypt_without_resigning(master_key: bytes, original: Envelope, plaintext: str) -> Envelope:
    """Create an attacker-edited ciphertext but retain the original signature verbatim."""
    if len(master_key) != 32:
        raise CryptoError("AES-256 key must be 32 bytes")
    env = Envelope(original.msg_uuid, original.sender_id, original.recipient_id,
                   original.created_at, original.alg, os.urandom(NONCE_LEN), b"", original.signature)
    env.ciphertext = AESGCM(master_key).encrypt(env.nonce, plaintext.encode("utf-8"), env.aad())
    return env


def decrypt_unprotected(master_key: bytes, env: Envelope) -> str:
    """Open an unsigned relay envelope; AEAD protects storage, not sender authenticity."""
    if env.alg != ALG or len(env.nonce) != NONCE_LEN or env.signature:
        raise CryptoError("malformed unprotected relay envelope")
    try:
        return AESGCM(master_key).decrypt(env.nonce, env.ciphertext, env.aad()).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise DecryptionError("authenticated decryption failed") from exc


def verify_envelope(env: Envelope, sender_pub: Ed25519PublicKey) -> None:
    if env.alg != ALG:
        raise SignatureError("unsupported algorithm")
    if len(env.nonce) != NONCE_LEN or len(env.signature) != SIG_LEN:
        raise SignatureError("malformed nonce/signature")
    try:
        sender_pub.verify(env.signature, env.signed_bytes())
    except InvalidSignature as exc:
        raise SignatureError("signature verification failed") from exc


def decrypt_envelope(master_key: bytes, env: Envelope, sender_pub: Ed25519PublicKey) -> str:
    verify_envelope(env, sender_pub)  # never decrypt unverified data
    try:
        return AESGCM(master_key).decrypt(env.nonce, env.ciphertext, env.aad()).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise DecryptionError("authenticated decryption failed") from exc
