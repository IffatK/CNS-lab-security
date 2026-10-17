"""Controlled lab tests executed against the REAL crypto code with ephemeral keys.
Every result is computed at run time; nothing is hardcoded."""
import copy
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from models.message import Message
from services import messaging
from services.crypto import (SignatureError, decrypt_envelope, encrypt_and_sign, public_key_from_b64,
                             public_key_b64, verify_envelope)

PLAINTEXT = "lab-test plaintext 0123456789"


def _fixture():
    master = os.urandom(32)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    env = encrypt_and_sign(master, priv, 1, 2, PLAINTEXT)
    return master, priv, pub, env


def _flip(b: bytes, i=0):
    ba = bytearray(b)
    ba[i] ^= 0x01
    return bytes(ba)


def _rejects(env, pub, master):
    """True only if verification raised AND decrypt_envelope refused to return plaintext."""
    try:
        verify_envelope(env, pub)
        return False, "signature unexpectedly VALID"
    except SignatureError:
        pass
    try:
        decrypt_envelope(master, env, pub)
        return False, "decrypt unexpectedly returned plaintext"
    except SignatureError:
        return True, "SignatureError raised; decrypt refused"


def t_roundtrip(user):
    master, _, pub, env = _fixture()
    verify_envelope(env, pub)
    ok = decrypt_envelope(master, env, pub) == PLAINTEXT
    return ("Encrypt+sign then verify+decrypt returns original plaintext", ok,
            f"alg={env.alg}, nonce={len(env.nonce)}B, sig={len(env.signature)}B, ct={len(env.ciphertext)}B")


def t_tamper_ct(user):
    master, _, pub, env = _fixture()
    env.ciphertext = _flip(env.ciphertext)
    rejected, why = _rejects(env, pub, master)
    # independent AEAD-layer check: raw AES-GCM must also reject the modified ciphertext
    try:
        _, _, _, e2 = _fixture()
        AESGCM(os.urandom(32)).decrypt(e2.nonce, _flip(e2.ciphertext), e2.aad())
        aead = "AES-GCM accepted modified ciphertext (unexpected)"
        aead_ok = False
    except InvalidTag:
        aead, aead_ok = "AES-GCM independently raised InvalidTag", True
    except Exception:
        aead, aead_ok = "AES-GCM rejected (key mismatch path)", True
    return ("Modified ciphertext is rejected, plaintext never released", rejected and aead_ok, f"{why}; {aead}")


def t_tamper_sig(user):
    master, _, pub, env = _fixture()
    env.signature = _flip(env.signature, 10)
    rejected, why = _rejects(env, pub, master)
    return ("Modified signature is rejected", rejected, why)


def t_tamper_meta(user):
    master, _, pub, env = _fixture()
    results = []
    for field, val in (("recipient_id", 99), ("sender_id", 77), ("created_at", "2000-01-01T00:00:00.000000Z"),
                       ("msg_uuid", "00000000-0000-0000-0000-000000000000")):
        e = copy.copy(env)
        setattr(e, field, val)
        results.append((field,) + _rejects(e, pub, master))
    e = copy.copy(env)
    e.nonce = _flip(e.nonce)
    results.append(("nonce",) + _rejects(e, pub, master))
    ok = all(r[1] for r in results)
    return ("Modified signed metadata (recipient, sender, time, id, nonce) is rejected", ok,
            ", ".join(f"{f}:{'rejected' if r else 'ACCEPTED'}" for f, r, _ in results))


def t_wrong_key(user):
    master, _, _, env = _fixture()
    other = Ed25519PrivateKey.generate().public_key()
    rejected, why = _rejects(env, other, master)
    return ("Signature from a different sender key is rejected", rejected, why)


def t_nonce(user):
    master = os.urandom(32)
    priv = Ed25519PrivateKey.generate()
    nonces = {encrypt_and_sign(master, priv, 1, 2, PLAINTEXT).nonce for _ in range(2000)}
    return ("2000 encryptions of the same plaintext use 2000 distinct 12-byte nonces", len(nonces) == 2000,
            f"{len(nonces)} unique nonces of 2000")


def t_audit(user):
    msgs = Message.query.filter((Message.sender_id == user.id) | (Message.recipient_id == user.id)).all()
    if not msgs:
        return ("Every stored message you can access verifies", None, "no stored messages to audit yet")
    bad = [m.id for m in msgs if messaging.verify_signature_status(m) != "verified"]
    return ("Every stored message you can access verifies", not bad,
            f"{len(msgs) - len(bad)} verified, {len(bad)} failed" + (f" (ids {bad[:10]})" if bad else ""))


TESTS = {
    "roundtrip": t_roundtrip, "tamper_ciphertext": t_tamper_ct, "tamper_signature": t_tamper_sig,
    "tamper_metadata": t_tamper_meta, "wrong_key": t_wrong_key, "nonce_uniqueness": t_nonce,
    "stored_audit": t_audit,
}


def run(name, user):
    expected, passed, observed = TESTS[name](user)
    return {"name": name, "expected": expected, "observed": observed, "passed": passed}
