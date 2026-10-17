import copy
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.crypto import (DecryptionError, SignatureError, canonical, decrypt_envelope, encrypt_and_sign,
                             verify_envelope)


@pytest.fixture
def parts():
    master = os.urandom(32)
    priv = Ed25519PrivateKey.generate()
    return master, priv.public_key(), encrypt_and_sign(master, priv, 1, 2, "hello secret")


def flip(b, i=0):
    x = bytearray(b); x[i] ^= 1; return bytes(x)


def test_roundtrip(parts):
    master, pub, env = parts
    verify_envelope(env, pub)
    assert decrypt_envelope(master, env, pub) == "hello secret"
    assert b"hello secret" not in env.ciphertext


def test_nonce_12_bytes_and_unique():
    master, priv = os.urandom(32), Ed25519PrivateKey.generate()
    ns = [encrypt_and_sign(master, priv, 1, 2, "x").nonce for _ in range(500)]
    assert all(len(n) == 12 for n in ns) and len(set(ns)) == 500


def test_same_plaintext_different_ciphertext():
    master, priv = os.urandom(32), Ed25519PrivateKey.generate()
    a, b = (encrypt_and_sign(master, priv, 1, 2, "same") for _ in range(2))
    assert a.ciphertext != b.ciphertext


@pytest.mark.parametrize("field", ["ciphertext", "signature", "nonce"])
def test_tampered_bytes_rejected(parts, field):
    master, pub, env = parts
    setattr(env, field, flip(getattr(env, field), 3))
    with pytest.raises(SignatureError):
        decrypt_envelope(master, env, pub)


@pytest.mark.parametrize("field,val", [("recipient_id", 9), ("sender_id", 9), ("created_at", "2001-01-01T00:00:00.000000Z"),
                                       ("msg_uuid", "x"), ("alg", "none")])
def test_tampered_metadata_rejected(parts, field, val):
    master, pub, env = parts
    e = copy.copy(env); setattr(e, field, val)
    with pytest.raises(SignatureError):
        decrypt_envelope(master, e, pub)


def test_wrong_sender_key_rejected(parts):
    master, _, env = parts
    with pytest.raises(SignatureError):
        decrypt_envelope(master, env, Ed25519PrivateKey.generate().public_key())


def test_never_decrypts_when_signature_invalid(parts, monkeypatch):
    master, pub, env = parts
    env.signature = flip(env.signature)
    import services.crypto as c
    monkeypatch.setattr(c, "AESGCM", lambda k: (_ for _ in ()).throw(AssertionError("decrypt reached")))
    with pytest.raises(SignatureError):
        decrypt_envelope(master, env, pub)


def test_validly_signed_but_wrong_master_key_fails_aead(parts):
    master, pub, env = parts
    with pytest.raises(DecryptionError):
        decrypt_envelope(os.urandom(32), env, pub)


def test_canonical_is_order_independent():
    assert canonical({"b": 1, "a": [1, 2]}) == canonical({"a": [1, 2], "b": 1}) == b'{"a":[1,2],"b":1}'
