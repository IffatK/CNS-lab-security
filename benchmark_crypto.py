#!/usr/bin/env python3
"""Measure actual CNS envelope routines against AES-GCM primitive baselines.

This is a local microbenchmark of services.crypto, not an HTTP/application-load test.
Run from the project root with the project virtual environment active.
"""
from __future__ import annotations

import csv
import os
import platform
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import cryptography
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from services.crypto import encrypt_and_sign, decrypt_envelope


ROOT=Path(__file__).resolve().parent
SIZES=(16,256,1024,2000)
TRIALS=100


def main() -> None:
    out=ROOT/"crypto_benchmark.csv"
    fields=["run_timestamp_utc","python_version","cryptography_version","platform",
            "operation","payload_bytes","trial","mode","duration_ns"]
    stamp=datetime.now(timezone.utc).isoformat()
    key=os.urandom(32)
    signer=Ed25519PrivateKey.generate()
    aes=AESGCM(key)
    sanity=encrypt_and_sign(key,signer,1,2,"benchmark-self-check")
    assert decrypt_envelope(key,sanity,signer.public_key())=="benchmark-self-check"
    rng=random.Random(20261017)
    records=[]
    for size in SIZES:
        plaintext="A"*size
        plain=plaintext.encode("utf-8")
        # Prepare valid signed envelopes outside the decrypt timing window.
        envelopes=[encrypt_and_sign(key,signer,1,2,plaintext) for _ in range(TRIALS)]
        pub=signer.public_key()
        for trial in range(TRIALS):
            env=envelopes[trial]
            aad=env.aad()
            # Pair each trial by payload size and alternate execution order randomly.
            for mode in rng.sample(("full_envelope","aesgcm_only"),2):
                if mode=="full_envelope":
                    start=time.perf_counter_ns()
                    produced=encrypt_and_sign(key,signer,1,2,plaintext)
                    elapsed=time.perf_counter_ns()-start
                    records.append((stamp,platform.python_version(),cryptography.__version__,platform.platform(),
                                    "encrypt",size,trial,mode,elapsed))
                else:
                    nonce=os.urandom(12)
                    start=time.perf_counter_ns()
                    aes.encrypt(nonce,plain,aad)
                    elapsed=time.perf_counter_ns()-start
                    records.append((stamp,platform.python_version(),cryptography.__version__,platform.platform(),
                                    "encrypt",size,trial,mode,elapsed))
            decrypted=[]
            for mode in rng.sample(("full_envelope","aesgcm_only"),2):
                if mode=="full_envelope":
                    start=time.perf_counter_ns()
                    recovered=decrypt_envelope(key,env,pub)
                    elapsed=time.perf_counter_ns()-start
                else:
                    start=time.perf_counter_ns()
                    recovered=aes.decrypt(env.nonce,env.ciphertext,aad)
                    elapsed=time.perf_counter_ns()-start
                decrypted.append(recovered)
                records.append((stamp,platform.python_version(),cryptography.__version__,platform.platform(),
                                "decrypt",size,trial,mode,elapsed))
            assert all(value in (plaintext,plain) for value in decrypted)
    with out.open("w",newline="",encoding="utf-8") as f:
        writer=csv.writer(f); writer.writerow(fields); writer.writerows(records)
    print(f"Wrote {len(records)} actual measurements to {out}")
    print(f"Payload sizes: {', '.join(map(str,SIZES))} bytes; {TRIALS} trials per size/mode/operation")
    print(f"Python {platform.python_version()}, cryptography {cryptography.__version__}, {platform.platform()}")


if __name__=="__main__": main()
