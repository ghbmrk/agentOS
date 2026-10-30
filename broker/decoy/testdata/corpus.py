#!/usr/bin/env python3
"""Writes corpus.json: synthetic, format-valid examples of each decoy kind,
made independently of broker/decoy (Python's secrets, zlib and OpenSSL), for
decoy.TestDecoyIndistinguishable's two-sample test. Synthetic only: no value
here was ever issued by anyone. Run: python3 corpus.py > corpus.json
"""
import base64, json, secrets, struct, subprocess, sys, zlib

N = 100
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
B64URL = B64[:62] + "-_"

def pick(alpha, n):
    return "".join(secrets.choice(alpha) for _ in range(n))

def b62(v, n):
    out = ""
    for _ in range(n):
        out = B62[v % 62] + out
        v //= 62
    return out

def github():
    body = pick(B62, 30)
    return "ghp_" + body + b62(zlib.crc32(body.encode()), 6)

def ssh():
    der = subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    seed = der[-32:]
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der, check=True, capture_output=True).stdout[-32:]
    s = lambda b: struct.pack(">I", len(b)) + b
    blob = s(b"ssh-ed25519") + s(pub)
    check = secrets.token_bytes(4)
    sec = check + check + s(b"ssh-ed25519") + s(pub) + s(seed + pub) + s(b"")
    i = 1
    while len(sec) % 8:
        sec += bytes([i]); i += 1
    raw = b"openssh-key-v1\0" + s(b"none") + s(b"none") + s(b"") + struct.pack(">I", 1) + s(blob) + s(sec)
    enc = base64.b64encode(raw).decode()
    lines = [enc[i:i + 70] for i in range(0, len(enc), 70)]
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----\n"

kinds = {
    "github": github,
    "aws-key-id": lambda: "AKIA" + pick("QRSTUVWXYZ234567", 1) + pick(B32, 15),
    "aws-secret": lambda: pick(B64, 40),
    "anthropic": lambda: "sk-ant-api03-" + pick(B64URL, 93) + "AA",
    "openai": lambda: "sk-proj-" + pick(B64URL, 74) + "T3BlbkFJ" + pick(B64URL, 74),
    "ssh-ed25519": ssh,
    "recovery": lambda: (lambda h: h[:5] + "-" + h[5:])(secrets.token_hex(5)),
}
json.dump({k: [f().encode().hex() for _ in range(N)] for k, f in kinds.items()}, sys.stdout, indent=0, sort_keys=True)
sys.stdout.write("\n")
