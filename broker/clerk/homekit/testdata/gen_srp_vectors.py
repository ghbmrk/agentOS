"""Pinned SRP-6a vectors for TestSRPVectors: an independent second implementation.

Python standard library only. It follows RFC 5054 (3072-bit group, g = 5) and
RFC 2945 with HAP's choices: SHA-512, user "Pair-Setup", and fixed-width
encodings (PAD = 384 bytes for A, B and S; the 16-byte salt as sent). Each
formula was checked against aiohomekit 4.0.1 aiohomekit/crypto/srp.py, read
as text only (never run); the two agree on every line marked "agrees".

    python3 -I gen_srp_vectors.py > srp_vectors.json

Every input is a synthetic canary: no setup code below belongs to an
accessory, and the private values are fixed counters, not keys.
"""
import hashlib
import json
import sys

N = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
    "E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
    16,
)  # RFC 5054 appendix A, 3072-bit group (agrees)
G = 5
L = 384
USER = b"Pair-Setup"


def H(*parts):
    return hashlib.sha512(b"".join(parts)).digest()


def pad(n):
    return n.to_bytes(L, "big")


def num(b):
    return int.from_bytes(b, "big")


K_MUL = num(H(pad(N), pad(G)))  # k = H(N | PAD(g)) (agrees: equals srp.py CLIENT_K_VALUE)
assert format(K_MUL, "x").startswith("a9c2e2559bf0ebb53f0cbbf62282906bede7f218")
H_GROUP = bytes(x ^ y for x, y in zip(H(pad(N)), H(bytes([G]))))  # H(N) xor H(g), g unpadded (agrees)


def vector(name, code, salt, a, b):
    x = num(H(salt, H(USER + b":" + code.encode())))  # x = H(s | H(I ":" P)) (agrees)
    v = pow(G, x, N)
    A = pow(G, a, N)
    B = (K_MUL * v + pow(G, b, N)) % N  # B = k*v + g^b (agrees)
    u = num(H(pad(A), pad(B)))  # u = H(PAD(A) | PAD(B)) (agrees)
    S_client = pow((B - K_MUL * v) % N, a + u * x, N)
    S_server = pow(A * pow(v, u, N), b, N)
    assert S_client == S_server
    K = H(pad(S_client))  # K = H(PAD(S)) (agrees)
    M1 = H(H_GROUP, H(USER), salt, pad(A), pad(B), K)  # (agrees)
    M2 = H(pad(A), M1, K)  # (agrees)
    return {
        "name": name, "code": code, "salt": salt.hex(),
        "a": format(a, "x"), "b": format(b, "x"),
        "A": pad(A).hex(), "B": pad(B).hex(), "K": K.hex(),
        "M1": M1.hex(), "M2": M2.hex(),
    }


CASES = [
    ("plain", "111-22-333", "0102030405060708090a0b0c0d0e0f10",
     0x1111111122222222333333334444444455555555666666667777777788888888,
     0x99999999AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFF00000001),
    ("zero-led-salt", "111-22-333", "0000000000000000000000000000beef",
     0x0123456789ABCDEF0123456789ABCDEF, 0xFEDCBA9876543210FEDCBA9876543210),
    ("other-code", "999-88-777", "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", 0x42, 0x4242),
]



def first_zero_led(start, value):
    """The first counter from start whose value's 384-byte form starts 0x00."""
    n = start
    while pad(value(n))[0] != 0:
        n += 1
    return n


# A vector whose B starts with a zero byte, so PAD() is exercised on the
# value the accessory sends (#3325 item 8; "other-code" already has an A
# that starts with zero bytes). The private value is found by counting up
# from a fixed start, so the search is reproducible.
ZL_CODE, ZL_SALT = "222-33-444", bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
ZL_X = num(H(ZL_SALT, H(USER + b":" + ZL_CODE.encode())))
ZL_B = first_zero_led(0x5000, lambda b: (K_MUL * pow(G, ZL_X, N) + pow(G, b, N)) % N)
CASES += [
    ("zero-led-B", ZL_CODE, ZL_SALT.hex(), 0x1234, ZL_B),
]

json.dump({
    "generator": "gen_srp_vectors.py (independent; formulas cross-read against aiohomekit 4.0.1 srp.py)",
    "vectors": [vector(n, c, bytes.fromhex(s), a, b) for n, c, s, a, b in CASES],
}, sys.stdout, indent=1)
print()
