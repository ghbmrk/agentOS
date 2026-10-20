"""DKIM (RFC 6376) for the eval's synthetic mail: rsa-sha256 with relaxed/relaxed
canonicalization, signing for gen.py and verification for the reference predicate.

Standard library only. Keys are made fresh by gen.py and only their public halves are
kept (keys.json), so no private key is ever in the repository.
"""
import base64
import hashlib
import re
import secrets

# DER DigestInfo prefix for SHA-256 (RFC 8017 section 9.2, note 1).
_SHA256_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
# DER AlgorithmIdentifier for rsaEncryption with NULL parameters.
_RSA_ALG = bytes.fromhex("300d06092a864886f70d0101010500")


def _probable_prime(n, rounds=40):
    if n < 4:
        return n in (2, 3)
    for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        c = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if _probable_prime(c):
            return c


def keygen(bits=2048):
    """A fresh RSA key as (n, e, d)."""
    e = 65537
    while True:
        p, q = _prime(bits // 2), _prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % e:
            n = p * q
            if n.bit_length() == bits:
                return n, e, pow(e, -1, phi)


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag, body):
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(v):
    b = v.to_bytes(v.bit_length() // 8 + 1, "big")
    return _der(0x02, b)


def public_der(n, e):
    """SubjectPublicKeyInfo DER, the form a DKIM key record's p= carries."""
    rsa = _der(0x30, _der_int(n) + _der_int(e))
    return _der(0x30, _RSA_ALG + _der(0x03, b"\x00" + rsa))


def _read(buf, i):
    tag, i = buf[i], i + 1
    n = buf[i]
    i += 1
    if n & 0x80:
        k = n & 0x7F
        n, i = int.from_bytes(buf[i:i + k], "big"), i + k
    return tag, buf[i:i + n], i + n


def parse_public(p):
    """(n, e) from a key record's base64 p= value; raises ValueError if malformed."""
    der = base64.b64decode(p, validate=True)
    tag, spki, _ = _read(der, 0)
    tag2, alg, j = _read(spki, 0)
    tag3, bits, _ = _read(spki, j)
    if (tag, tag2, tag3) != (0x30, 0x30, 0x03) or _der(0x30, alg) != _RSA_ALG or bits[:1] != b"\x00":
        raise ValueError("not an RSA SubjectPublicKeyInfo")
    _, seq, _ = _read(bits, 1)
    _, nb, k = _read(seq, 0)
    _, eb, _ = _read(seq, k)
    return int.from_bytes(nb, "big"), int.from_bytes(eb, "big")


def _emsa(digest, k):
    t = _SHA256_INFO + digest
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


# --- messages -------------------------------------------------------------------------

def split(raw):
    """(headers, body): headers as [(name, raw value with folding kept)], in order."""
    head, sep, body = raw.partition(b"\r\n\r\n")
    if not sep:
        head, body = raw, b""
    headers = []
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and headers:
            name, value = headers[-1]
            headers[-1] = (name, value + b"\r\n" + line)
        elif line:
            name, _, value = line.partition(b":")
            headers.append((name.decode("ascii"), value))
    return headers, body


def relaxed_header(name, value):
    v = re.sub(rb"\r\n", b"", value)
    v = re.sub(rb"[ \t]+", b" ", v).strip(b" ")
    return name.strip().lower().encode("ascii") + b":" + v + b"\r\n"


def relaxed_body(body, limit=None):
    lines = body.split(b"\r\n")
    if lines and lines[-1] == b"":
        lines.pop()
    out = [re.sub(rb"[ \t]+", b" ", ln).rstrip(b" ") for ln in lines]
    while out and out[-1] == b"":
        out.pop()
    canon = b"".join(ln + b"\r\n" for ln in out)
    return canon if limit is None else canon[:limit]


def tags(value):
    """A DKIM-Signature's tag list as a dict; raises ValueError on a repeated tag."""
    out = {}
    for part in re.sub(rb"\s+", b"", value).decode("ascii").split(";"):
        if not part:
            continue
        k, _, v = part.partition("=")
        if k in out:
            raise ValueError("repeated tag " + k)
        out[k] = v
    return out


def _select(headers, names):
    """Header instances for h=, bottom-up per name (RFC 6376 section 5.4.2). A name listed
    more times than it occurs signs as empty, which is what over-signing relies on."""
    used = {}
    picked = []
    for name in names:
        key = name.strip().lower()
        seen = used.get(key, 0)
        inst = [h for h in headers if h[0].strip().lower() == key]
        if seen < len(inst):
            picked.append(inst[len(inst) - 1 - seen])
        used[key] = seen + 1
    return picked


def _header_input(headers, names, sig_value):
    data = b"".join(relaxed_header(n, v) for n, v in _select(headers, names))
    unsigned = re.sub(rb"(\bb=)[^;]*", rb"\1", sig_value)
    return data + relaxed_header("DKIM-Signature", unsigned).rstrip(b"\r\n")


def sign(raw, d, s, key, signed, l_tag=False):
    """raw with a DKIM-Signature prepended. signed lists h= names in order (repeat a name
    to over-sign it); l_tag adds l= with the current canonical body length."""
    n, _, priv = key
    headers, body = split(raw)
    canon = relaxed_body(body)
    parts = ["v=1", "a=rsa-sha256", "c=relaxed/relaxed", "d=" + d, "s=" + s]
    if l_tag:
        parts.append("l=%d" % len(canon))
    parts += ["h=" + ":".join(signed), "bh=" + base64.b64encode(hashlib.sha256(canon).digest()).decode(), "b="]
    value = (" " + "; ".join(parts)).encode()
    k = (n.bit_length() + 7) // 8
    em = _emsa(hashlib.sha256(_header_input(headers, signed, value)).digest(), k)
    sig = pow(int.from_bytes(em, "big"), priv, n).to_bytes(k, "big")
    value += base64.b64encode(sig)
    return b"DKIM-Signature:" + value + b"\r\n" + raw


def verify(raw, keys):
    """Each DKIM-Signature's result as dicts {d, h, l, pass, why}. keys maps
    "<s>._domainkey.<d>" to a key record's p= value."""
    headers, body = split(raw)
    results = []
    for name, value in headers:
        if name.strip().lower() != "dkim-signature":
            continue
        r = {"d": None, "h": [], "l": None, "pass": False, "why": ""}
        results.append(r)
        try:
            t = tags(value)
        except ValueError as err:
            r["why"] = str(err)
            continue
        r["d"] = t.get("d", "").lower() or None
        r["h"] = [x.strip().lower() for x in t.get("h", "").split(":") if x.strip()]
        r["l"] = t.get("l")
        if t.get("v") != "1" or t.get("a") != "rsa-sha256" or t.get("c") != "relaxed/relaxed":
            r["why"] = "unsupported v, a or c"
            continue
        if "from" not in r["h"]:
            r["why"] = "h= lacks from"
            continue
        rec = keys.get("%s._domainkey.%s" % (t.get("s", ""), r["d"]))
        if rec is None:
            r["why"] = "no key record"
            continue
        limit = int(r["l"]) if r["l"] is not None and r["l"].isdigit() else None
        if base64.b64encode(hashlib.sha256(relaxed_body(body, limit)).digest()).decode() != t.get("bh"):
            r["why"] = "body hash mismatch"
            continue
        try:
            n, e = parse_public(rec)
            sig = int.from_bytes(base64.b64decode(t.get("b", ""), validate=True), "big")
        except ValueError as err:
            r["why"] = "bad key or signature encoding: %s" % err
            continue
        k = (n.bit_length() + 7) // 8
        want = _emsa(hashlib.sha256(_header_input(headers, t["h"].split(":"), value)).digest(), k)
        if sig >= n or pow(sig, e, n).to_bytes(k, "big") != want:
            r["why"] = "signature mismatch"
            continue
        r["pass"] = True
    return results
