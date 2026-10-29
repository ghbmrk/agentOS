#!/usr/bin/env python3
"""Print a GGUF model file's general.license (INFER-image, #3655; INFER-A4).

Usage: gguf_licence.py FILE
Prints the value and exits 0; exits 1, printing why, on a file that is not GGUF v2 or v3 or whose
header has no general.license string. image/infer.sh refuses any model whose value is not
apache-2.0, so the licence checked is the one written into the exact file the image ships.
The file is a download: every length is bounded before it is read, and nothing in it is run.
"""
import struct
import sys

MAX_KV = 1 << 16          # metadata pairs
MAX_STR = 1 << 24         # bytes in one string (a chat template is the longest, about 4 KiB)
MAX_ARRAY = 1 << 22       # items in one array (the tokenizer's vocabulary is about 150k)
MAX_DEPTH = 4
# GGUF value types: fixed-size scalars by struct code; 8 is a string, 9 an array.
SCALAR = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
STRING, ARRAY = 8, 9


class Bad(Exception):
    pass


def take(f, n):
    b = f.read(n)
    if len(b) != n:
        raise Bad("truncated header")
    return b


def string(f):
    n, = struct.unpack("<Q", take(f, 8))
    if n > MAX_STR:
        raise Bad("string of %d bytes" % n)
    return take(f, n)


def skip(f, t, depth=0):
    """Read past one value of type t, returning it only when it is a string."""
    if t in SCALAR:
        take(f, struct.calcsize("<" + SCALAR[t]))
        return None
    if t == STRING:
        return string(f)
    if t == ARRAY:
        if depth >= MAX_DEPTH:
            raise Bad("arrays nested past %d" % MAX_DEPTH)
        et, n = struct.unpack("<IQ", take(f, 12))
        if n > MAX_ARRAY:
            raise Bad("array of %d items" % n)
        if et in SCALAR:
            take(f, n * struct.calcsize("<" + SCALAR[et]))
        else:
            for _ in range(n):
                skip(f, et, depth + 1)
        return None
    raise Bad("unknown value type %d" % t)


def licence(path):
    with open(path, "rb") as f:
        if take(f, 4) != b"GGUF":
            raise Bad("not a GGUF file")
        version, = struct.unpack("<I", take(f, 4))
        if version not in (2, 3):
            raise Bad("GGUF version %d" % version)
        _, nkv = struct.unpack("<QQ", take(f, 16))
        if nkv > MAX_KV:
            raise Bad("%d metadata pairs" % nkv)
        for _ in range(nkv):
            key = string(f)
            t, = struct.unpack("<I", take(f, 4))
            v = skip(f, t)
            if key == b"general.license":
                if v is None:
                    raise Bad("general.license is not a string")
                return v.decode("utf-8", "replace")
    raise Bad("no general.license in the header")


if __name__ == "__main__":
    try:
        print(licence(sys.argv[1]))
    except (Bad, OSError) as e:
        print("%s: %s" % (sys.argv[1], e), file=sys.stderr)
        sys.exit(1)
