"""DTMF keypad decoder (Goertzel) for 8 kHz, 16-bit mono PCM.

S2 uses it to check the uplink audio of a call: the owner hears digits and presses them on the keypad.
It also probes CH-17's premise that the broker can decode keypad codes from call audio itself."""
import math
import struct

RATE = 8000
ROWS = (697, 770, 852, 941)
COLS = (1209, 1336, 1477, 1633)
KEYS = ("123A", "456B", "789C", "*0#D")
FRAME = 205  # ~25.6 ms, the classic DTMF Goertzel block at 8 kHz
HOP = 102


def _power(x, f):
    k = 2 * math.cos(2 * math.pi * f / RATE)
    s1 = s2 = 0.0
    for v in x:
        s1, s2 = v + k * s1 - s2, s1
    return s1 * s1 + s2 * s2 - k * s1 * s2


def frame_key(x):
    """Return the key in one frame of samples, or None."""
    energy = sum(v * v for v in x)
    if energy < len(x) * 1e4:  # silence (~-30 dBFS)
        return None
    rp = [_power(x, f) for f in ROWS]
    cp = [_power(x, f) for f in COLS]
    r, c = max(range(4), key=rp.__getitem__), max(range(4), key=cp.__getitem__)
    # Both tones must dominate their group and carry most of the frame's energy.
    if sorted(rp)[-2] * 4 > rp[r] or sorted(cp)[-2] * 4 > cp[c]:
        return None
    if (rp[r] + cp[c]) * 2 / len(x) < energy * 0.5:
        return None
    twist = rp[r] / cp[c]
    if not 0.1 < twist < 10:
        return None
    return KEYS[r][c]


def decode(samples):
    """Decode a sequence of samples into a string of keys. A key counts once per press (>= 2 frames)."""
    out, prev, run, emitted = [], None, 0, False
    for i in range(0, len(samples) - FRAME + 1, HOP):
        k = frame_key(samples[i:i + FRAME])
        if k == prev:
            run += 1
        else:
            prev, run, emitted = k, 1, False
        if k and run >= 2 and not emitted:
            out.append(k)
            emitted = True
    return "".join(out)


def decode_pcm(raw):
    n = len(raw) // 2
    return decode(struct.unpack("<%dh" % n, raw[:2 * n]))


def tone(key, ms=120, gap=120, amp=8000):
    """Synthesize one key press plus a silence gap (used by tests and the loopback self-check)."""
    r = next(i for i, row in enumerate(KEYS) if key in row)
    c = KEYS[r].index(key)
    n = RATE * ms // 1000
    s = [int(amp * (math.sin(2 * math.pi * ROWS[r] * t / RATE) + math.sin(2 * math.pi * COLS[c] * t / RATE)) / 2)
         for t in range(n)]
    return s + [0] * (RATE * gap // 1000)
