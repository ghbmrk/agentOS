"""S2: does a USB LTE modem do SMS and voice under Linux? Driven over ModemManager (mmcli).

The owner's phone is the only interface: the box texts instructions, the owner replies, answers a
call, presses the digits they hear, then calls the box. Downlink audio is checked by the owner
hearing the digits, uplink audio by decoding the keypad tones (dtmf.py).

Audio routes are vendor specific and UNTESTED until real hardware (from the vendors' AT manuals):
  Quectel (USB 2c7c): USB Audio Class, enabled once with AT+QCFG="usbcfg" (UAC flag), then AT+QPCMV=1,2.
  SIMCom (USB 1e0e): AT+CPCMREG=1 streams 8 kHz 16-bit PCM over the modem's audio serial port.
Results never include IMEI, ICCID, IMSI, or phone numbers. Call recordings go to private/ only."""
import glob
import json
import os
import random
import re
import subprocess
import threading
import time

import dtmf

RATE = 8000


def sh(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return "error: %s" % e


def mm(args, js=False):
    out = sh("mmcli %s%s" % (args, " -J" if js else ""))
    if js:
        try:
            return json.loads(out)
        except ValueError:
            return {}
    return out


def same_number(a, b):
    da, db = re.sub(r"\D", "", a or ""), re.sub(r"\D", "", b or "")
    return len(da) >= 7 and da[-10:] == db[-10:]


def wait(pred, secs, step=2):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return None


class Modem:
    def __init__(self):
        lst = wait(lambda: mm("-L", True).get("modem-list"), 180)
        self.path = lst[0] if lst else None
        self.idx = self.path.rsplit("/", 1)[1] if self.path else None

    def info(self):
        return mm("-m %s" % self.idx, True).get("modem", {})

    def at(self, cmd):
        m = re.search(r"response: '(.*)'", mm("-m %s --command='%s'" % (self.idx, cmd)), re.S)
        return m.group(1).strip() if m else "no response"

    def usb_vendor(self):
        dev = self.info().get("generic", {}).get("device", "")
        return read(os.path.join(dev, "idVendor")) if dev else ""

    def sms(self, number, text):
        out = mm("-m %s --messaging-create-sms=\"text='%s',number='%s'\"" % (self.idx, text, number))
        m = re.search(r"/SMS/(\d+)", out)
        return bool(m) and "successfully sent" in mm("-s %s --send" % m.group(1)).lower()

    def inbox(self):
        for p in mm("-m %s --messaging-list-sms" % self.idx, True).get("modem.messaging.sms", []):
            s = mm("-s %s" % p.rsplit("/", 1)[1], True).get("sms", {})
            if s.get("properties", {}).get("pdu-type") == "deliver":
                yield s.get("content", {})

    def calls(self):
        out = []
        for p in mm("-m %s --voice-list-calls" % self.idx, True).get("modem.voice.call", []):
            c = mm("-o %s" % p.rsplit("/", 1)[1], True).get("call", {}).get("properties", {})
            out.append((p.rsplit("/", 1)[1], c))
        return out

    def call_state(self, cid):
        return mm("-o %s" % cid, True).get("call", {}).get("properties", {}).get("state", "")


def read(p):
    try:
        with open(p) as f:
            return f.read().strip()
    except OSError:
        return ""


# ---- audio routes ------------------------------------------------------------------------------

def uac_card(vendor):
    for d in glob.glob("/proc/asound/card*/usbid"):
        if read(d).startswith(vendor + ":"):
            return os.path.basename(os.path.dirname(d))[4:]
    return None


def quectel_enable_uac(modem):
    """One-time: set the UAC flag in the USB composition, keeping every other interface as it is."""
    cur = modem.at('+QCFG="usbcfg"')
    m = re.search(r'"usbcfg",([^\s]+)', cur, re.I)
    if not m:
        return "could not read usbcfg: %s" % cur
    f = m.group(1).split(",")
    if len(f) < 9 or f[8] == "1":
        return "usbcfg unchanged: %s" % cur
    f[8] = "1"
    modem.at('+QCFG="usbcfg",%s' % ",".join(f))
    modem.at("+CFUN=1,1")  # modem restarts and re-enumerates with the audio interface
    time.sleep(20)
    return "UAC enabled (was %s)" % cur


def simcom_audio_tty():
    for t in glob.glob("/sys/bus/usb-serial/devices/ttyUSB*"):
        intf = os.path.dirname(os.path.realpath(t))
        if read(intf + "/bInterfaceNumber") == "04" and read(os.path.dirname(intf) + "/idVendor") == "1e0e":
            return "/dev/" + os.path.basename(t)
    return None


def prompt_pcm(text, path):
    sh("espeak-ng -s 140 -w %s.wav '%s' && sox %s.wav -r 8000 -c 1 -b 16 -e signed -t raw %s"
       % (path, text, path, path))
    return read_bytes(path)


def read_bytes(p):
    try:
        with open(p, "rb") as f:
            return f.read()
    except OSError:
        return b""


def converse(route, modem, pcm, secs, rec_path):
    """Play pcm to the far end while recording `secs` of what comes back. Returns recorded PCM."""
    kind, dev = route
    if kind == "uac":
        rec = subprocess.Popen(["arecord", "-q", "-D", "plughw:%s" % dev, "-f", "S16_LE", "-r", "8000",
                                "-c", "1", "-t", "raw", "-d", str(secs), rec_path])
        p = subprocess.Popen(["aplay", "-q", "-D", "plughw:%s" % dev, "-f", "S16_LE", "-r", "8000", "-c", "1",
                              "-t", "raw"], stdin=subprocess.PIPE)
        p.communicate(pcm)
        rec.wait()
        return read_bytes(rec_path)
    if kind == "serial":
        modem.at("+CPCMREG=1")
        sh("stty -F %s raw -echo" % dev)
        fd = os.open(dev, os.O_RDWR | os.O_NOCTTY)
        got = bytearray()

        def writer():
            for i in range(0, len(pcm), 320):  # 20 ms chunks at real-time pace
                os.write(fd, pcm[i:i + 320])
                time.sleep(0.02)
        th = threading.Thread(target=writer, daemon=True)
        th.start()
        end = time.monotonic() + secs
        while time.monotonic() < end:
            got += os.read(fd, 640)
        os.close(fd)
        modem.at("+CPCMREG=0")
        with open(rec_path, "wb") as f:
            f.write(got)
        return bytes(got)
    time.sleep(secs)
    return b""


def call_test(modem, route, cid, private, tag):
    digits = "".join(random.SystemRandom().choice("123456789") for _ in range(4))
    spoken = ". ".join(digits)
    pcm = prompt_pcm("Agent O S test. Your digits are: %s. Again: %s. Now press them on your keypad." %
                     (spoken, spoken), "/run/testkit/prompt.raw")
    got = converse(route, modem, pcm, 40, os.path.join(private, "call-%s.raw" % tag))
    mm("-o %s --hangup" % cid)
    if got:
        sh("sox -t raw -r 8000 -c 1 -b 16 -e signed %s %s" % (os.path.join(private, "call-%s.raw" % tag),
                                                            os.path.join(private, "call-%s.wav" % tag)))
    heard = dtmf.decode_pcm(got) if got else ""
    if not got:
        return "call connected; no audio route for this modem, audio not tested"
    return "%s: sent digits %s, decoded keypad %r, %d s of uplink audio" % (
        "PASS" if digits in heard else "FAIL", digits, heard, len(got) // (2 * RATE))


def run(conf, private):
    os.makedirs(private, exist_ok=True)
    os.makedirs("/run/testkit", exist_ok=True)
    owner = conf["OWNER_NUMBER"]
    res = []
    m = Modem()
    if not m.idx:
        return [("modem", "FAIL: no modem found by ModemManager within 3 minutes")]
    mm("-m %s -e" % m.idx)
    reg = wait(lambda: m.info().get("3gpp", {}).get("registration-state") in ("home", "roaming"), 120)
    g, t = m.info().get("generic", {}), m.info().get("3gpp", {})
    res += [("modem", "%s %s, firmware %s" % (g.get("manufacturer"), g.get("model"), g.get("revision"))),
            ("network", "%s, registered %s, %s, signal %s%%" % (
                t.get("operator-name"), t.get("registration-state"), ",".join(g.get("access-technologies", [])),
                g.get("signal-quality", {}).get("value"))),
            ("ims_registration", m.at("+CIREG?")),  # 3GPP 27.007: VoLTE needs IMS
            ("voice_interface", "yes" if "error" not in mm("-m %s --voice-list-calls" % m.idx).lower() else "no")]
    if not reg:
        return res + [("result", "FAIL: not registered on the network")]

    vendor = m.usb_vendor()
    route = ("none", None)
    if vendor == "2c7c":
        if not uac_card(vendor):
            res.append(("quectel_uac", quectel_enable_uac(m)))
            m = Modem()
            mm("-m %s -e" % m.idx)
            wait(lambda: m.info().get("3gpp", {}).get("registration-state") in ("home", "roaming"), 120)
        card = uac_card(vendor)
        if card:
            route = ("uac", card)
    elif vendor == "1e0e" and simcom_audio_tty():
        route = ("serial", simcom_audio_tty())
    res.append(("audio_route", "%s %s" % route if route[1] else "none known for USB vendor %s" % vendor))

    # SMS out and in
    t0 = time.monotonic()
    res.append(("sms_out", "PASS" if m.sms(owner, "AgentOS S2 test: reply PING to this text within 5 minutes.")
                else "FAIL"))
    seen = {json.dumps(c, sort_keys=True) for c in m.inbox()}
    ping = wait(lambda: next((c for c in m.inbox() if json.dumps(c, sort_keys=True) not in seen
                              and same_number(c.get("number"), owner)), None), 300, 3)
    res.append(("sms_in", "PASS: %r after %.0f s" % (ping.get("text", "")[:20], time.monotonic() - t0) if ping
                else "FAIL: no reply within 5 minutes"))

    # Outgoing call
    m.sms(owner, "Next I will call you. Answer, listen for 4 digits, then press them on your keypad.")
    time.sleep(15)
    if vendor == "2c7c" and route[0] == "uac":
        m.at("+QPCMV=1,2")
    out = mm("-m %s --voice-create-call=\"number=%s\"" % (m.idx, owner))
    cm = re.search(r"/Call/(\d+)", out)
    if cm:
        mm("-o %s --start" % cm.group(1))
        ok = wait(lambda: m.call_state(cm.group(1)) == "active", 60)
        res.append(("call_out", call_test(m, route, cm.group(1), private, "out") if ok
                    else "FAIL: not answered or not connected (%s)" % m.call_state(cm.group(1))))
        mm("-o %s --hangup" % cm.group(1))
    else:
        res.append(("call_out", "FAIL: could not create call: %s" % out[:80]))

    # Incoming call
    m.sms(owner, "Now call this number from your phone within 5 minutes. I will answer and read 4 digits.")
    ring = wait(lambda: next((cid for cid, c in m.calls() if c.get("direction") == "incoming"
                              and c.get("state") == "ringing-in"), None), 300, 1)
    if ring:
        if vendor == "2c7c" and route[0] == "uac":
            m.at("+QPCMV=1,2")
        mm("-o %s --accept" % ring)
        ok = wait(lambda: m.call_state(ring) == "active", 20, 1)
        res.append(("call_in", call_test(m, route, ring, private, "in") if ok else "FAIL: could not answer"))
    else:
        res.append(("call_in", "FAIL: no incoming call within 5 minutes"))

    summary = ", ".join("%s %s" % (k.replace("_", " "), v.split(":")[0].lower()) for k, v in res
                        if k in ("sms_out", "sms_in", "call_out", "call_in"))
    m.sms(owner, ("S2 done: %s. Results are on the drive." % summary)[:160])
    return res
