"""S2: does a USB LTE modem do SMS and voice under Linux? Driven over ModemManager (mmcli).

The owner's phone is the only interface: the box texts instructions, the owner replies, answers a
call, presses the digits they hear, then calls the box. Downlink audio is checked by the owner
hearing the digits, uplink audio by decoding the keypad tones (dtmf.py).

Audio routes are vendor specific and UNTESTED until real hardware (from the vendors' AT manuals):
  Quectel (USB 2c7c): USB Audio Class, enabled once with AT+QCFG="usbcfg" (UAC flag), then AT+QPCMV=1,2.
  SIMCom (USB 1e0e): AT+CPCMREG=1 streams 8 kHz 16-bit PCM over the modem's audio serial port.
Results never include IMEI, ICCID, IMSI, or phone numbers. Call recordings go to private/ only.

It also takes the readings broker/modem/at/S2-CONFIRM.md lists for the Go driver (C3, C7, C9, C11 to C15,
and the speech part of C10), so S2 runs once: the owner inserts the SIM, sends one text and takes the calls."""
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


def shape(text):
    """An AT answer with identifiers blanked, for results/: digit runs of 6 or more (ICCID, IMSI) and
    quoted hex (CEREG's area and cell) become their length, so the form stays readable (C13)."""
    text = re.sub(r'"[0-9A-Fa-f]{2,}"', lambda m: '"<%d hex>"' % (len(m.group(0)) - 2), text or "")
    return re.sub(r"\d{6,}", lambda m: "<%d digits>" % len(m.group(0)), text)


def number_form(number):
    """How the carrier wrote a number, never the number itself (C12)."""
    n = (number or "").strip()
    digits = re.sub(r"\D", "", n)
    if not digits:
        return "none"
    if n.startswith("+"):
        form = "international (+)"
    elif digits.startswith("00"):
        form = "international (00)"
    elif digits.startswith("0"):
        form = "trunk prefix 0"
    else:
        form = "no prefix"
    return "%s, %d digits" % (form, len(digits))


URC_KEY = re.compile(r"\+QTONEDET:\s*(\d+)|\+RXDTMF:\s*([0-9A-D*#])")


def urc_keys(log):
    """Keys from the modems' own DTMF reports in ModemManager's debug log (C7):
    Quectel +QTONEDET: <ASCII code>, SIMCom +RXDTMF: <key>."""
    return "".join(chr(int(a)) if a else b for a, b in URC_KEY.findall(log or "")
                   if b or 32 < int(a) < 127)


def extra_keys(heard, digits):
    """Keys decoded beyond the one expected run of digits: the owner's speech decoded as keys (C10)."""
    return len(heard.replace(digits, "", 1)) if digits in heard else len(heard)


def port_interfaces(ports, interface_of):
    """ModemManager's ports ("ttyUSB2 (at)") with their USB interface numbers (C3)."""
    out = []
    for p in ports or []:
        m = re.match(r"(\S+) \((\w+)\)", p)
        if m and m.group(1).startswith("tty"):
            out.append("%s %s if%s" % (m.group(2), m.group(1), interface_of(m.group(1)) or "?"))
    return ", ".join(out) or "none listed"


def tty_interface(name):
    dev = "/sys/class/tty/%s/device" % name  # ttyACM: the interface itself; ttyUSB: a port under it
    return read(dev + "/bInterfaceNumber") or read(dev + "/../bInterfaceNumber")


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
    old = m.group(1)
    modem.at('+QCFG="usbcfg",%s' % ",".join(f))
    t0 = time.monotonic()
    modem.at("+CFUN=1,1")  # modem restarts and re-enumerates with the audio interface
    wait(lambda: not mm("-L", True).get("modem-list"), 30, 1)
    back = wait(lambda: mm("-L", True).get("modem-list"), 180, 1)
    return ('UAC enabled; this setting persists in the modem. To restore: AT+QCFG="usbcfg",%s. '
            "Restart (C11): %s" % (old, "listed by ModemManager again after %.0f s" % (time.monotonic() - t0) if back
                                   else "not listed again within 210 s"))


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
    pcm = prompt_pcm("Agent O S test. Your digits are: %s. Again: %s. Now press them on your keypad, "
                     "then count aloud from one to ten." % (spoken, spoken), "/run/testkit/prompt.raw")
    since = time.time()
    got = converse(route, modem, pcm, 50, os.path.join(private, "call-%s.raw" % tag))
    mm("-o %s --hangup" % cid)
    if got:
        sh("sox -t raw -r 8000 -c 1 -b 16 -e signed %s %s" % (os.path.join(private, "call-%s.raw" % tag),
                                                            os.path.join(private, "call-%s.wav" % tag)))
    heard = dtmf.decode_pcm(got) if got else ""
    if not got:
        return "call connected; no audio route for this modem, audio not tested; modem DTMF reports %r (C7)" % (
            urc_keys(sh("journalctl -b -o cat -u ModemManager --since=@%d" % since, 30)))
    reports = urc_keys(sh("journalctl -b -o cat -u ModemManager --since=@%d" % since, 30))
    return ("%s: sent digits %s, decoded keypad %r, %d s of uplink audio; speech decoded as %d extra keys (C10); "
            "modem DTMF reports %s (C7)" % (
                "PASS" if digits in heard else "FAIL", digits, heard, len(got) // (2 * RATE),
                extra_keys(heard, digits), repr(reports) if reports else "none in ModemManager's log"))


def readings(m, vendor):
    """One-shot AT readings for S2-CONFIRM.md, identifiers blanked by shape()."""
    quectel = vendor == "2c7c"
    out = [("ports", port_interfaces(m.info().get("generic", {}).get("ports"), tty_interface)),  # C3
           ("sim_serial_form", shape(m.at("+QCCID" if quectel else "+CICCID"))),  # C13
           ("status_forms", shape(" | ".join(m.at(c) for c in ("+CPIN?", "+CEREG?", "+CSQ")))),  # C13
           ("sms_storage", shape(m.at("+CPMS=?") + " | " + m.at("+CPMS?")))]  # C9
    if quectel:  # C15
        out.append(("network_time", shape(m.at("+QLTS=1") + " | " + m.at("+QLTS=2"))))
    else:  # C14
        out.append(("network_time", m.at("+CCLK?")))
    m.at("+QTONEDET=1" if quectel else "+DDET=1")  # C7: the modem's own DTMF reports, read after each call
    return out


def long_text(m):
    """C9: a 200-character text to the box's own number arrives whole. Content is synthetic, never logged."""
    own = next(iter(m.info().get("generic", {}).get("own-numbers") or []), "")
    if not own:
        return "not tested: the SIM does not report its own number"
    body = ("agentOS S2 long text check " * 8)[:200]
    seen = {json.dumps(c, sort_keys=True) for c in m.inbox()}
    if not m.sms(own, body):
        return "FAIL: could not send to the box's own number"
    got = wait(lambda: next((c for c in m.inbox() if json.dumps(c, sort_keys=True) not in seen
                             and same_number(c.get("number"), own)), None), 180, 3)
    if not got:
        return "FAIL: no text back from the box's own number within 3 minutes"
    return "PASS: arrived whole" if (got.get("text") or "") == body else (
        "FAIL: arrived as %d characters, not 200 (split or cut)" % len(got.get("text") or ""))


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
    res += readings(m, vendor)

    # SMS out and in
    t0 = time.monotonic()
    res.append(("sms_out", "PASS" if m.sms(owner, "agentOS S2 test: reply PING to this text within 5 minutes.")
                else "FAIL"))
    seen = {json.dumps(c, sort_keys=True) for c in m.inbox()}
    ping = wait(lambda: next((c for c in m.inbox() if json.dumps(c, sort_keys=True) not in seen
                              and same_number(c.get("number"), owner)), None), 300, 3)
    # Never log message content: results/ is the folder the owner uploads.
    res.append(("sms_in", "PASS (%s) after %.0f s" % (
        "PING received" if (ping.get("text") or "").strip().upper() == "PING" else "other text",
        time.monotonic() - t0) if ping else "FAIL: no reply from the owner's number within 5 minutes"))
    if ping:
        res.append(("sms_sender_form", number_form(ping.get("number"))))  # C12
    res.append(("sms_long_in", long_text(m)))  # C9

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
    # Answer only the owner: any other caller is left ringing and never recorded.
    ring = wait(lambda: next((cid for cid, c in m.calls() if c.get("direction") == "incoming"
                              and c.get("state") == "ringing-in" and same_number(c.get("number"), owner)),
                             None), 300, 1)
    if ring:
        res.append(("caller_form", number_form(next((c.get("number") for cid, c in m.calls() if cid == ring), ""))))
        if vendor == "2c7c" and route[0] == "uac":
            m.at("+QPCMV=1,2")
        mm("-o %s --accept" % ring)
        ok = wait(lambda: m.call_state(ring) == "active", 20, 1)
        res.append(("call_in", call_test(m, route, ring, private, "in") if ok else "FAIL: could not answer"))
    else:
        res.append(("call_in", "FAIL: no call from the owner's number within 5 minutes (caller ID hidden?)"))

    summary = ", ".join("%s %s" % (k.replace("_", " "), v.split(":")[0].lower()) for k, v in res
                        if k in ("sms_out", "sms_in", "call_out", "call_in"))
    m.sms(owner, ("S2 done: %s. Results are on the drive." % summary)[:160])
    return res
