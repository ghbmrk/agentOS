#!/usr/bin/env python3
"""REQ: NET-2. Tests for ci_wan.sh, ci_boot.sh's check of the WAN's router-advertisement handling (#5189, #5330).

The probe runs against a fake /sys and /proc (its R prefix), with systemctl and sleep stood in on
PATH; the verdict runs on console logs holding the probe's line."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
WAN = str(HERE / "ci_wan.sh")
# systemctl show -P ExecStart for the placeholder unit, as systemd prints it.
SLEEP = ("{ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep infinity ; ignore_errors=no ; start_time=[n/a] ; "
         "stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }")
DAEMON = ("{ path=/usr/bin/agentos-enforcer ; argv[]=/usr/bin/agentos-enforcer ; ignore_errors=no ; "
          "start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }")
ROUTE = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000400 00000001 00000000 00000003     ens3\n"


class Probe(unittest.TestCase):
    """The guest half: what it reads and how it names the daemon unit."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.tool("sleep", "exit 0")
        self.card("bond0", device=False, operstate="up", accept_ra="2")  # no device: not a card
        self.card("ens3")
        self.put("proc/net/ipv6_route", "")

    def put(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def tool(self, name, body):
        p = self.bin / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(0o755)

    def card(self, name, device=True, operstate="down", accept_ra="0"):
        if device:
            self.put("sys/class/net/%s/device/uevent" % name, "")
        self.put("sys/class/net/%s/operstate" % name, operstate + "\n")
        self.put("proc/sys/net/ipv6/conf/%s/accept_ra" % name, accept_ra + "\n")
        self.put("proc/sys/net/ipv6/conf/%s/forwarding" % name, "1\n")

    def execstart(self, text, status=0):
        self.put("execstart", text)
        self.tool("systemctl", '[ "$*" = "show -P ExecStart agentos-enforcer.service" ] || exit 9\n'
                  'cat "%s"\nexit %d' % (self.root / "execstart", status))

    def probe(self):
        env = dict(os.environ, R=str(self.root), PATH="%s:%s" % (self.bin, os.environ["PATH"]))
        out = subprocess.run(["sh", WAN, "probe"], env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout.strip()

    def test_placeholder_unit(self):
        self.execstart(SLEEP + "\n")
        self.assertEqual(self.probe(), "enforcer-ci: wan=ens3 operstate=down accept_ra=0 forwarding=1 "
                         "ipv6_default=no daemon=placeholder")

    def test_real_execstart_is_real(self):
        # #5330 item 1: ENF-m-b swaps only ExecStart (or adds a drop-in) and the Description still
        # says placeholder. The probe reads the effective ExecStart, never the Description.
        self.put("usr/lib/systemd/system/agentos-enforcer.service",
                 "[Unit]\nDescription=agentOS enforcer (placeholder until ENF-m-b)\n")
        self.execstart(DAEMON + "\n")
        self.assertTrue(self.probe().endswith(" operstate=down accept_ra=0 forwarding=1 ipv6_default=no daemon=real"))

    def test_only_the_lone_sleep_is_the_placeholder(self):
        for text, status in ((SLEEP + "\n" + DAEMON + "\n", 0),  # a second command added by a drop-in
                             (DAEMON + "\n" + SLEEP + "\n", 0),
                             (SLEEP.replace("infinity ;", "infinity 1 ;") + "\n", 0),
                             (SLEEP.replace("argv[]=/usr/bin/sleep", "argv[]=sleep") + "\n", 0),
                             ("", 0),
                             (SLEEP + "\n", 1)):  # systemctl failed
            with self.subTest(text=text, status=status):
                self.execstart(text, status)
                self.assertTrue(self.probe().endswith(" daemon=real"))

    def test_router_advertisements_read(self):
        self.execstart(DAEMON + "\n")
        self.card("ens3", operstate="up", accept_ra="2")
        self.assertEqual(self.probe(), "enforcer-ci: wan=ens3 operstate=up accept_ra=2 forwarding=1 "
                         "ipv6_default=no daemon=real")
        self.card("ens3", operstate="up")
        self.put("proc/net/ipv6_route", ROUTE)
        self.assertEqual(self.probe(), "enforcer-ci: wan=ens3 operstate=up accept_ra=0 forwarding=1 "
                         "ipv6_default=yes daemon=real")


class Verdict(unittest.TestCase):
    """The host half: which probe lines pass and what a miss says."""

    def verdict(self, line):
        with tempfile.NamedTemporaryFile("w", suffix=".log") as log:
            log.write("[  OK  ] Started something.\r\n" + (line + "\r\n" if line else ""))
            log.flush()
            out = subprocess.run(["sh", WAN, "verdict", log.name], capture_output=True, text=True, timeout=30)
        return out.returncode, out.stdout.strip()

    def line(self, operstate="up", ra="0", route="no", daemon="real", wan="ens3"):
        return ("enforcer-ci: wan=%s operstate=%s accept_ra=%s forwarding=1 ipv6_default=%s daemon=%s"
                % (wan, operstate, ra, route, daemon))

    def test_handled(self):
        for kw in (dict(ra="2"), dict(route="yes"), dict(ra="2", daemon="placeholder"), dict(operstate="down", ra="2")):
            with self.subTest(**kw):
                rc, out = self.verdict(self.line(**kw))
                self.assertEqual(rc, 0)
                self.assertTrue(out.startswith("ok   WAN router advertisements handled ("), out)

    def test_placeholder_down_passes(self):
        for state in ("down", "unknown"):
            with self.subTest(state=state):
                self.assertEqual(self.verdict(self.line(operstate=state, daemon="placeholder")),
                                 (0, "ok   no WAN link configured until ENF-m-b (%s)" % self.line(
                                     operstate=state, daemon="placeholder")[len("enforcer-ci: "):]))

    def test_misses(self):
        m = "MISS WAN router advertisements handled: "
        for kw, said in ((dict(), "accept_ra=2 or an IPv6 default route"),
                         (dict(daemon="placeholder"), "accept_ra=2 or an IPv6 default route"),
                         (dict(operstate="down"), "the WAN is down"),
                         # #5330 item 3: unknown is not down.
                         (dict(operstate="unknown"), "the WAN's link state is unknown"),
                         (dict(operstate="lowerlayerdown"), "the WAN's link is not up")):
            with self.subTest(**kw):
                line = self.line(**kw)
                self.assertEqual(self.verdict(line), (1, "%s%s (%s)" % (m, said, line[len("enforcer-ci: "):])))

    def test_no_probe_line(self):
        self.assertEqual(self.verdict(""), (1, "MISS the WAN probe's line on a network card ()"))
        line = self.line(wan="none", daemon="placeholder", operstate="")
        rc, out = self.verdict(line)
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("MISS the WAN probe's line on a network card (wan=none "), out)


if __name__ == "__main__":
    unittest.main()
