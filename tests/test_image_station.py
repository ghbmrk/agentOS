# The station beside the access point on CI's hwsim boot (#936 r4b-2, brief P2-2w-c3-r4b test 7;
# image/ASSUMPTIONS.md P2-2w-c3-r4b-2-I1). ci_boot.sh boots a fresh copy with mac80211_hwsim's two
# radios and reads the guest's "agentos-hwsim:" lines; these tests hold the script to the brief's
# lifecycle matrix without a boot: every host check is a line the guest can say, no check is a
# prefix of another, the test radio leaves before the loader starts, and the password is a
# synthetic canary that no line prints.
# REQ: ONB-1, ONB-3, DEV-2, CH-9, STO-2, HW-1, HW-4, HW-10
import base64
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI_BOOT = os.path.join(ROOT, "image", "ci_boot.sh")


def script():
    with open(CI_BOOT) as f:
        return f.read()


def guest(name):
    # The body of the heredoc function NAME: the script the guest runs from the 9p share.
    m = re.search(name + r"\(\) \{\n\tcat <<'EOS'\n(.*?)\nEOS\n\}", script(), re.S)
    assert m, name
    return m.group(1) + "\n"


def wants(log):
    # The phrases ci_boot.sh requires as "agentos-hwsim: <phrase>" in LOG's console.
    s = script()
    m = re.search(r'for want in ([^;]*); do\n\thas "\$W/' + re.escape(log) + r'" "agentos-hwsim: \$want"', s)
    assert m, log
    return re.findall(r'"([^"]*)"', m.group(1))


def said(text):
    # Every phrase the guest scripts can print: MSG= values (check's pass line), say lines and
    # the probe's dropped line.
    out = set(re.findall(r'MSG="([^"]*)"', text))
    out |= set(re.findall(r'say "([^"$]*)"', text)) | set(re.findall(r"^\s*say (\w+)$", text, re.M))
    if 'say "probe $port dropped"' in text:
        out |= {"probe %s dropped" % p for p in re.search(r"for port in ([0-9 ]+); do", text).group(1).split()}
    return out


def units():
    # The CI-only units, decoded from their SMBIOS credentials.
    s = script()
    out = {}
    for name, body in re.findall(r'hwsim_cred systemd\.extra-unit\.([a-z-]+\.service) "([^"]*)"', s):
        out[name] = subprocess.run(["sh", "-c", "printf '%b' \"$1\"", "-", body], capture_output=True,
                                   text=True, check=True).stdout
    return out


class HwsimBootTest(unittest.TestCase):
    def test_guest_scripts_parse(self):
        subprocess.run(["sh", "-n"], input=guest("hwsim_setup"), text=True, check=True)
        subprocess.run(["bash", "-n"], input=guest("hwsim_check"), text=True, check=True)

    def test_every_host_check_is_a_line_the_guest_says(self):
        # A typo between the two sides would make a check that can never pass, or one that passes
        # on another line; each phrase is said exactly as the host greps it.
        can = said(guest("hwsim_setup")) | said(guest("hwsim_check"))
        for log in ("console-hwsim.log", "console-hwsim-reboot.log"):
            for w in wants(log):
                self.assertIn(w, can, (log, w))

    def test_no_check_is_a_prefix_of_another(self):
        # grep -F "agentos-hwsim: X" also matches "agentos-hwsim: X and more", so a passing longer
        # line would hide a missing shorter one.
        can = sorted(said(guest("hwsim_setup")) | said(guest("hwsim_check")))
        for a in can:
            for b in can:
                if a != b:
                    self.assertFalse(b.startswith(a), (a, b))

    def test_a_failed_check_never_reads_as_a_pass(self):
        s = script()
        self.assertIn('check() { if "$@"; then say "$MSG"; else say "FAIL $MSG"; fi; }', guest("hwsim_check"))
        self.assertIn('hasnt "$W/console-hwsim.log" "agentos-hwsim: FAIL"', s)
        self.assertIn('hasnt "$W/console-hwsim-reboot.log" "agentos-hwsim: FAIL"', s)
        self.assertNotIn("FAIL", " ".join(said(guest("hwsim_check")) - {"FAIL $MSG"}))

    def test_the_lifecycle_matrix_is_checked(self):
        # Brief P2-2w-c3-r4b, "Lifecycle outcomes": first boot, join, loader restart, helper
        # restart, reboot; the confirm's Down/Up is the loader's own path and a restart covers it.
        first = set(wants("console-hwsim.log"))
        for w in ("wlsta0 exists", "wlsta0 on the box's radio", "one station on the radio",
                  "NetworkManager manages only wlsta0", "the loader logged the station allowed",
                  "station joined", "station has a lease", "DNS resolves over the station",
                  "the box's access point stays up", "wlsta0 survived the loader restart",
                  "after the loader restart, one station on the radio",
                  "the station stayed joined after the loader restart",
                  "after the loader restart, the box's access point serves again",
                  "the helper restart left the station"):
            self.assertIn(w, first)
        reboot = set(wants("console-hwsim-reboot.log"))
        for w in ("wlsta0 exists", "no saved network after the reboot", "wlsta0 not joined after the reboot",
                  "the box's access point serves"):
            self.assertIn(w, reboot)
        s = script()
        self.assertIn('echo reboot >"$HS/mode"\nTMO=600 EXTRA="$HWSIM_EXTRA" boot "$W/console-hwsim-reboot.log" "$W/hwsim.raw"\n', s)
        self.assertIn('if [ "$(cat $S/mode)" = reboot ]; then', guest("hwsim_check"))

    def test_the_station_is_dropped_on_every_port(self):
        # DEV-2, CH-9: from the test network every probed port on the station's address times out;
        # only timeout's 124 reads as dropped, and a positive control shows the link carries TCP.
        c = guest("hwsim_check")
        self.assertIn("for port in 22 80 443 18789 5355; do\n\tns timeout 4 bash -c \"exec 3<>/dev/tcp/$addr/$port\"", c)
        self.assertIn('if [ $rc = 124 ]; then say "probe $port dropped"; else say "FAIL probe $port answered (rc=$rc)"; fi', c)
        self.assertIn("station reaches the test network", wants("console-hwsim.log"))
        self.assertIn("wlsta0 not exempt from the inbound drop", wants("console-hwsim.log"))
        self.assertIn('has "$W/console-hwsim.log" "agentos-health: PASS secure_boot=on usr=verity inbound=drop swap=off dumps=off forward=off"', script())

    def test_the_test_radio_leaves_before_the_loader_starts(self):
        # The loader takes every radio it sees (image/ASSUMPTIONS.md I16), so the second radio is in
        # its own namespace first; the check runs after the loader and before the boot report.
        setup = guest("hwsim_setup")
        self.assertIn("modprobe mac80211_hwsim radios=2", setup)
        self.assertIn('iw phy "$phy" set netns name hwsimap', setup)
        u = units()
        self.assertIn("Before=agentos-ap.service", u["agentos-hwsim-setup.service"])
        check = u["agentos-hwsim-check.service"]
        self.assertIn("Requires=agentos-hwsim-setup.service", check)
        self.assertRegex(check, r"After=[^\n]*agentos-ap\.service")
        self.assertRegex(check, r"Before=[^\n]*agentos-boot-report\.service")
        self.assertIn("ExecStart=/bin/bash /run/agentos-hwsim/share/check.sh", check)
        self.assertIn("mount -t 9p -o trans=virtio,version=9p2000.L,ro hwsim", u["agentos-hwsim-setup.service"])
        self.assertIn("readonly=on", re.search(r'HWSIM_EXTRA="([^"]*)"', script()).group(1))

    def test_the_password_is_a_synthetic_canary_no_line_prints(self):
        # STO-2, HW-10: the canary rides in a share file, never on a unit's command line, and no
        # say line, console or file on the drive may carry it.
        s = script()
        psk = re.search(r"^HWSIM_PSK=(\S+)$", s, re.M).group(1)
        self.assertTrue(psk.startswith("agentos-ci-canary-"), psk)
        c = guest("hwsim_check")
        self.assertIn("PSK=$(cat $S/psk)", c)
        for line in c.splitlines():
            if re.search(r"\bsay\b", line):
                self.assertNotIn("$PSK", line, line)
        for body in units().values():
            self.assertNotIn(psk, body)
        self.assertIn('hasnt "$W/console-hwsim.log" "$HWSIM_PSK"', s)
        for w in ("the PSK is in no journal line", "the PSK is in no file on the drive"):
            self.assertIn(w, wants("console-hwsim.log"))
        self.assertIn("the PSK is in no file on the drive", wants("console-hwsim-reboot.log"))
        self.assertIn("grep -rlsF \"$PSK\" /etc /var /root /home /srv /opt /usr/local", c)

    def test_the_join_is_in_memory_and_ci_only(self):
        # No join is enabled before the sealed store (NM-1): CI's join is an unsaved connection made
        # by root, and the image's helper is not changed or used.
        c = guest("hwsim_check")
        self.assertIn("nmcli connection add save no type wifi ifname wlsta0", c)
        self.assertNotIn("netjoin.sock", c)
        self.assertNotIn("-station", script())

    def test_the_single_channel_join_is_reported_not_checked(self):
        # #2629: the off-channel join's outcome is the open question, so it is a NOTE line.
        c = guest("hwsim_check")
        self.assertIn('say "NOTE single-channel join on channel $off beside the access point on $box: $r;', c)
        self.assertIn('grep -a "agentos-hwsim: NOTE" "$W/console-hwsim.log" | guest_echo', script())
        for w in wants("console-hwsim.log"):
            self.assertFalse(w.startswith("NOTE"), w)

    def restarts(self, ap_rc=0, fresh=1, nj_rc=0):
        # The guest's restart section, run with stubbed systemctl and loader log: the box's
        # access point and station still look up from before the restart (the old state), so
        # only the restart's own result and a fresh "serving the" line tell a good restart.
        c = guest("hwsim_check")
        pre = c[:c.index('MSG="wlsta0 exists"')]
        sec = c[c.index("# Loader restart:"):c.index("nopsk\n", c.index("# Loader restart:"))]
        stubs = """
SERVED=3
sleep() { :; }
cat() { echo 7; }
logged() { echo "$SERVED"; }
ap_up() { :; }
joined() { :; }
radio_ifs() { echo 2; }
systemctl() {
	case "$1 $2" in
	"restart agentos-ap.service") [ %d = 1 ] && SERVED=$((SERVED + 1)); return %d ;;
	"restart agentos-netjoin.service") return %d ;;
	esac
}
""" % (fresh, ap_rc, nj_rc)
        out = subprocess.run(["bash"], input=pre + stubs + sec, capture_output=True, text=True).stdout
        return [l[len("agentos-hwsim: "):] for l in out.splitlines()]

    def test_a_failed_restart_never_reads_as_a_pass(self):
        # The checks after a restart pass on the old state, so a rejected loader restart, a
        # loader that never logs serving again, or a rejected helper restart must each FAIL.
        good = self.restarts()
        self.assertEqual([l for l in good if l.startswith("FAIL")], [])
        for w in ("the loader restart succeeded", "the restarted loader logged serving",
                  "after the loader restart, the box's access point serves again",
                  "the helper restart succeeded", "the helper restart left the station"):
            self.assertIn(w, good)
            self.assertIn(w, wants("console-hwsim.log"))
        for kw, want in ((dict(ap_rc=1, fresh=0), "FAIL the loader restart succeeded"),
                         (dict(fresh=0), "FAIL the restarted loader logged serving"),
                         (dict(nj_rc=1), "FAIL the helper restart succeeded")):
            self.assertIn(want, self.restarts(**kw), kw)

    def test_assumptions_record_the_hwsim_boot(self):
        with open(os.path.join(ROOT, "image", "ASSUMPTIONS.md")) as f:
            a = f.read()
        row = [l for l in a.splitlines() if l.startswith("| P2-2w-c3-r4b-2-I1 |")]
        self.assertEqual(len(row), 1)
        for w in ("mac80211_hwsim", "wlsta0", "save no", "#2629", "#935"):
            self.assertIn(w, row[0])


if __name__ == "__main__":
    unittest.main()
