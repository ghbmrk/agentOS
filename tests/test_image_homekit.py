"""DEV-homekit-b2c (#3894, briefs/DEV-homekit.md "Part (b2), settled"): the HomeKit clerk's unit, user and key
hand-off in the image, against the kernel's unit and the main it runs (broker/cmd/agentos-homekit, HK-host-10).

Static assertions on the shipped unit, as CAM-clerk-image (#4058) has for the camera clerk: its own user, its key
from its own socket on descriptor 3, no other socket the manager hands it, and the home network alone. The kernel
tying each key entry to its own keeper unit is a kernel-lane row, not a parse of the kernel's command line here."""
# REQ: CLK-1, NET-2, DEV-8, DEV-2, UPD-10
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import ROOT, check, exec_args, arg, ini  # noqa: E402
from test_image_keeper import (KERNEL, PRESET, SYSUSERS, TMPFILES, UNITS, exec_lines, go_flags,  # noqa: E402
                               slice_cgroup)

HOMEKIT = UNITS / "agentos-keeper-homekit.service"
CMD = ROOT / "broker/cmd/agentos-homekit"
DEVICES = ROOT / "broker/cmd/agentos-devices/agentos-devices.service"


def clerk_keys():
    k = exec_args(KERNEL)
    kern = k[k.index("--") + 1:]
    out = {}
    for i, w in enumerate(kern):
        if w == "-clerk-key":
            name, sock_cg = kern[i + 1].split("=", 1)
            out[name] = tuple(sock_cg.split(","))
    return out


class HomeKitClerkUnitTest(unittest.TestCase):

    def setUp(self):
        self.h = exec_args(HOMEKIT)
        self.svc = ini(HOMEKIT)["Service"]

    # REQ: CLK-1
    def test_the_clerk_runs_its_main_under_its_own_user(self):
        h = self.h
        self.assertEqual(h[0], "/usr/lib/agentos/agentos-homekit")
        flags = [w[1:] for w in h[1:] if w.startswith("-")]
        self.assertEqual(sorted(flags), sorted(go_flags("agentos-homekit")))
        self.assertEqual((self.svc["User"], self.svc["Group"]), ("agentos-homekit", "agentos-homekit"))
        users = [l.split()[1] for l in SYSUSERS.read_text().splitlines() if l.startswith("u ")]
        self.assertIn("agentos-homekit", users)
        # The owner side is agentosd, root (HK-host-1); no other peer.
        self.assertEqual(arg(h, "owner-uid"), "0")
        self.assertRegex((ROOT / "image/build.sh").read_text(), r"(?s)for cmd in agentosd [^;]*\bagentos-homekit\b[^;]*; do")

    # REQ: CLK-1
    def test_the_kernel_hands_the_key_to_this_unit_alone(self):
        keys = clerk_keys()
        sock, cg = keys["homekit"]
        drop = ini(UNITS / "agentos-keeper-.service.d/90-keeper.conf")["Service"]
        self.assertEqual(cg, slice_cgroup(drop["Slice"], HOMEKIT.name))
        self.assertIn(HOMEKIT.name, check.KEEPER_UNITS)
        self.assertNotIn("Slice", self.svc)
        self.assertEqual(len({s for s, _ in keys.values()}), len(keys))
        self.assertEqual(exec_lines(HOMEKIT, "OpenFile"), [sock + ":clerk-key"])
        for key in ("Sockets", "FileDescriptorStoreMax", "StandardInput", "StandardOutput", "DelegateSubgroup"):
            self.assertNotIn(key, self.svc)
        self.assertEqual([k for k in check.EXEC_KEYS if k in self.svc], ["ExecStart"])
        self.assertIn('clerkName = "homekit"', (CMD / "main.go").read_text())

    # REQ: CLK-1, STO-2, UPD-10
    def test_the_clerk_s_lifecycle(self):
        u = ini(HOMEKIT)["Unit"]
        k = exec_args(KERNEL)
        self.assertIn("agentos-keeper-kernel.service", u["After"].split())
        self.assertIn("systemd-tmpfiles-setup.service", u["After"].split())
        self.assertEqual(exec_lines(HOMEKIT, "ConditionPathExists"), [arg(k[1:k.index("--")], "store")])
        self.assertEqual(ini(HOMEKIT)["Install"]["WantedBy"], "multi-user.target")
        self.assertIn("enable %s" % HOMEKIT.name, PRESET.read_text().splitlines())
        self.assertEqual((self.svc["Restart"], self.svc["RestartSec"], self.svc["RestartSteps"],
                          self.svc["RestartMaxDelaySec"]), ("on-failure", "2", "8", "5min"))
        self.assertEqual(u["StartLimitIntervalSec"], "0")
        # The sealed store and homekit.json: keeper state, made at every boot, the clerk's user's alone, and
        # hidden from every main-side unit.
        state = arg(self.h, "dir")
        self.assertIn(state, check.KEEPER_PATHS)
        self.assertIn(state[1:], check.SERVICE_DIRS)
        made = {w[1]: w for w in (l.split() for l in TMPFILES.read_text().splitlines()) if w and w[0] == "d"}
        self.assertEqual(made[state], ["d", state, "0700", "agentos-homekit", "agentos-homekit", "-"])
        self.assertEqual(self.svc["ReadWritePaths"], state)
        main_side = ini(UNITS / "agentos-.service.d/50-main-side.conf")["Service"]["InaccessiblePaths"].split()
        self.assertIn(state, main_side)
        # The owner socket: the clerk's runtime directory, which the main side may reach.
        run = "/run/" + self.svc["RuntimeDirectory"]
        self.assertEqual(arg(self.h, "owner-sock").rsplit("/", 1)[0], run)
        self.assertEqual(self.svc["RuntimeDirectoryMode"], "0755")
        self.assertFalse(check.keeper_reach(run))
        self.assertIn(run[1:], check.SERVICE_DIRS)
        for key in ("StateDirectory", "RuntimeDirectoryPreserve", "DynamicUser", "Environment", "EnvironmentFile"):
            self.assertNotIn(key, self.svc)

    # REQ: CLK-1, NET-2, DEV-2, DEV-8, UPD-10
    def test_the_hardening_set_of_the_devices_host(self):
        s, d = ini(HOMEKIT)["Service"], ini(DEVICES)["Service"]
        # Every sandbox setting of agentos-devices.service, as it sets it, but its own user, command and
        # restart, and its syscall filter, which the clerk's tightens (below).
        own = {"User", "Group", "ExecStart", "Restart", "RestartSec", "SystemCallFilter"}
        for k, v in d.items():
            if k not in own:
                self.assertEqual(s.get(k), v, k)
        self.assertEqual(exec_lines(HOMEKIT, "SystemCallFilter"), ["@system-service", "~@debug @mount @privileged @resources"])
        self.assertEqual(s["SystemCallErrorNumber"], "EPERM")
        self.assertEqual(s["DevicePolicy"], "closed")
        self.assertNotIn("DeviceAllow", s)
        self.assertNotIn(HOMEKIT.name, check.TPM_UNITS)
        # HAP over IP to listed accessories, on the home network alone (NET-2): no netlink, no other family.
        self.assertEqual(s["RestrictAddressFamilies"].split(), ["AF_UNIX", "AF_INET", "AF_INET6"])
        self.assertEqual(s["IPAddressDeny"], "any")
        self.assertEqual(s["IPAddressAllow"].split(), ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                       "100.64.0.0/10", "169.254.0.0/16", "fc00::/7", "fe80::/10"])

    # REQ: CLK-1, NET-2
    def test_no_socket_the_manager_opens_reaches_the_clerk(self):
        # IPAddressAllow= filters the clerk's own sockets; one the manager opens and passes (Sockets=, a .socket
        # unit naming or matching it) would not be the clerk's to have, so the image ships none.
        self.assertNotIn("Sockets", self.svc)
        stem = HOMEKIT.name[:-len(".service")]
        for unit in sorted(UNITS.glob("*.socket")):
            u = ini(unit)
            sock = u["Socket"] if u.has_section("Socket") else {}
            self.assertNotEqual(unit.stem, stem, unit.name)
            self.assertNotIn(HOMEKIT.name, sock.get("Service", "").split(), unit.name)
