"""DEV-homekit-b2c (#3894, briefs/DEV-homekit.md "Part (b2), settled"): the HomeKit clerk's unit, user and key
hand-off in the image, against the kernel's unit and the main it runs (broker/cmd/agentos-homekit, HK-host-10).

mkosi.finalize's clerk check (clerk_violations) holds every clerk the kernel hands a key to, this one among them:
its own user, its key from its own socket, and the home network alone unless the check names it a world clerk.
Each test of a refusal is a mutant of the shipped tree that the check must refuse."""
# REQ: CLK-1, NET-2, DEV-8, DEV-2, UPD-10
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import ROOT, check, exec_args, arg, ini  # noqa: E402
import test_image_keeper  # noqa: E402
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
        self.assertEqual(cg, check.keeper_cgroup(HOMEKIT.name))
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
        self.assertEqual(s["IPAddressAllow"].split(), [str(n) for n in check.HOME_NETS])
        self.assertNotIn(HOMEKIT.name, check.WORLD_CLERKS)


class ClerkTreeTest(test_image_keeper.KeeperTreeTest):
    """mkosi.finalize's clerk check on the shipped tree, and on mutants of it. Removing the HomeKit clerk's own
    user, its key hand-off line or its home-only address lines fails the tree check (brief b2c)."""

    UNIT = HOMEKIT.name

    def refused(self, *words):
        v = check.violations(self.root)
        self.assertTrue([l for l in v if all(w in l for w in words)], v)

    def clerk_v(self):
        return [l for l in self.v() if "CLK-1" in l or "NET-2" in l]

    # REQ: CLK-1, NET-2
    def test_the_shipped_clerks_pass(self):
        self.assertEqual(self.clerk_v(), [])
        self.assertEqual(sorted(clerk_keys()), ["camera", "homekit", "mail"])

    # REQ: CLK-1
    def test_without_its_own_user_it_is_refused(self):
        self.edit(self.UNIT, "User=agentos-homekit\n", "")
        self.refused(self.UNIT, "User=", "CLK-1")

    # REQ: CLK-1
    def test_a_root_numeric_or_dynamic_user_is_refused(self):
        for user in ("root", "0", "990"):
            with self.subTest(user=user):
                self.setUp()
                self.edit(self.UNIT, "User=agentos-homekit\n", "User=%s\n" % user)
                self.refused(self.UNIT, "User=%s" % user, "CLK-1")
        self.setUp()
        self.add(self.UNIT, "Service", "DynamicUser=yes")
        self.refused(self.UNIT, "a named user of its own", "CLK-1")

    # REQ: CLK-1
    def test_another_unit_s_user_is_refused(self):
        self.edit(self.UNIT, "User=agentos-homekit\n", "User=agentos-camera\n")
        self.refused(self.UNIT, "also agentos-keeper-camera.service's", "CLK-1")

    # REQ: CLK-1
    def test_without_its_key_hand_off_it_is_refused(self):
        line = "OpenFile=/run/agentos-kernel/key-homekit.sock:clerk-key\n"
        self.edit(self.UNIT, line, "")
        self.refused(self.UNIT, "OpenFile", "CLK-1")
        self.setUp()
        self.edit(self.UNIT, line, "OpenFile=/run/agentos-kernel/key-camera.sock:clerk-key\n")
        self.refused(self.UNIT, "OpenFile", "CLK-1")
        self.setUp()
        self.edit(self.UNIT, line, line + "OpenFile=/run/agentos-homekit/other:extra\n")
        self.refused(self.UNIT, "OpenFile", "CLK-1")

    # REQ: CLK-1
    def test_a_key_entry_off_the_keeper_or_twice_is_refused(self):
        kernel = "agentos-keeper-kernel.service"
        entry = "-clerk-key homekit=/run/agentos-kernel/key-homekit.sock,"
        self.edit(kernel, entry + "/agentos.slice/agentos-keeper.slice/agentos-keeper-homekit.service",
                  entry + "/agentos.slice/agentos-homekit.service")
        self.refused(kernel, "not a keeper unit's cgroup", "CLK-1")
        self.setUp()
        self.edit(kernel, "-clerk-key homekit=/run/agentos-kernel/key-homekit.sock",
                  "-clerk-key homekit=/run/agentos-kernel/key-camera.sock")
        self.refused(kernel, "socket /run/agentos-kernel/key-camera.sock twice", "CLK-1")
        self.setUp()
        (self.root / "usr/lib/systemd/system" / self.UNIT).unlink()
        self.refused(kernel, "does not ship", "CLK-1")

    # REQ: NET-2
    def test_without_its_home_only_address_lines_it_is_refused(self):
        s = HOMEKIT.read_text()
        deny = "IPAddressDeny=any\n"
        allow = next(l for l in s.splitlines(True) if l.startswith("IPAddressAllow="))
        self.edit(self.UNIT, deny, "")
        self.refused(self.UNIT, "IPAddressDeny", "NET-2")
        for wide in ("0.0.0.0/0", "8.8.8.0/24", "::/0", "2001:db8::/32", "localhost", "10.0.0.0/7"):
            with self.subTest(allow=wide):
                self.setUp()
                self.edit(self.UNIT, allow, allow.rstrip("\n") + " " + wide + "\n")
                self.refused(self.UNIT, "IPAddressAllow=" + wide, "NET-2")
        # A drop-in that widens it is read too.
        self.setUp()
        write_dropin = self.root / "etc/systemd/system" / (self.UNIT + ".d") / "50-wide.conf"
        write_dropin.parent.mkdir(parents=True, exist_ok=True)
        write_dropin.write_text("[Service]\nIPAddressDeny=\n")
        self.refused(self.UNIT, "IPAddressDeny", "NET-2")

    # REQ: NET-2
    def test_only_a_named_world_clerk_leaves_the_home_network(self):
        self.assertEqual(check.WORLD_CLERKS, ("agentos-keeper-mail.service",))
        self.assertNotIn("IPAddressDeny", ini(UNITS / "agentos-keeper-mail.service")["Service"])
        # The camera clerk, keyed after the mail clerk, is held to the home network too.
        cam = "agentos-keeper-camera.service"
        self.edit(cam, "IPAddressDeny=any\n", "")
        self.refused(cam, "IPAddressDeny", "NET-2")


# The keeper tree's own tests run once, in test_image_keeper.
for _n in [n for n in vars(test_image_keeper.KeeperTreeTest) if n.startswith("test_")]:
    setattr(ClerkTreeTest, _n, None)


if __name__ == "__main__":
    unittest.main()
