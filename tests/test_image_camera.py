"""CAM-clerk-image (#3867): the camera clerk's unit, user, key hand-off and decoder sandbox paths in the image,
against the kernel's unit and the main they run (broker/cmd/agentos-camera, CAM-host-9, CAM-host-11).

CI's camera unit step runs the clerk's decoder start inside this same unit file on a systemd host, with only
ExecStart= and the key's OpenFile= replaced (broker/cmd/agentos-camera TestDecoderStartsInTheUnitsSandbox)."""
# REQ: CLK-1, NET-2, DEV-2, RES-2, UPD-10
import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, ROOT, check, exec_args, arg, ini  # noqa: E402
from test_image_keeper import (KERNEL, PRESET, SYSUSERS, TMPFILES, UNITS, exec_lines, go_flags,  # noqa: E402
                               slice_cgroup)

CAMERA = UNITS / "agentos-keeper-camera.service"
CMD = ROOT / "broker/cmd/agentos-camera"
CI = ROOT / ".github/workflows/ci.yml"


def go_const(path, name):
    """The integer constant NAME in Go file PATH: a literal, or a literal shifted left by one."""
    m = re.search(r"(?m)^\s*(?:const\s+)?%s\s*=\s*(\d+)(?:\s*<<\s*(\d+))?\s*(?://.*)?$" % name, (ROOT / path).read_text())
    if not m:
        raise AssertionError("no constant %s in %s" % (name, path))
    return int(m.group(1)) << int(m.group(2) or 0)


class CameraClerkUnitTest(unittest.TestCase):

    def setUp(self):
        self.c, k = exec_args(CAMERA), exec_args(KERNEL)
        i = k.index("--")
        self.unlock, self.kern = k[1:i], k[i + 1:]
        self.svc = ini(CAMERA)["Service"]

    def clerk_keys(self):
        out = {}
        for i, w in enumerate(self.kern):
            if w == "-clerk-key":
                name, sock_cg = self.kern[i + 1].split("=", 1)
                out[name] = tuple(sock_cg.split(","))
        return out

    # REQ: CLK-1
    def test_the_clerk_runs_its_main_under_its_own_user(self):
        c = self.c
        self.assertEqual(c[0], "/usr/lib/agentos/agentos-camera")
        flags = [w[1:] for w in c[1:] if w.startswith("-")]
        self.assertEqual(sorted(flags), sorted(go_flags("agentos-camera")))
        self.assertEqual((self.svc["User"], self.svc["Group"]), ("agentos-camera", "agentos-camera"))
        users = [l.split()[1] for l in SYSUSERS.read_text().splitlines() if l.startswith("u ")]
        self.assertIn("agentos-camera", users)
        # The owner side is agentosd, root (CAM-host-1); no other peer, and no kernel socket yet (CAM-host-6).
        self.assertEqual(arg(c, "owner-uid"), "0")
        self.assertNotIn("camera", [w.split("=", 1)[0] for w in self.kern[1:] if "=" in w and
                                    self.kern[self.kern.index(w) - 1] == "-clerk"])

    # REQ: CLK-1
    def test_the_kernel_hands_the_key_to_this_unit_alone(self):
        keys = self.clerk_keys()
        self.assertEqual(sorted(keys), ["camera", "mail"])
        sock, cg = keys["camera"]
        drop = ini(UNITS / "agentos-keeper-.service.d/90-keeper.conf")["Service"]
        self.assertEqual(cg, slice_cgroup(drop["Slice"], CAMERA.name))
        self.assertNotIn("Slice", self.svc)
        self.assertIn(CAMERA.name, check.KEEPER_UNITS)
        # Each clerk's own socket, in the kernel's directory.
        self.assertNotEqual(sock, keys["mail"][0])
        self.assertEqual(sock.rsplit("/", 1)[0], arg(self.kern, "owner-sock").rsplit("/", 1)[0])
        # The manager connects at each start; the clerk gets the connection as descriptor 3, its only one.
        self.assertEqual(exec_lines(CAMERA, "OpenFile"), [sock + ":clerk-key"])
        for key in ("Sockets", "FileDescriptorStoreMax", "StandardInput", "StandardOutput"):
            self.assertNotIn(key, self.svc)
        self.assertEqual([k for k in check.EXEC_KEYS if k in self.svc], ["ExecStart"])
        self.assertIn('clerkName = "camera"', (CMD / "main.go").read_text())
        # The kernel matches the peer's whole cgroup, so no process of the unit may sit in a subgroup when
        # the manager connects: no DelegateSubgroup= (the clerk moves itself once it holds its key).
        self.assertNotIn("DelegateSubgroup", self.svc)

    # REQ: RES-2, NET-2
    def test_the_decoders_group_is_the_units_own(self):
        _, cg = self.clerk_keys()["camera"]
        self.assertEqual(arg(self.c, "cgroup"), "/sys/fs/cgroup" + cg)
        # Delegated exactly the controllers the sandboxes' groups take (broker/cgroup Controllers).
        src = (ROOT / "broker/cgroup/cgroup.go").read_text()
        want = re.search(r'var Controllers = \[\]string\{([^}]*)\}', src).group(1)
        self.assertEqual(self.svc["Delegate"].split(), re.findall(r'"([a-z]+)"', want))
        self.assertIn('const leaf = "clerk"', (CMD / "main.go").read_text())
        self.assertIn("Rootless: true", (CMD / "main.go").read_text())
        # The unit's caps hold every admitted camera's decoder at its own cap, and the clerk above them.
        cams = go_const("broker/cmd/agentos-camera/host.go", "maxCameras")
        mem = go_const("broker/clerk/camera/decode.go", "DefaultDecodeMem")
        pids = go_const("broker/vm/gvisor/runonce.go", "oneShotPids")
        self.assertEqual(self.svc["MemoryMax"], "5G")
        self.assertEqual(5 << 30, cams * mem + (1 << 30))
        self.assertEqual(int(self.svc["TasksMax"]), cams * pids + 64)

    # REQ: NET-2, UPD-10
    def test_the_decoder_paths_are_the_images(self):
        build = (ROOT / "image/build.sh").read_text()
        self.assertIn('sh "$HERE/camdecode.sh" "$STAGE%s"' % arg(self.c, "decode-root"), build)
        self.assertIn('install -m 0755 "$OUT/gvisor/runsc" "$STAGE%s"' % arg(self.c, "runsc"), build)
        self.assertRegex(build, r"(?s)for cmd in agentosd .*\bagentos-camera; do")
        # runsc's state and the owner socket: the clerk's runtime directory, which the main side may reach.
        run = "/run/" + self.svc["RuntimeDirectory"]
        self.assertEqual(arg(self.c, "owner-sock").rsplit("/", 1)[0], run)
        self.assertEqual(arg(self.c, "runsc-root").rsplit("/", 1)[0], run)
        self.assertEqual(self.svc["RuntimeDirectoryMode"], "0755")
        self.assertFalse(check.keeper_reach(run))
        self.assertIn(run[1:], check.SERVICE_DIRS)

    # REQ: CLK-1, STO-2, UPD-10
    def test_the_clerk_s_lifecycle(self):
        u = ini(CAMERA)["Unit"]
        self.assertIn("agentos-keeper-kernel.service", u["After"].split())
        self.assertIn("systemd-tmpfiles-setup.service", u["After"].split())
        self.assertEqual(exec_lines(CAMERA, "ConditionPathExists"), [arg(self.unlock, "store")])
        self.assertEqual(ini(CAMERA)["Install"]["WantedBy"], "multi-user.target")
        self.assertIn("enable %s" % CAMERA.name, PRESET.read_text().splitlines())
        self.assertEqual((self.svc["Restart"], self.svc["RestartSec"], self.svc["RestartSteps"],
                          self.svc["RestartMaxDelaySec"]), ("on-failure", "2", "8", "5min"))
        self.assertEqual(u["StartLimitIntervalSec"], "0")
        # The sealed store and the retained capture: keeper state on the root partition, made at every
        # boot, the clerk's user's alone, and hidden from every main-side unit.
        state = arg(self.c, "dir")
        self.assertIn(state, check.KEEPER_PATHS)
        self.assertIn(state[1:], check.SERVICE_DIRS)
        made = {w[1]: w for w in (l.split() for l in TMPFILES.read_text().splitlines()) if w and w[0] == "d"}
        self.assertEqual(made[state], ["d", state, "0700", "agentos-camera", "agentos-camera", "-"])
        self.assertEqual(self.svc["ReadWritePaths"], state)
        main_side = ini(UNITS / "agentos-.service.d/50-main-side.conf")["Service"]["InaccessiblePaths"].split()
        self.assertIn(state, main_side)
        for key in ("StateDirectory", "RuntimeDirectoryPreserve", "DynamicUser"):
            self.assertNotIn(key, self.svc)

    # REQ: CLK-1, NET-2, DEV-2, UPD-10
    def test_the_clerk_s_sandbox(self):
        s = self.svc
        for k, v in (("NoNewPrivileges", "yes"), ("CapabilityBoundingSet", ""), ("LimitCORE", "0"), ("UMask", "0077"),
                     ("ProtectSystem", "strict"), ("ProtectHome", "yes"), ("PrivateTmp", "yes"), ("PrivateIPC", "yes"),
                     ("PrivateDevices", "yes"), ("DevicePolicy", "closed"), ("ProtectProc", "invisible"),
                     ("NoExecPaths", "/"), ("ExecPaths", "/usr"), ("SystemCallArchitectures", "native")):
            self.assertEqual(s[k], v, k)
        self.assertNotIn("DeviceAllow", s)
        self.assertNotIn(CAMERA.name, check.TPM_UNITS)
        # runsc makes its namespaces for each sandbox, rootless, and the clerk starts it with clone3 (into its
        # group), which systemd's namespace filter answers with ENOSYS: no RestrictNamespaces= (CAM-host-11).
        self.assertNotIn("RestrictNamespaces", s)
        self.assertIn("UseCgroupFD: true", (ROOT / "broker/vm/gvisor/runonce.go").read_text())
        # The sentry and gofer filter their own calls; the unit still refuses what no sandbox makes.
        self.assertEqual(exec_lines(CAMERA, "SystemCallFilter"), ["~@cpu-emulation @obsolete @raw-io @reboot @swap"])
        self.assertEqual(s["SystemCallErrorNumber"], "EPERM")
        self.assertEqual((s["ProtectClock"], s["ProtectKernelModules"]), ("yes", "yes"))
        # The nodes' stream ports on the home network, the ranges the device-driver host reaches (DEV-2).
        devices = ini(ROOT / "broker/cmd/agentos-devices/agentos-devices.service")["Service"]
        self.assertEqual(s["IPAddressDeny"], "any")
        self.assertEqual(s["IPAddressAllow"].split(), devices["IPAddressAllow"].split())
        self.assertEqual(s["RestrictAddressFamilies"].split(), ["AF_UNIX", "AF_INET", "AF_INET6"])
        self.assertNotIn("PrivateNetwork", s)
        self.assertNotIn("Environment", s)
        self.assertNotIn("EnvironmentFile", s)

    # REQ: CLK-1, NET-2
    def test_ci_runs_a_decoder_in_this_unit(self):
        ci = CI.read_text()
        self.assertIn("S=../%s\n" % UNITS.relative_to(ROOT), ci)
        self.assertIn("U=$S/%s\n" % CAMERA.name, ci)
        self.assertIn("TestDecoderStartsInTheUnitsSandbox", ci)
        test = (CMD / "unit_test.go").read_text()
        self.assertIn("func TestDecoderStartsInTheUnitsSandbox(", test)


if __name__ == "__main__":
    unittest.main()
