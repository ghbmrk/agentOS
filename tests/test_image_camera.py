"""CAM-clerk-image (#3867) and CAM-decoder-uid (#4134): the camera clerk's unit, user and key hand-off, and its
decoder sessions' socket and unit, in the image, against the kernel's unit and the mains they run
(broker/cmd/agentos-camera, broker/cmd/agentos-camdecode-host; CAM-host-9, CAM-host-11).

CI's camera decoder step runs the shipped socket and decoder unit on a systemd host, with only the decoder
unit's ExecStart= replaced by its test, and connects as the clerk's user: each session runs a sandbox under a
user of its own, neither root nor the clerk's (broker/cmd/agentos-camdecode-host TestDecoderStartsInItsUnit)."""
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
MAIL = UNITS / "agentos-keeper-mail.service"
DEC_SOCKET = UNITS / "agentos-camdecode.socket"
DECODER = UNITS / "agentos-camdecode@.service"
CMD = ROOT / "broker/cmd/agentos-camera"
HOST_CMD = ROOT / "broker/cmd/agentos-camdecode-host"
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
        self.assertEqual(sorted(keys), ["camera", "homekit", "mail"])
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
        # The kernel matches the peer's whole cgroup: the clerk never leaves its unit's group.
        self.assertNotIn("DelegateSubgroup", self.svc)

    # REQ: RES-2, CLK-1
    def test_the_clerk_starts_no_sandbox(self):
        # The decoders are the decoder unit's (DecoderUnitTest): the clerk's unit delegates no group, its caps
        # are the clerk's alone, and its process links no sandbox runtime.
        self.assertNotIn("Delegate", self.svc)
        self.assertEqual((self.svc["MemoryMax"], self.svc["TasksMax"]), ("1G", "64"))
        for flag in ("runsc", "runsc-root", "decode-root", "cgroup"):
            self.assertNotIn("-" + flag, self.c)
        self.assertEqual(arg(self.c, "decoder"), ini(DEC_SOCKET)["Socket"]["ListenStream"])
        self.assertIn(DEC_SOCKET.name, ini(CAMERA)["Unit"]["After"].split())
        for src in CMD.glob("*.go"):
            if not src.name.endswith("_test.go"):
                self.assertNotIn("broker/vm/gvisor", src.read_text(), src.name)
                self.assertNotIn("broker/cgroup", src.read_text(), src.name)

    # REQ: CLK-1, UPD-10
    def test_the_owner_socket_is_the_clerk_s_alone(self):
        build = (ROOT / "image/build.sh").read_text()
        self.assertRegex(build, r"(?s)for cmd in agentosd [^;]*\bagentos-camera\b[^;]*; do")
        # The owner socket: the clerk's runtime directory, which the main side may reach and only the clerk's
        # uid writes. No decoder session runs as that uid, so a dial that checks the server's uid reaches the
        # clerk and nothing a decoder escape holds (CAM-host-11).
        run = "/run/" + self.svc["RuntimeDirectory"]
        self.assertEqual(arg(self.c, "owner-sock").rsplit("/", 1)[0], run)
        self.assertEqual(self.svc["RuntimeDirectoryMode"], "0755")
        self.assertFalse(check.keeper_reach(run))
        self.assertIn(run[1:], check.SERVICE_DIRS)
        self.assertNotEqual(ini(DECODER)["Service"]["User"], self.svc["User"])

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
        # It starts no sandbox, so it has the mail clerk's profile: no namespace, no writable code, the
        # service call set and a read-only cgroup tree.
        mail = ini(MAIL)["Service"]
        for k in ("RestrictNamespaces", "MemoryDenyWriteExecute", "ProtectControlGroups", "SystemCallErrorNumber"):
            self.assertEqual(s[k], mail[k], k)
        self.assertEqual(exec_lines(CAMERA, "SystemCallFilter"), exec_lines(MAIL, "SystemCallFilter"))
        self.assertEqual((s["ProtectClock"], s["ProtectKernelModules"]), ("yes", "yes"))
        # The nodes' stream ports on the home network, the ranges the device-driver host reaches (DEV-2).
        devices = ini(ROOT / "broker/cmd/agentos-devices/agentos-devices.service")["Service"]
        self.assertEqual(s["IPAddressDeny"], "any")
        self.assertEqual(s["IPAddressAllow"].split(), devices["IPAddressAllow"].split())
        self.assertEqual(s["RestrictAddressFamilies"].split(), ["AF_UNIX", "AF_INET", "AF_INET6"])
        self.assertNotIn("PrivateNetwork", s)
        self.assertNotIn("Environment", s)
        self.assertNotIn("EnvironmentFile", s)


class DecoderUnitTest(unittest.TestCase):
    """CAM-decoder-uid (#4134): each decoder session is a connection to agentos-camdecode.socket, which only
    the clerk's user can open, and a fresh agentos-camdecode@.service under a dynamic user named for its
    instance, so no session runs as the clerk's uid, as root or as another session's."""

    def setUp(self):
        self.sock = ini(DEC_SOCKET)["Socket"]
        self.svc = ini(DECODER)["Service"]
        self.clerk = ini(CAMERA)["Service"]
        self.c = exec_args(DECODER)

    # REQ: CLK-1
    def test_only_the_clerk_opens_a_session(self):
        self.assertEqual((self.sock["SocketUser"], self.sock["SocketGroup"], self.sock["SocketMode"]),
                         (self.clerk["User"], self.clerk["Group"], "0600"))
        self.assertEqual(self.sock["Accept"], "yes")
        self.assertNotIn("Service", self.sock)
        self.assertFalse(check.keeper_reach(self.sock["ListenStream"], above=True))
        self.assertIn("enable %s" % DEC_SOCKET.name, PRESET.read_text().splitlines())
        self.assertEqual(ini(DEC_SOCKET)["Install"]["WantedBy"], "sockets.target")
        # One session per admitted camera (CAM-host-4).
        self.assertEqual(int(self.sock["MaxConnections"]), go_const("broker/cmd/agentos-camera/host.go", "maxCameras"))
        # The connection is the process's standard input, which its main serves and nothing else.
        self.assertEqual((self.svc["StandardInput"], self.svc["StandardOutput"]), ("socket", "null"))
        self.assertIn("os.Stdin", (HOST_CMD / "main.go").read_text())

    # REQ: CLK-1
    def test_each_session_is_a_user_of_its_own(self):
        s = self.svc
        # DynamicUser= with User= naming the instance: systemd makes one user per name, so each connection's
        # (Accept= names it by its count, pid and uid) is its own, and its uid is freed when it ends.
        self.assertEqual((s["DynamicUser"], s["User"]), ("yes", "camdec-%i"))
        self.assertNotIn("Group", s)
        users = [l.split()[1] for l in SYSUSERS.read_text().splitlines() if l.startswith("u ")]
        self.assertFalse([u for u in users if u.startswith("camdec")])
        self.assertNotEqual(s["User"], self.clerk["User"])
        self.assertEqual((s["PrivatePIDs"], s["PrivateTmp"]), ("yes", "yes"))
        # Nothing is handed to it but the connection: no key, credential, file or environment.
        for key in ("OpenFile", "LoadCredential", "LoadCredentialEncrypted", "SetCredential", "Environment",
                    "EnvironmentFile", "PassEnvironment", "Sockets", "AmbientCapabilities", "SupplementaryGroups",
                    "Slice", "ExecStartPre", "ExecStartPost", "ExecStopPost", "ReadWritePaths", "RuntimeDirectory",
                    "StateDirectory"):
            self.assertNotIn(key, s, key)
        # The main side's mask: it sees no keeper path, the clerk's sealed store and capture among them.
        self.assertNotIn(DECODER.name, check.KEEPER_UNITS)
        self.assertIn(arg(exec_args(CAMERA), "dir"), check.KEEPER_PATHS)
        # runsc's state: the unit's own /tmp.
        self.assertTrue(arg(self.c, "runsc-root").startswith("/tmp/"))

    # REQ: NET-2, UPD-10
    def test_the_decoder_paths_are_the_images(self):
        self.assertEqual(self.c[0], "/usr/lib/agentos/agentos-camdecode-host")
        flags = [w[1:] for w in self.c[1:] if w.startswith("-")]
        self.assertEqual(sorted(flags), sorted(go_flags("agentos-camdecode-host")))
        build = (ROOT / "image/build.sh").read_text()
        self.assertIn('sh "$HERE/camdecode.sh" "$STAGE%s"' % arg(self.c, "decode-root"), build)
        self.assertIn('install -m 0755 "$OUT/gvisor/runsc" "$STAGE%s"' % arg(self.c, "runsc"), build)
        self.assertRegex(build, r"(?s)for cmd in agentosd [^;]*\bagentos-camdecode-host\b[^;]*; do")
        self.assertIn("Rootless: true", (HOST_CMD / "main.go").read_text())

    # REQ: RES-2
    def test_the_sandbox_s_group_is_the_unit_s_own(self):
        # Delegated exactly the controllers the sandbox's group takes (broker/cgroup Controllers).
        src = (ROOT / "broker/cgroup/cgroup.go").read_text()
        want = re.search(r'var Controllers = \[\]string\{([^}]*)\}', src).group(1)
        self.assertEqual(self.svc["Delegate"].split(), re.findall(r'"([a-z]+)"', want))
        self.assertIn('const leaf = "host"', (ROOT / "broker/clerk/camera/decodehost/decodehost.go").read_text())
        self.assertNotIn("DelegateSubgroup", self.svc)
        # The unit's caps hold the sandbox at its own cap, and the process above it.
        mem = go_const("broker/clerk/camera/decode.go", "DefaultDecodeMem")
        pids = go_const("broker/vm/gvisor/runonce.go", "oneShotPids")
        self.assertEqual(self.svc["MemoryMax"], "576M")
        self.assertEqual(576 << 20, mem + (64 << 20))
        self.assertEqual(int(self.svc["TasksMax"]), pids + 32)

    # REQ: CLK-1, NET-2, UPD-10
    def test_the_session_s_sandbox(self):
        s = self.svc
        for k, v in (("NoNewPrivileges", "yes"), ("CapabilityBoundingSet", ""), ("LimitCORE", "0"), ("UMask", "0077"),
                     ("ProtectSystem", "strict"), ("ProtectHome", "yes"), ("PrivateIPC", "yes"),
                     ("PrivateDevices", "yes"), ("DevicePolicy", "closed"), ("ProtectProc", "invisible"),
                     ("NoExecPaths", "/"), ("ExecPaths", "/usr"), ("SystemCallArchitectures", "native"),
                     ("PrivateNetwork", "yes"), ("IPAddressDeny", "any"), ("RestrictAddressFamilies", "AF_UNIX")):
            self.assertEqual(s[k], v, k)
        for key in ("IPAddressAllow", "DeviceAllow", "MemoryDenyWriteExecute"):
            self.assertNotIn(key, s)
        # runsc makes its namespaces for the sandbox, rootless, and the process starts it with clone3 (into its
        # group), which systemd's namespace filter answers with ENOSYS: no RestrictNamespaces= (CAM-host-11).
        self.assertNotIn("RestrictNamespaces", s)
        self.assertIn("UseCgroupFD: true", (ROOT / "broker/vm/gvisor/runonce.go").read_text())
        # The sentry and gofer filter their own calls; the unit still refuses what no sandbox makes.
        self.assertEqual(exec_lines(DECODER, "SystemCallFilter"), ["~@cpu-emulation @obsolete @raw-io @reboot @swap"])
        self.assertEqual(s["SystemCallErrorNumber"], "EPERM")
        self.assertEqual((s["ProtectClock"], s["ProtectKernelModules"]), ("yes", "yes"))

    # REQ: CLK-1, NET-2
    def test_ci_runs_sessions_in_this_unit(self):
        ci = CI.read_text()
        self.assertIn("S=../%s\n" % UNITS.relative_to(ROOT), ci)
        self.assertIn("U=$S/%s\n" % DECODER.name, ci)
        self.assertIn("$S/%s" % DEC_SOCKET.name, ci)
        self.assertIn("TestDecoderStartsInItsUnit", ci)
        test = (HOST_CMD / "unit_test.go").read_text()
        self.assertIn("func TestDecoderStartsInItsUnit(", test)


if __name__ == "__main__":
    unittest.main()
