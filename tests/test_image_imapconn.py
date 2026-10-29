"""TB-parsers-2-launch (#3015, from TB-parsers-2, #2937 gap 2): the mail clerk's IMAP connection process
as the image starts it. Each session the clerk opens on agentos-imapconn.socket is a fresh
agentos-imapconn@.service: go-imap runs there, under a user that is not the clerk's, with no network,
an empty read-only root holding only its binary (so none of the clerk's files) and no new privileges.
These are the static checks on the units and on mkosi.finalize's empty-root rule; CI's boot test runs a
stand-in under the shipped sandbox and checks the property from inside it (image/ci_boot.sh, IMAPCONN)."""
# REQ: CLK-1, KRN-2, A5, UPD-10
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, ROOT, check, clean_tree, exec_args, arg, ini, write  # noqa: E402
from test_image_keeper import KEEPER_FILES, MAIL, PRESET, SYSUSERS, UNITS, exec_lines  # noqa: E402
from test_image_noexec import STOCK_TMP, SYSTEM, shipped_units, stage_binaries  # noqa: E402

SOCKET = UNITS / "agentos-imapconn.socket"
SERVICE = UNITS / "agentos-imapconn@.service"
DROPIN = "agentos-imapconn@.service.d/90-empty-root.conf"
BINARY = "/usr/lib/agentos/agentos-imapconn"
CI_BOOT = ROOT / "image/ci_boot.sh"
WORKFLOW = ROOT / ".github/workflows/image.yml"


class ImapConnUnitsTest(unittest.TestCase):
    def setUp(self):
        self.sock = ini(SOCKET)["Socket"]
        self.svc = ini(SERVICE)["Service"]
        self.clerk = ini(MAIL)["Service"]

    def test_only_the_clerk_reaches_a_fresh_process_per_session(self):
        # The clerk's -imap-conn is this socket, which only the clerk's user can connect to, and each
        # connection starts its own instance, so its own process.
        self.assertEqual(arg(exec_args(MAIL), "imap-conn"), self.sock["ListenStream"])
        self.assertEqual((self.sock["SocketUser"], self.sock["SocketGroup"], self.sock["SocketMode"]),
                         (self.clerk["User"], self.clerk["Group"], "0600"))
        self.assertEqual(self.sock["Accept"], "yes")
        self.assertNotIn("Service", self.sock)
        self.assertTrue(0 < int(self.sock["MaxConnections"]) <= 8)
        self.assertFalse(check.keeper_reach(self.sock["ListenStream"], above=True))
        self.assertIn("enable agentos-imapconn.socket", PRESET.read_text().splitlines())
        self.assertEqual(ini(SOCKET)["Install"]["WantedBy"], "sockets.target")
        # The connection is the process's descriptor 3, which its main serves and nothing else.
        main = (ROOT / "broker/clerk/inbox/imapconn/cmd/imapconn/main.go").read_text()
        self.assertIn("os.NewFile(3,", main)
        self.assertNotIn("StandardInput=socket", SERVICE.read_text())

    def test_the_process_is_not_the_clerk_and_holds_no_credential(self):
        s = self.svc
        self.assertEqual((s["User"], s["Group"]), ("agentos-imapconn", "agentos-imapconn"))
        self.assertNotEqual(s["User"], self.clerk["User"])
        self.assertRegex(SYSUSERS.read_text(), r'(?m)^u agentos-imapconn - ')
        # Nothing is handed to it but the connection: no key, credential, file or environment.
        for key in ("OpenFile", "LoadCredential", "LoadCredentialEncrypted", "SetCredential", "Environment",
                    "EnvironmentFile", "PassEnvironment", "Sockets", "DynamicUser", "AmbientCapabilities",
                    "SupplementaryGroups", "Slice", "ExecStartPre", "ExecStartPost", "ExecStopPost"):
            self.assertNotIn(key, s, key)
        self.assertEqual((s["StandardInput"], s["StandardOutput"], s["StandardError"]), ("null", "null", "null"))
        self.assertNotIn(SERVICE.name, check.KEEPER_UNITS + check.TPM_UNITS)

    def test_the_sandbox(self):
        s = self.svc
        # No network: no socket of any family, its own empty network namespace, no IP; its own pid
        # namespace, so no other session's process to see, signal or open under /proc (#3880).
        for k, v in (("RestrictAddressFamilies", "none"), ("PrivatePIDs", "yes"), ("PrivateNetwork", "yes"), ("IPAddressDeny", "any"),
                     # The empty root: the binary, bound from the verity-checked /usr, is all there is.
                     ("TemporaryFileSystem", "/:ro,noexec"), ("BindReadOnlyPaths", BINARY), ("ExecStart", BINARY),
                     ("NoNewPrivileges", "yes"), ("CapabilityBoundingSet", ""), ("PrivateDevices", "yes"),
                     ("PrivateIPC", "yes"), ("ProcSubset", "pid"), ("ProtectProc", "invisible"), ("LimitCORE", "0"),
                     ("MemoryDenyWriteExecute", "yes"), ("RestrictNamespaces", "yes"), ("LockPersonality", "yes"),
                     ("SystemCallArchitectures", "native")):
            self.assertEqual(s[k], v, k)
        self.assertEqual(exec_lines(SERVICE, "SystemCallFilter"), ["@system-service", "~@debug @mount @privileged @resources"])
        # Bounded: its memory times the socket's connections, its tasks, and a backstop on its life.
        self.assertRegex(s["MemoryMax"], r"^\d+M$")
        self.assertLessEqual(int(s["MemoryMax"][:-1]) * int(self.sock["MaxConnections"]), 1024)
        self.assertTrue(s["TasksMax"].isdigit())
        self.assertRegex(s["RuntimeMaxSec"], r"^\d+(s|min|h)?$")
        # The image builds that binary from the connection process's main.
        build = (ROOT / "image/build.sh").read_text()
        self.assertRegex(build, r'-o "\$STAGE%s" \./clerk/inbox/imapconn/cmd/imapconn\)' % re.escape(BINARY))
        # The main side's mask is lifted only because the root holds none of its paths.
        self.assertEqual(ini(UNITS / DROPIN)["Service"]["InaccessiblePaths"], "")
        self.assertIn(SERVICE.name, check.EMPTY_ROOT_UNITS)


class ImapConnTreeTest(unittest.TestCase):
    """mkosi.finalize on a tree holding the image's own units with the connection process's drop-in."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = clean_tree(pathlib.Path(self.tmp.name))
        for rel, src in shipped_units().items():
            write(self.root, rel, src.read_text())
        for rel in KEEPER_FILES + ("usr/lib/systemd/system/" + DROPIN,):
            write(self.root, rel, (MK / "mkosi.extra" / rel).read_text())
        write(self.root, SYSTEM + "tmp.mount", STOCK_TMP)
        write(self.root, "usr/lib/sysusers.d/agentos-setup.conf", SYSUSERS.read_text())
        stage_binaries(self.root)

    def v(self):
        return [l for l in check.keeper_violations(self.root) + check.noexec_violations(self.root)
                if l.startswith(("agentos-imapconn", "agentos-modem"))]

    def drop(self, unit, text):
        write(self.root, SYSTEM + unit + ".d/95-x.conf", "[Service]\n" + text + "\n")

    def test_the_image_passes(self):
        self.assertEqual(self.v(), [])
        self.assertEqual(check.violations(self.root), [])

    def test_the_lift_needs_the_empty_root(self):
        lifted = "the main side never sees the keeper's state (D-154)"
        # Each of these leaves the process a root with something in it, or makes systemd drop the
        # empty root (#3642, #3712), so the lifted mask is refused.
        # PrivatePIDs= mounts a /proc, not an entry at "/", so the shipped unit keeps its root.
        for text in ("TemporaryFileSystem=\nTemporaryFileSystem=/var", "NoExecPaths=/", "DynamicUser=yes",
                     "ProtectSystem=strict", "BindReadOnlyPaths=/var:/"):
            with self.subTest(text):
                self.drop("agentos-imapconn@.service", text)
                self.assertTrue([l for l in self.v() if l.startswith("agentos-imapconn@.service") and lifted in l],
                                self.v())
                (self.root / SYSTEM / "agentos-imapconn@.service.d/95-x.conf").unlink()
        # The rule is the listed unit's alone: another unit with the same empty root keeps the mask.
        self.drop("agentos-modem.service", "TemporaryFileSystem=/:ro,noexec\nInaccessiblePaths=")
        self.assertTrue([l for l in self.v() if l.startswith("agentos-modem.service") and lifted in l], self.v())


class ImapConnBootTest(unittest.TestCase):
    """The boot probe changes only the binary the shipped units run, and CI runs it."""

    def test_the_probe_changes_only_the_binary(self):
        text = CI_BOOT.read_text()
        m = re.search(r"systemd\.unit-dropin\.agentos-imapconn@\.service~99-ci-probe' \"(.*?)\"\)", text)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), r"[Service]\nExecStart=\nExecStart=$ICB/bootconn\nBindReadOnlyPaths=$ICB/bootconn\n")
        # The probe runs as the clerk's user, then as another, which the socket refuses.
        self.assertIn("setpriv --reuid=%s --regid=%s" % ((ini(MAIL)["Service"]["User"],) * 2), text)
        self.assertIn("setpriv --reuid=agentos-planner --regid=agentos-planner", text)
        for c in ("each session is a fresh process", "runs as uid", "socket() refused", "has its own pid namespace",
                  "marks itself undumpable", "cannot read session 1's memory", "cannot open the clerk's state directory",
                  "ends when the session closes"):
            self.assertIn(c, text)
            self.assertIn(c, (ROOT / "broker/clerk/inbox/imapconn/testdata/bootprobe/main.go").read_text())
        wf = WORKFLOW.read_text()
        self.assertIn("./clerk/inbox/imapconn/testdata/$b", wf)
        self.assertIn('IMAPCONN="$RUNNER_TEMP/imapconn"', wf)


if __name__ == "__main__":
    unittest.main()
