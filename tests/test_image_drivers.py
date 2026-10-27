"""DEVSLOT-image (#3471, part b1 of #3321, briefs/DEVSLOT-drivers.md "Part (b), settled"): the image
ships each private device driver under /usr, listed in drivers.json and the release manifest by name,
repository, commit, hash, declaration, class row and measure, and runs it only under units rendered
from mkosi.finalize's one template. The public build lists none. Each refusal is a driver directory
the build must refuse (image/finish_image.py --stage-drivers, devslot.Check through image/drivercheck)
or a mutant of a staged tree that mkosi.finalize must refuse. The fixture driver's binary is the
drivercheck binary itself: a real static Go executable."""
# REQ: DEV-1, KRN-2, RES-2, HW-10
import configparser
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import ENTRY, H, IMG, check, clean_tree, finish, reference_tool  # noqa: E402

DECL = {"Device": "scale", "Link": "tcp", "Channels": [{"Name": "stream", "Port": 8080}],
        "Shapes": [{"Name": "get", "Channel": "stream", "Kind": "tcp-frame", "Prefix": "AQ==", "Min": 1, "Max": 1}],
        "Operations": [{"Name": "weigh", "Verb": "read", "Shapes": ["get"]}],
        "Readings": ["mass"], "MaxRead": 64, "MaxReadings": 4}
ENTRY_JSON = {"repository": "ghbmrk/agentos-private", "commit": "ab" * 20, "declaration": DECL,
              "classes": {"weigh": "read"}, "measure": {"lines": 900, "deps": 0, "parsers": 1}}
SERVICE = "usr/lib/systemd/system/agentos-driver-scale@.service"
SOCKET = "usr/lib/systemd/system/agentos-driver-scale.socket"
SYSUSER = "usr/lib/sysusers.d/agentos-driver-scale.conf"
BINARY = "usr/lib/agentos/drivers/scale/driver"


def unit(text):
    p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    p.optionxform = str
    p.read_string(text)
    return p


def elf(ptypes, e_type=2):
    """A minimal ELF64 x86-64 header with program headers of PTYPES."""
    head = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    head += struct.pack("<HHIQQQIHHHHHH", e_type, 62, 1, 0, 64, 0, 0, 64, 56, len(ptypes), 64, 0, 0)
    return head + b"".join(struct.pack("<IIQQQQQQ", t, 0, 0, 0, 0, 0, 0, 0) for t in ptypes)


class DriversTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin_dir = tempfile.TemporaryDirectory()
        cls.checker = pathlib.Path(cls.bin_dir.name) / "drivercheck"
        subprocess.run(["go", "build", "-trimpath", "-o", str(cls.checker), "."], cwd=IMG / "drivercheck",
                       env=dict(os.environ, CGO_ENABLED="0"), check=True)

    @classmethod
    def tearDownClass(cls):
        cls.bin_dir.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = pathlib.Path(self.tmp.name)
        self.src, self.stage = self.d / "drivers", self.d / "stage"
        self.src.mkdir()
        self.stage.mkdir()

    def driver(self, name="scale", entry=None, data=None):
        d = self.src / name
        d.mkdir()
        (d / "driver").write_bytes(self.checker.read_bytes() if data is None else data)
        (d / "entry.json").write_text(json.dumps(ENTRY_JSON if entry is None else entry))
        return d

    def stage_drivers(self, src=None):
        return finish.stage_drivers(str(self.src) if src is None else src, str(self.stage), [str(self.checker)])

    def refused(self):
        with self.assertRaises(ValueError) as cm:
            self.stage_drivers()
        return str(cm.exception)

    def driver_lines(self):
        return check.driver_violations(self.stage)

    def test_public_build_lists_no_drivers(self):
        self.assertEqual(self.stage_drivers(""), [])
        self.assertEqual(json.loads((self.stage / check.DRIVERS_JSON).read_text()), {"drivers": []})
        shipped = [p for p in self.stage.rglob("*") if p.is_file()]
        self.assertEqual(shipped, [self.stage / check.DRIVERS_JSON], "no driver, unit or user ships")
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        self.assertEqual(finish.manifest("7", H, name, text, {}, {}, [])["drivers"], [])
        self.assertEqual(finish.manifest("7", H, name, text, {})["drivers"], [])
        self.assertEqual(self.driver_lines(), [])
        # The whole tree check passes the public tree with its empty drivers.json.
        clean_tree(self.stage)
        self.assertEqual(check.violations(self.stage), [])
        build = (IMG / "build.sh").read_text()
        self.assertIn('finish_image.py" --stage-drivers "$DRIVERS" "$STAGE"', build)
        self.assertIn('finish_image.py" "$OUT" "$VERSION" "$STAGE/usr/lib/agentos/drivers.json"', build)

    def test_manifest_names_each_driver(self):
        self.driver()
        [e] = self.stage_drivers()
        canonical = json.loads(subprocess.run([str(self.checker)], input=json.dumps(
            {"declaration": DECL, "classes": {"weigh": "read"}}).encode(), capture_output=True, check=True).stdout)
        self.assertEqual(e, {"name": "scale", "repository": "ghbmrk/agentos-private", "commit": "ab" * 20,
                             "sha256": hashlib.sha256(self.checker.read_bytes()).hexdigest(),
                             "declaration": canonical, "classes": {"weigh": "read"},
                             "measure": {"lines": 900, "deps": 0, "parsers": 1}})
        # The class row (part b point 4) is carried through as data, apart from the declaration.
        self.assertEqual(e["classes"], {"weigh": "read"})
        self.assertNotIn("classes", e["declaration"])
        self.assertEqual(json.loads((self.stage / check.DRIVERS_JSON).read_text()), {"drivers": [e]})
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        self.assertEqual(finish.manifest("7", H, name, text, {}, {}, [e])["drivers"], [e])
        self.assertEqual((self.stage / BINARY).read_bytes(), self.checker.read_bytes())
        self.assertEqual((self.stage / BINARY).stat().st_mode & 0o7777, 0o755)
        for rel, body in check.driver_units("scale").items():
            self.assertEqual((self.stage / rel).read_text(), body)
        self.assertEqual(self.driver_lines(), [])
        # The whole tree check passes a tree with the driver: its units pass UPD-10 (the binary's
        # read-only bind onto itself under TemporaryFileSystem=/:ro mounts nothing new under /usr).
        clean_tree(self.stage)
        self.assertEqual(check.violations(self.stage), [])

    def test_class_row_must_match_the_operations(self):
        for classes in ({}, {"weigh": "read", "tare": "read"}, {"tare": "read"}, {"weigh": "exec"}):
            with self.subTest(classes=classes):
                shutil.rmtree(self.src)
                self.src.mkdir()
                self.driver(entry=dict(ENTRY_JSON, classes=classes))
                self.assertIn("class", self.refused())

    def test_driver_refused(self):
        bad_decl = dict(DECL, Operations=[{"Name": "weigh", "Verb": "exec", "Shapes": ["get"]}])
        build_refusals = {
            "declaration fails Check": (lambda: self.driver(entry=dict(ENTRY_JSON, declaration=bad_decl)), "DEV-4"),
            "declaration with an unknown field": (lambda: self.driver(entry=dict(ENTRY_JSON, declaration=dict(
                DECL, Host="203.0.113.1"))), "unknown field"),
            "name off the alphabet": (lambda: self.driver("Scale_1"), "alphabet"),
            "name too long for its user": (lambda: self.driver("s" * 20), "alphabet"),
            "dynamically linked (PT_INTERP)": (lambda: self.driver(data=elf([1, 3])), "dynamically linked"),
            "dynamically linked (PT_DYNAMIC)": (lambda: self.driver(data=elf([1, 2])), "dynamically linked"),
            "position-independent": (lambda: self.driver(data=elf([1], e_type=3)), "fixed-address"),
            "not an ELF": (lambda: self.driver(data=b"#!/bin/sh\n"), "ELF"),
            "extra file": (lambda: (self.driver() / "lib.so").write_bytes(b""), "exactly"),
            "entry with an extra key": (lambda: self.driver(entry=dict(ENTRY_JSON, sha256="00" * 32)), "keys"),
            "short commit": (lambda: self.driver(entry=dict(ENTRY_JSON, commit="abc")), "commit"),
            "measure not counts": (lambda: self.driver(entry=dict(ENTRY_JSON, measure={"lines": "9"})), "measure"),
        }
        for what, (make, why) in build_refusals.items():
            with self.subTest(what):
                shutil.rmtree(self.src)
                self.src.mkdir()
                make()
                self.assertIn(why, self.refused())
        # What the tree check refuses after staging: a hash mismatch, an unlisted file, a listed binary
        # missing, and a listing that is not drivers.json's shape.
        shutil.rmtree(self.src)
        self.src.mkdir()
        self.driver()
        self.stage_drivers()
        clean = self.stage
        mutants = {
            "hash mismatch": lambda r: (r / BINARY).write_bytes(self.checker.read_bytes() + b"\0"),
            "unlisted file": lambda r: (r / "usr/lib/agentos/drivers/scale/helper").write_bytes(b"x"),
            "unlisted driver": lambda r: ((r / "usr/lib/agentos/drivers/other").mkdir(),
                                          (r / "usr/lib/agentos/drivers/other/driver").write_bytes(b"x")),
            "listed binary missing": lambda r: (r / BINARY).unlink(),
            "group-writable binary": lambda r: (r / BINARY).chmod(0o775),
            "listing off its shape": lambda r: (r / check.DRIVERS_JSON).write_text('{"drivers": [{"name": "scale"}]}'),
            "listing unreadable": lambda r: (r / check.DRIVERS_JSON).write_text("{"),
        }
        for what, mutate in mutants.items():
            with self.subTest(what):
                root = self.d / ("m-" + what.replace(" ", "-"))
                shutil.copytree(clean, root, symlinks=True)
                mutate(root)
                self.assertTrue([v for v in check.driver_violations(root) if "DEVSLOT-image" in v], what)

    def test_driver_units_are_the_template(self):
        self.driver()
        self.stage_drivers()
        units = check.driver_units("scale")
        sock, svc = unit(units[SOCKET]), unit(units[SERVICE])
        # #3466 delta L3 6448392099: MaxConnections= is a [Socket] option, so it is in the socket unit,
        # not the service, where systemd would ignore it with a warning.
        self.assertEqual(sock["Socket"]["MaxConnections"], "2")
        self.assertNotIn("MaxConnections", svc["Service"])
        self.assertEqual((sock["Socket"]["Accept"], sock["Socket"]["SocketMode"]), ("yes", "0600"))
        for k, v in (("RestrictAddressFamilies", "none"), ("PrivateNetwork", "yes"), ("IPAddressDeny", "any"),
                     ("TemporaryFileSystem", "/:ro"), ("StandardInput", "null"), ("StandardOutput", "null"),
                     ("StandardError", "null"), ("NoNewPrivileges", "yes"), ("CapabilityBoundingSet", ""),
                     ("NoExecPaths", "/"), ("ExecPaths", "/usr/lib/agentos/drivers/scale/driver"),
                     ("User", "agentos-drv-scale"), ("LimitCORE", "0"), ("RuntimeMaxSec", "120")):
            self.assertEqual(svc["Service"][k], v, k)
        # RES-2: the driver's whole memory is MemoryMax= times MaxConnections=.
        self.assertEqual(svc["Service"]["MemoryMax"], "48M")
        clean = self.stage
        edit = lambda rel, old, new: lambda r: (r / rel).write_text((r / rel).read_text().replace(old, new))  # noqa: E731
        mutants = {
            "RestrictAddressFamilies= dropped": edit(SERVICE, "RestrictAddressFamilies=none\n", ""),
            "MaxConnections= dropped": edit(SOCKET, "MaxConnections=2\n", ""),
            "MaxConnections= raised": edit(SOCKET, "MaxConnections=2", "MaxConnections=64"),
            "StandardInput= changed": edit(SERVICE, "StandardInput=null", "StandardInput=socket"),
            "user changed": edit(SYSUSER, "u agentos-drv-scale", "u root"),
            "unit missing": lambda r: (r / SOCKET).unlink(),
            "drop-in": lambda r: ((r / (SERVICE + ".d")).mkdir(),
                                  (r / (SERVICE + ".d/50-net.conf")).write_text("[Service]\nPrivateNetwork=no\n")),
            "etc override": lambda r: ((r / "etc/systemd/system").mkdir(parents=True),
                                       (r / "etc/systemd/system/agentos-driver-scale@.service").write_text("[Service]\n")),
            "other unit runs as a driver's user": lambda r: (r / "usr/lib/systemd/system/x.service").write_text(
                "[Service]\nUser=agentos-drv-scale\n"),
            "other unit reaches the drivers' sockets": lambda r: (r / "usr/lib/systemd/system/x.service").write_text(
                "[Service]\nBindPaths=/run/agentos-drivers\n"),
            "sysusers line for a driver's user": lambda r: (r / "usr/lib/sysusers.d/x.conf").write_text(
                "m agentos-drv-scale tss\n"),
            "unit for an unlisted driver": lambda r: (r / "usr/lib/systemd/system/agentos-driver-other.socket").write_text(
                "[Socket]\n"),
        }
        for what, mutate in mutants.items():
            with self.subTest(what):
                root = self.d / ("m-" + what.replace(" ", "-").replace("'", ""))
                shutil.copytree(clean, root, symlinks=True)
                mutate(root)
                self.assertTrue([v for v in check.driver_violations(root) if "DEVSLOT-image" in v], what)

    def test_template_parses_as_systemd_reads_it(self):
        # systemd-analyze verify names every key systemd ignores (MaxConnections= in [Service] was one,
        # #3466 delta L3): the rendered units must draw no such warning. The binary's path is the one
        # host-specific word, pointed at a file that exists here.
        tool = reference_tool(self, "systemd-analyze")
        units = check.driver_units("scale")
        exe = shutil.which("true")
        for rel in (SOCKET, SERVICE):
            body = units[rel].replace("/usr/lib/agentos/drivers/scale/driver", exe)
            name = pathlib.PurePosixPath(rel).name.replace("@.service", "@op.service")
            (self.d / name).write_text(body)
        r = subprocess.run([tool, "verify", "--man=no", str(self.d / "agentos-driver-scale.socket"),
                            str(self.d / "agentos-driver-scale@op.service")], capture_output=True, text=True)
        self.assertNotIn("Unknown key", r.stderr + r.stdout)
        self.assertNotIn("ignoring", r.stderr + r.stdout)

    def test_self_bind_is_only_a_regular_file_under_usr(self):
        # UPD-10 still refuses a bind that lands anything new under /usr.
        self.driver()
        self.stage_drivers()
        files = [check.Conf(str(self.stage), SERVICE)]
        self.assertTrue(check.self_bind(files, "/usr/lib/agentos/drivers/scale/driver"))
        for w in ("/var/lib/x:/usr/lib/agentos/drivers/scale/driver", "-/usr/lib/agentos/drivers/scale/driver",
                  "/usr/lib/agentos/drivers/scale", "/usr/lib/agentos/drivers/scale/../scale/driver",
                  "/usr/lib/agentos/drivers/missing/driver", "/etc/passwd"):
            self.assertFalse(check.self_bind(files, w), w)
        (self.stage / "usr/lib/agentos/link").symlink_to("/var/lib/x")
        self.assertFalse(check.self_bind(files, "/usr/lib/agentos/link"))


if __name__ == "__main__":
    unittest.main()
