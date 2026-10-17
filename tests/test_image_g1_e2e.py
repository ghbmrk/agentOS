"""Follow-ups to the in-image end-to-end run (G1-e2e, #1688; PR #1705 reviews): the boot report says
when the Wi-Fi page is down because its claim hand-over failed (#1743), and nothing CI-only from the
e2e run (the box-e2e driver, image/e2e/*) reaches the shipped image (#1739).

Kept apart from tests/test_image.py, which several open PRs edit (D-111)."""
import configparser
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG = ROOT / "image"
MK = IMG / "mkosi"
AGENTOS_LIB = MK / "mkosi.extra/usr/lib/agentos"
E2E = IMG / "e2e"
BUILD = IMG / "build.sh"
WORKFLOW = ROOT / ".github/workflows/image.yml"


def ini(path):
    p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    p.optionxform = str
    p.read(path)
    return p


def stub(d, name, body):
    f = d / name
    f.write_text("#!/bin/sh\n" + body + "\n")
    f.chmod(0o755)


class ClaimSignalTest(unittest.TestCase):
    """#1743: agentos-localui.service Requires= its claim hand-over, so a failed hand-over leaves the
    setup access point up with no page. The boot report names it; the page stays fail-closed."""
    # REQ: HW-10

    def report(self, claim_state):
        # Runs boot-report with no wired link and stand-ins for the commands it calls; systemctl
        # answers is-failed for the claim unit with CLAIM_STATE (None: systemctl itself fails).
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            (t / "net").mkdir()
            stub(t, "sleep", ":")
            stub(t, "ip", ":")
            stub(t, "findmnt", "echo 1073741824")
            stub(t, "systemd-bless-boot", "echo good")
            if claim_state is None:
                stub(t, "systemctl", "exit 1")
            else:
                stub(t, "systemctl", '[ "$*" = "is-failed agentos-localui-claim.service" ] || exit 9\n'
                     'echo %s; [ %s = failed ]' % (claim_state, claim_state))
            script = (AGENTOS_LIB / "boot-report").read_text().replace(
                "/usr/lib/systemd/systemd-bless-boot", str(t / "systemd-bless-boot"))
            env = dict(os.environ, PATH="%s:%s" % (t, os.environ["PATH"]), AGENTOS_SYS_NET=str(t / "net"))
            out = subprocess.run(["sh", "-c", script], env=env, check=True, capture_output=True, text=True).stdout
            return out.splitlines()

    def page_line(self, lines):
        page = [x for x in lines if x.startswith("agentos-page: ")]
        self.assertEqual(len(page), 1, lines)
        return page[0]

    def test_a_failed_hand_over_is_reported_with_what_to_do(self):
        lines = self.report("failed")
        self.assertEqual(self.page_line(lines),
                         "agentos-page: down claim=failed (power-cycle; if it persists, contact support)")

    def test_a_done_or_skipped_hand_over_reads_ok(self):
        # Done (a oneshot that exited 0) and skipped by its condition (a download box, or already
        # moved) both read inactive; active covers a RemainAfterExit= edit.
        for state in ("inactive", "active"):
            with self.subTest(state=state):
                self.assertEqual(self.page_line(self.report(state)), "agentos-page: claim=ok")

    def test_an_unreadable_state_is_never_ok(self):
        for state in (None, "activating", "unknown"):
            with self.subTest(state=state):
                self.assertEqual(self.page_line(self.report(state)), "agentos-page: claim=unknown")

    def test_the_page_line_follows_the_lines_ci_waits_for(self):
        # ci_boot.sh stops waiting at "agentos-boot:" and reads the uplink line first; the page line
        # comes after both, so neither moves.
        lines = self.report("failed")
        self.assertTrue(lines[0].startswith("agentos-uplink: "), lines)
        self.assertIn(" agentos-boot: bless=good", lines[0])
        self.assertTrue(lines[1].startswith("agentos-page: "), lines)

    def test_the_report_runs_after_the_hand_over(self):
        report = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-boot-report.service")
        self.assertIn("agentos-localui-claim.service", report["Unit"]["After"].split())

    def test_the_page_stays_fail_closed(self):
        # The signal must not become a way round the gate: the page still Requires= the hand-over,
        # and the hand-over still runs before it.
        page = ini(ROOT / "broker/cmd/agentos-localui/agentos-localui.service")["Unit"]
        self.assertIn("agentos-localui-claim.service", page["Requires"].split())
        self.assertIn("agentos-localui-claim.service", page["After"].split())
        claim = ini(ROOT / "broker/cmd/agentos-localui/agentos-localui-claim.service")["Unit"]
        self.assertIn("agentos-localui.service", claim["Before"].split())


# Names that mark CI-only e2e pieces: the driver binary and its package, and image/e2e's own units
# (agentos-e2e.service, agentos-e2e-seal.service). image/e2e's drop-ins have generic names
# (multi-user.conf), so they are caught by content instead.
E2E_NAMES = ("box-e2e", "boxe2e", "e2e/", "agentos-e2e")


def shipped_sources():
    """build.sh (its install list) and every file under image/mkosi (what mkosi puts in the image)."""
    yield BUILD
    for p in sorted(MK.rglob("*")):
        if p.is_file():
            yield p


def shipped_hits(paths, e2e_dir=E2E):
    """(path, reason) for each shipped source that names an e2e piece or copies an image/e2e file."""
    e2e_bytes = {p.read_bytes(): p.name for p in pathlib.Path(e2e_dir).iterdir() if p.is_file()}
    hits = []
    for p in paths:
        data = pathlib.Path(p).read_bytes()
        if data in e2e_bytes:
            hits.append((p, "copy of image/e2e/" + e2e_bytes[data]))
        text = data.decode("utf-8", "replace")
        for name in E2E_NAMES:
            if name in text or name in pathlib.Path(p).name:
                hits.append((p, name))
    return hits


def workflow_hits(text):
    """Lines of image.yml that put the e2e driver, or the directory handed to ci_boot.sh as E2E,
    under $RUNNER_TEMP/out: the image build's output, whose stage/ is the image's extra tree."""
    hits = []
    for line in text.splitlines():
        if "E2E=" in line:
            where = line.split("E2E=", 1)[1].split()[0]
        elif "box-e2e" in line or "boxe2e" in line:
            where = line
        else:
            continue
        if "$RUNNER_TEMP/out" in where:
            hits.append(line.strip())
    return hits


class ImageGuardTest(unittest.TestCase):
    """#1739: the box-e2e driver (broker/e2e/boxe2e, netguard-exempt) and image/e2e's root-run units
    and drop-ins are CI-only. Nothing in the image's build inputs may name or copy them."""
    # REQ: DEV-2, HW-1

    def test_the_shipped_image_names_no_e2e_piece(self):
        self.assertTrue(E2E.is_dir() and any(E2E.iterdir()), "image/e2e moved: update this guard")
        self.assertEqual(shipped_hits(shipped_sources()), [])

    def test_the_workflow_builds_the_driver_outside_the_image_output(self):
        text = WORKFLOW.read_text()
        self.assertIn('-o "$RUNNER_TEMP/e2e/box-e2e" ./e2e/boxe2e', text)
        self.assertIn('E2E="$RUNNER_TEMP/e2e"', text)
        self.assertEqual(workflow_hits(text), [])

    def test_a_planted_reference_in_a_shipped_source_fails(self):
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            plants = {
                "build.sh": 'install -m 0755 "$E2E/box-e2e" "$STAGE/usr/lib/agentos/box-e2e"\n',
                "build2.sh": '(cd "$REPO/broker" && go build -o "$STAGE/usr/lib/agentos/x" ./e2e/boxe2e)\n',
                "build3.sh": 'install -D "$REPO/image/e2e/agentos-e2e.service" "$STAGE/usr/lib/systemd/system/"\n',
                "agentos-e2e-seal.service": "[Service]\nExecStart=/bin/true\n",
                "multi-user.conf": (E2E / "multi-user.conf").read_text(),
            }
            for name, body in plants.items():
                (t / name).write_text(body)
            hit = {pathlib.Path(p).name for p, _ in shipped_hits(sorted(t.iterdir()))}
            self.assertEqual(hit, set(plants))
            clean = t / "agentosd.service"
            clean.write_text("# (G1-e2e). No tmpfiles line.\n")
            self.assertEqual(shipped_hits([clean]), [])

    def test_a_driver_built_into_the_image_output_fails(self):
        for line in (
            'run: cd broker && go build -o "$RUNNER_TEMP/out/stage/usr/lib/agentos/box-e2e" ./e2e/boxe2e',
            'run: cd broker && go build -o "$RUNNER_TEMP/out/box-e2e" ./e2e/boxe2e',
            'run: sudo env E2E="$RUNNER_TEMP/out/e2e" image/ci_boot.sh "$RUNNER_TEMP/out/a.raw"',
        ):
            with self.subTest(line=line):
                self.assertEqual(len(workflow_hits(line)), 1)
        ok = 'run: sudo env E2E="$RUNNER_TEMP/e2e" image/ci_boot.sh "$RUNNER_TEMP/out/a.raw" "$RUNNER_TEMP/boot"'
        self.assertEqual(workflow_hits(ok), [])


if __name__ == "__main__":
    unittest.main()
