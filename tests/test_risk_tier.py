import contextlib
import io
import pathlib
import sys
import os
import subprocess
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import risk_tier as rt  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


class RiskTierTest(unittest.TestCase):
    def test_paths(self):
        cases = {
            "broker/vault/vault.go": "A",
            "broker/vault/vault_test.go": "A",
            "broker/egress/proxy.go": "A",
            "broker/go.sum": "A",
            "assurance/canary-targets.json": "A",
            "tools/canary.py": "A",
            "tools/risk_tier.py": "A",
            "tools/ci_scope.py": "A",
            "tools/ci_split.py": "A",
            "tools/g1_scope_g2.txt": "A",
            "broker/mail/deliver.go": "A",
            "broker/daemon/daemon.go": "A",
            "broker/cmd/agentosd/main.go": "A",
            # loops is A through its core.txt allow lines.
            "broker/loops/probe.go": "A",
            "broker/loops/machine.go": "A",
            # Tier-A-narrow (#1698): probecmd builds CRED-1 child
            # environments and gates effects, so it stays A (Security #1700
            # f1, f4); corpus and machprobe meet no criterion and are B.
            "broker/probecmd/probecmd.go": "A",
            "broker/corpus/checks.go": "B",
            "broker/machprobe/machprobe.go": "B",
            # REQ: OP-3 (SIM-sim L3 #727: the harness is what assures the journal).
            "broker/sim/world.go": "A",
            # REQ: HW-10 (CTRL-claim-tier, #1067 R1: the lockout and one-claim rule)
            "broker/claim/claim.go": "A",
            "broker/claim/claim_test.go": "A",
            # REQ: HW-10 (CTRL-claim-wire: first boot routes the claim and the card)
            "broker/firstboot/start.go": "A",
            "broker/attention/attention.go": "B",
            # A broker package in no list is A until it is classed.
            "broker/newpkg/x.go": "A",
            "guest/openclaw/Dockerfile": "B",
            "guest/openclaw/src/x.ts": "B",
            "SPEC.md": "B",
            "docs/owners-guide.md": "C",
            "tools/trace.py": "C",
            "spikes/S8-provider-workers/README.md": "C",
            "BOARD.md": "C",
        }
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path)[0], want)

    # RT-1a (briefs/RT-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_image_ci_and_guest_build_paths_are_a(self):
        # Each path brief RT-1 lists under "Today", at the tier RT-1a gives it.
        paths = [
            "image/build.sh",
            "image/finish_image.py",
            "image/ci_boot.sh",
            "image/mkosi/mkosi.conf",
            "image/mkosi/mkosi.finalize",
            "image/mkosi/mkosi.repart/10-root.conf",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-health.service",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-fallback.service",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-drive-id.service",
            "image/mkosi/mkosi.extra/usr/lib/systemd/system/agentos-boot-report.service",
            ".github/workflows/image.yml",
            ".github/workflows/ci.yml",
            ".github/pull_request_template.md",
            ".claude/settings.json",
            "guest/openclaw/package-lock.json",
            "guest/openclaw/package.json",
            "guest/openclaw/build-rootfs.sh",
            "guest/openclaw/openclaw.json5",
            "guest/openclaw/launch.json",
            "guest/builder/launch.json",
            "guest/builder/build-rootfs.sh",
            "guest/codex/agentos-toolsh",
            "guest/codex/managed_config.toml",
            "guest/codex/requirements.toml",
            "guest/codex/launch.json",
            "broker/cmd/agentos-modem/agentos-modem.service",
            "broker/attention/systemd/x.conf",
            "broker/attention/x.socket",
            "broker/attention/x.timer",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path)[0], "A")
        # Under spikes/, a unit file is a sketch, not something the image runs.
        self.assertEqual(rt.tier_of("spikes/S1/systemd/x.service")[0], "C")

    # RT-1a (briefs/RT-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_every_image_file_and_unit_in_the_tree_is_a(self):
        # Walks the tree, so a new image file or unit cannot slip in below A.
        found = []
        for dirpath, dirs, files in os.walk(ROOT):
            rel = pathlib.Path(dirpath).relative_to(ROOT)
            dirs[:] = [d for d in dirs if not (rel == pathlib.Path(".") and d in (".git", "spikes"))]
            for f in files:
                p = (rel / f).as_posix()
                in_mkosi = p.startswith("image/mkosi/")
                unit = f.endswith((".service", ".socket", ".timer")) or (
                    "systemd" in rel.parts and f.endswith(".conf"))
                if in_mkosi or unit:
                    found.append(p)
        self.assertIn("image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service", found)
        self.assertIn("broker/cmd/agentos-localui/agentos-localui.service", found)
        below = [p for p in found if rt.tier_of(p)[0] != "A"]
        self.assertEqual(below, [])

    # RT-1b (briefs/RT-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_explicit_c_list_and_unmatched_default_b(self):
        cases = {
            "newdir/x": "B",
            "newdir/x.md": "B",
            ".gitignore": "B",
            "docs/x.md": "C",
            "briefs/x.md": "C",
            "reviews/l3/2026-10-15-pr1.md": "C",
            "decisions/D-001.md": "C",
            "tests/test_x.py": "C",
            "tools/trace.py": "C",
            "tools/ASSUMPTIONS.md": "C",
            "image/README.md": "C",
            "image/ASSUMPTIONS.md": "C",
            "README.md": "C",
            "LATER.md": "C",
            "CLAUDE.md": "C",
            "LEDGER.md": "C",
            "METRICS.md": "C",
            "TRACE.md": "C",
            "SPEC.md": "B",
            # A .md below the top level of image/ is not documentation-only.
            "image/mkosi/x.md": "A",
        }
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path)[0], want)

    # RT-1a (briefs/RT-1.md; a local ID with no SPEC row, so no REQ marker)
    def test_moving_a_tier_a_file_out_keeps_tier_a(self):
        with tempfile.TemporaryDirectory() as d:
            def git(*args):
                subprocess.run(["git", "-C", d, *args], check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.invalid")
            git("config", "user.name", "t")
            os.makedirs(os.path.join(d, "image"))
            with open(os.path.join(d, "image", "build.sh"), "w") as f:
                f.write("echo build\n" * 20)
            git("add", ".")
            git("commit", "-qm", "base")
            os.makedirs(os.path.join(d, "docs"))
            git("mv", "image/build.sh", "docs/build.sh")
            git("commit", "-qm", "move")
            cwd = os.getcwd()
            os.chdir(d)
            try:
                paths = rt.changed_paths("HEAD~1", "HEAD")
            finally:
                os.chdir(cwd)
        self.assertIn("image/build.sh", paths)
        self.assertEqual(rt.tier_of_change(paths)[0], "A")

    def _base_merge_repo(self, d, side_path=None):
        """main gains a tier-A file after the PR branches; the PR (a docs edit) merges main in.

        With side_path, the PR also merges a non-main branch that adds that path.
        """
        def git(*args):
            return subprocess.run(["git", "-C", d, "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
                                  check=True, capture_output=True, text=True).stdout.strip()

        def add(path, text, msg):
            os.makedirs(os.path.join(d, os.path.dirname(path)), exist_ok=True)
            with open(os.path.join(d, path), "w") as f:
                f.write(text)
            git("add", ".")
            git("commit", "-qm", msg)

        git("init", "-q", "-b", "main")
        add("docs/x.md", "x\n", "base")
        git("checkout", "-q", "-b", "pr")
        add("docs/x.md", "x pr\n", "pr")
        git("checkout", "-q", "main")
        add("image/build.sh", "echo main\n", "main moves")
        if side_path:
            git("checkout", "-q", "-b", "side", "pr")
            add(side_path, "side\n", "side")
        git("checkout", "-q", "pr")
        git("merge", "-q", "--no-edit", "main")
        if side_path:
            git("merge", "-q", "--no-edit", "side")

    def _paths(self, d, base, head):
        cwd = os.getcwd()
        os.chdir(d)
        try:
            return rt.changed_paths(base, head)
        finally:
            os.chdir(cwd)

    def test_a_merge_of_main_does_not_raise_the_tier(self):
        # #1636: lines that arrived with a base merge are not the PR's own.
        with tempfile.TemporaryDirectory() as d:
            self._base_merge_repo(d)
            paths = self._paths(d, "main", "pr")
        self.assertEqual(paths, ["docs/x.md"])
        self.assertEqual(rt.tier_of_change(paths)[0], "C")

    def test_a_side_branch_merged_in_still_counts(self):
        # No false pass: only main's history is excluded, not any merged branch.
        with tempfile.TemporaryDirectory() as d:
            self._base_merge_repo(d, side_path=".github/workflows/x.yml")
            paths = self._paths(d, "main", "pr")
        self.assertEqual(sorted(paths), [".github/workflows/x.yml", "docs/x.md"])
        self.assertEqual(rt.tier_of_change(paths)[0], "A")

    def test_paths_git_would_quote_keep_tier_a(self):
        # git diff quotes names with non-ASCII bytes, quotes, tabs, backslashes
        # or newlines; the quoted form would match no A prefix and fall to B.
        names = ["image/mkosi/\u00e9", "image/a\tb", "image/a\\b", '.github/workflows/a"b.yml', "image/build\nx.sh"]
        with tempfile.TemporaryDirectory() as d:
            def git(*args):
                subprocess.run(["git", "-C", d, *args], check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.invalid")
            git("config", "user.name", "t")
            git("commit", "-q", "--allow-empty", "-m", "base")
            for n in names:
                os.makedirs(os.path.join(d, os.path.dirname(n)), exist_ok=True)
                with open(os.path.join(d, n), "w") as f:
                    f.write("x\n")
            git("add", ".")
            git("commit", "-qm", "add")
            cwd = os.getcwd()
            os.chdir(d)
            try:
                paths = rt.changed_paths("HEAD~1", "HEAD")
            finally:
                os.chdir(cwd)
        self.assertEqual(sorted(paths), sorted(names))
        for n in names:
            self.assertEqual(rt.tier_of(n)[0], "A", n)

    def test_highest_tier_wins(self):
        tier, why = rt.tier_of_change(["docs/a.md", "broker/attention/x.go", "broker/vault/y.go"])
        self.assertEqual((tier, why), ("A", ["broker/vault/y.go"]))
        self.assertEqual(rt.tier_of_change(["docs/a.md", "broker/budget/q.go"])[0], "B")
        self.assertEqual(rt.tier_of_change([]), ("C", []))

    def test_every_tier_a_package_exists(self):
        # A renamed package must not silently drop to tier B.
        missing = [p for p in sorted(rt.TIER_A_BROKER) if not (ROOT / "broker" / p).is_dir()]
        self.assertEqual(missing, [])

    # Tier-A-narrow (#1698; a work item with no SPEC row, so no REQ marker): a
    # broker package beyond core.txt is A only if it (a) handles a credential
    # or secret, (b) gates an effect or approval, or (c) parses owner-channel
    # input; the rest of broker/ is B.
    def test_tier_a_narrow_criteria(self):
        cases = {
            # (a) tpmseal seals the vault key-encryption key to the TPM.
            "broker/tpmseal/seal.go": ("A", "broker/tpmseal/"),
            # (b) update verifies and applies signed releases.
            "broker/update/update.go": ("A", "broker/update/"),
            # (c) owner parses the owner's texted commands.
            "broker/owner/owner.go": ("A", "broker/owner/"),
            # (b) hostdisk's udev rules hide host disks from every service.
            "broker/hostdisk/udev/59-agentos-host-disks.rules": ("A", "broker/hostdisk/"),
            # demoted: cgroup sets memory and CPU limits and gates nothing.
            "broker/cgroup/cgroup.go": ("B", "broker/cgroup/"),
            # core.txt packages stay A regardless, without a TIER_A_BROKER entry.
            "broker/vault/vault.go": ("A", "core list: broker/vault/"),
            # third-party source compiled into the broker stays A.
            "broker/vendor/modules.txt": ("A", "broker/vendor/"),
            "broker/third_party/go-imap/imap.go": ("A", "broker/third_party/"),
            # a package in no list, or a file at the module root, is A.
            "broker/newpkg/x.go": ("A", "unlisted broker path"),
            "broker/x.go": ("A", "unlisted broker path"),
        }
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path), want)
        for pkg in ("cgroup", "corpus", "hostchange", "machprobe"):
            with self.subTest(demoted=pkg):
                self.assertIn(pkg, rt.TIER_B_BROKER)
                self.assertEqual(rt.tier_of(f"broker/{pkg}/x.go")[0], "B")
        # The issue's criterion examples are listed by criterion, not only
        # through a core.txt allow line that a refactor could remove.
        for pkg in ("control", "apply", "recovery", "smsapi", "sipsign", "card"):
            with self.subTest(listed=pkg):
                self.assertIn(pkg, rt.TIER_A_BROKER)
        # Security #1700 delta f1/f2 and P/UX/L3 delta f1 (#1654): durable
        # writes keys, the vault and root.json (a); boxname parses the owner's
        # NAME text and runs the CH-21 check (c); events and recall hold
        # CRED-1 custody (a). Each is listed by criterion and is never B.
        for pkg in ("durable", "boxname", "events", "recall"):
            with self.subTest(promoted=pkg):
                self.assertIn(pkg, rt.TIER_A_BROKER)
                self.assertNotIn(pkg, rt.TIER_B_BROKER)
                self.assertEqual(rt.tier_of(f"broker/{pkg}/x.go"), ("A", f"broker/{pkg}/"))

    def test_every_broker_package_is_classed_once(self):
        # Each broker/ directory is tier A (listed or in core.txt) or in
        # TIER_B_BROKER, never both; TIER_A_BROKER repeats no core or wiring
        # package. A new directory fails here until it is classed.
        core, wiring, allowed = rt.core_list()
        in_core = {n.split("/")[0] for n in core | wiring | allowed}
        a = rt.TIER_A_BROKER | in_core
        dirs = {d.name for d in (ROOT / "broker").iterdir() if d.is_dir()}
        dirs -= {pre.split("/")[1] for pre in rt.TIER_A_BROKER_PREFIXES}
        self.assertEqual(sorted(dirs - a - rt.TIER_B_BROKER), [])
        self.assertEqual(sorted(a & rt.TIER_B_BROKER), [])
        self.assertEqual(sorted(rt.TIER_B_BROKER - dirs), [])
        self.assertEqual(sorted(rt.TIER_A_BROKER & (core | wiring)), [])

    # REQ: ONB-3 (P2-2w c3: netjoin writes the home Wi-Fi PSK, so it is tier A)
    def test_netjoin_is_tier_a(self):
        self.assertIn("netjoin", rt.TIER_A_BROKER)
        self.assertEqual(rt.tier_of("broker/netjoin/join.go")[0], "A")

    # REQ: HW-10 (CTRL-claim-tier, CTRL-claim-wire: OPERATING §3 and TIER_A_BROKER agree on claim and firstboot)
    def test_merge_gate_tools_tests_and_lens_rules_are_a(self):
        # Security on #1953: paths that left premerge's Mark-only list keep the full review.
        for f in ("tools/premerge.py", "tests/test_premerge.py", "tests/test_risk_tier_custody.py",
                  "tests/test_ci_scope.py", "tests/test_g1_scope.py", "tests/test_workflows.py",
                  "tests/test_merge_queue.py", "tests/test_lane.py", "reviews/l3/README.md",
                  "reviews/security/README.md"):
            self.assertEqual(rt.tier_of(f)[0], "A", f)
        for f in ("reviews/l3/2026-10-15-pr1.md", "reviews/README.md", "tests/test_records.py"):
            self.assertNotEqual(rt.tier_of(f)[0], "A", f)

    def test_operating_tier_a_list_agrees_with_tier_a_broker(self):
        text = (ROOT / "docs" / "OPERATING.md").read_text()
        row = next(l for l in text.splitlines() if l.startswith("| **A** |"))
        listed = row.split("(", 1)[1].split(")", 1)[0]
        listed = listed.split(", plus ", 1)[0]
        names = set()
        for item in listed.replace("; ", ", ").split(", "):
            item = item.split(": ", 1)[-1]  # drop the criterion label
            names.update(n.rstrip("*") for n in item.split("/"))
        # Every name is a real package, so a label cannot pass as one.
        missing = [n for n in sorted(names)
                   if not (ROOT / "broker" / n).is_dir()]
        self.assertEqual(missing, [])
        self.assertIn("claim", names)
        self.assertIn("claim", rt.TIER_A_BROKER)
        self.assertIn("firstboot", names)
        self.assertIn("firstboot", rt.TIER_A_BROKER)
        # Every package OPERATING names as tier A is tier A in the tool
        # (modem* covers modem and modemlink).
        not_a = [n for n in sorted(names)
                 if rt.tier_of("broker/" + n + "/x.go")[0] != "A"]
        self.assertEqual(not_a, [])

    # REQ: ARC-1 (SIM-core: the trusted core is the list in broker/core/core.txt)
    def test_core_list_rates_core_and_wiring_a(self):
        core, wiring, _ = rt.core_list()
        self.assertIn("journal", core)
        self.assertIn("cmd/agentosd", wiring)
        cases = {
            # core packages that no other rule makes A
            "broker/childproc/childproc.go": "A",
            "broker/meter/meter.go": "A",
            "broker/guesterr/guesterr.go": "A",
            # the list and its check decide what is core
            "broker/core/core.txt": "A",
            "broker/core/core_test.go": "A",
            # a broker package in neither the core nor TIER_A_BROKER
            "broker/attention/attention.go": "B",
        }
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path)[0], want)
        for pkg in sorted(core | wiring):
            with self.subTest(pkg=pkg):
                self.assertEqual(rt.tier_of(f"broker/{pkg}/x.go")[0], "A")
                self.assertTrue((ROOT / "broker" / pkg).is_dir(), pkg)

    # REQ: ARC-1 (SIM-core-allow-tier: a package an allow line lets call a
    # core write path is itself a core write path, so it is tier A)
    def test_allow_line_packages_are_a(self):
        allowed = rt.core_list()[2]
        # recalltool holds journal.Engine.Erase and grants.Gate.Withdraw/Authorize.
        self.assertIn("recall", allowed)
        self.assertIn("recalltool", allowed)
        self.assertEqual(rt.tier_of("broker/recalltool/tool.go"),
                         ("A", "core list: broker/recalltool/"))
        # recall also meets criterion (a) (CRED-1 custody), so TIER_A_BROKER
        # names it and its reason shows first.
        self.assertEqual(rt.tier_of("broker/recall/recall.go"), ("A", "broker/recall/"))
        for pkg in sorted(allowed):
            with self.subTest(pkg=pkg):
                self.assertEqual(rt.tier_of(f"broker/{pkg}/x.go")[0], "A")
                self.assertTrue((ROOT / "broker" / pkg).is_dir(), pkg)

    def test_allow_line_parsing_matches_core_test(self):
        # Same grammar as broker/core/core_test.go: allow <pkg> <symbol> -- <reason>.
        with tempfile.TemporaryDirectory() as d:
            ok = pathlib.Path(d) / "ok.txt"
            ok.write_text("core journal\nallow newpkg journal.Engine.Erase -- a reason\n")
            self.assertEqual(rt.core_list(ok)[2], {"newpkg"})
            for line in ("allow newpkg journal.Engine.Erase",
                         "allow newpkg journal.Engine.Erase --",
                         "allow newpkg journal.Engine.Erase because it must"):
                bad = pathlib.Path(d) / "bad.txt"
                bad.write_text("core journal\n" + line + "\n")
                with self.subTest(line=line), self.assertRaises(SystemExit):
                    rt.core_list(bad)

    def test_core_list_unreadable_fails(self):
        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d) / "core.txt"
            bad.write_text("core journal\nkernel vault\n")
            with self.assertRaises(SystemExit):
                rt.core_list(bad)
            with self.assertRaises(SystemExit):
                rt.core_list(pathlib.Path(d) / "missing.txt")

    # CTRL-lane-gate (#1300; a work item with no SPEC row, so no REQ marker): CI runs
    # `risk_tier.py --git BASE HEAD --pr-branch B --pr-title T` on every PR.
    def test_lane_gate_holds_codex_prs_to_tier_c(self):
        script = ROOT / "tools" / "risk_tier.py"
        with tempfile.TemporaryDirectory() as d:
            def git(*args):
                subprocess.run(["git", "-C", d, *args], check=True, capture_output=True)
            git("init", "-q", "-b", "main")
            git("config", "user.email", "t@example.invalid")
            git("config", "user.name", "t")
            pathlib.Path(d, "README.md").write_text("x\n")
            git("add", ".")
            git("commit", "-qm", "base")

            def change(branch, path):
                git("checkout", "-q", "-b", branch, "main")
                f = pathlib.Path(d, path)
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text("change\n")
                git("add", ".")
                git("commit", "-qm", branch)

            def gate(branch, title):
                return subprocess.run(
                    [sys.executable, "-I", str(script), "--git", "main", branch,
                     "--pr-branch", branch, "--pr-title", title],
                    cwd=d, capture_output=True, text=True)

            change("pkg/codex-CX-b-x", "broker/attention/x.go")    # tier B
            change("pkg/codex-CX-a-x", ".github/workflows/x.yml")  # tier A
            change("pkg/codex-CX-c-x", "docs/x.md")                # tier C
            change("claude/b-x", "broker/attention/y.go")          # tier B, peer branch
            cases = [
                ("pkg/codex-CX-b-x", "CX-b: x", 1),
                ("pkg/codex-CX-a-x", "CX-a: x", 1),
                ("pkg/codex-CX-c-x", "CX-c: x", 0),
                ("claude/b-x", "P-1: x", 0),
                # A CX- title puts the PR in the lane whatever its branch.
                ("claude/b-x", "CX-b: x", 1),
            ]
            for branch, title, want in cases:
                with self.subTest(branch=branch, title=title):
                    r = gate(branch, title)
                    self.assertEqual(r.returncode, want, r.stdout + r.stderr)
                    if want:
                        self.assertIn("codex lane is limited to tier C", r.stderr)

    def test_lane_of(self):
        self.assertEqual(rt.lane_of("pkg/codex-CX-name-case-1", ""), "codex")
        self.assertEqual(rt.lane_of("", " CX-name-case: x"), "codex")
        self.assertIsNone(rt.lane_of("pkg/ctrl-lane-gate-w7vxj3", "CTRL-lane-gate: x"))
        self.assertIsNone(rt.lane_of("claude/x", "X: codex"))
        self.assertIsNone(rt.lane_of(None, None))
        self.assertTrue(rt.lane_gate("pkg/codex-x", "", "C")[0])
        self.assertFalse(rt.lane_gate("pkg/codex-x", "", "B")[0])
        self.assertTrue(rt.lane_gate("claude/x", "", "A")[0])

    def _uncommitted_repo(self, d):
        """main at one commit; the checkout is main with nothing committed ahead."""
        def git(*args):
            subprocess.run(["git", "-C", d, "-c", "user.email=t@example.invalid", "-c", "user.name=t", *args],
                           check=True, capture_output=True)
        git("init", "-q", "-b", "main")
        os.makedirs(os.path.join(d, "docs"))
        os.makedirs(os.path.join(d, "image"))
        for p in ("docs/x.md", "image/build.sh"):
            with open(os.path.join(d, p), "w") as f:
                f.write("x\n")
        git("add", ".")
        git("commit", "-qm", "base")
        return git

    def _run(self, d, *args):
        return subprocess.run([sys.executable, str(ROOT / "tools" / "risk_tier.py"), *args],
                              cwd=d, capture_output=True, text=True)

    # RT-3a (briefs/RT-3.md; a local ID with no SPEC row, so no REQ marker)
    def test_uncommitted_changes_count_against_head(self):
        # #2272: a run before the first commit printed a bare C.
        cases = {
            "unstaged": lambda d, git: open(os.path.join(d, "image", "build.sh"), "a").write("y\n"),
            "staged": lambda d, git: (open(os.path.join(d, "image", "build.sh"), "a").write("y\n"),
                                      git("add", "image/build.sh")),
            "untracked": lambda d, git: open(os.path.join(d, "image", "new.sh"), "w").write("y\n"),
            # The commit takes the index, not the worktree.
            "staged then removed": lambda d, git: (open(os.path.join(d, "image", "new.sh"), "w").write("y\n"),
                                                   git("add", "image/new.sh"),
                                                   os.remove(os.path.join(d, "image", "new.sh")),
                                                   open(os.path.join(d, "docs", "y.md"), "w").write("z\n")),
        }
        for name, change in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                git = self._uncommitted_repo(d)
                change(d, git)
                r = self._run(d, "--git", "main", "HEAD")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.split()[0], "A", r.stdout)
                r = self._run(d, "--git", "main")  # HEAD by default
                self.assertEqual(r.stdout.split()[0], "A", r.stdout)
                # From a subdirectory, changes outside it still count.
                for sub in ("docs", "image"):
                    r = self._run(os.path.join(d, sub), "--git", "main", "HEAD")
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(r.stdout.split()[0], "A", r.stdout)

    # RT-3b
    def test_empty_diff_prints_no_tier(self):
        with tempfile.TemporaryDirectory() as d:
            git = self._uncommitted_repo(d)
            for args in (["--git", "main", "HEAD"], ["--git", "main", "--markdown"]):
                with self.subTest(args=args):
                    r = self._run(d, *args)
                    self.assertEqual(r.returncode, 2)
                    self.assertEqual(r.stdout, "")
                    self.assertIn("no changes between main and HEAD", r.stderr)
            # A named head commit ignores the working tree, as CI's runs do.
            open(os.path.join(d, "image", "build.sh"), "a").write("y\n")
            git("tag", "t")
            r = self._run(d, "--git", "main", "t")
            self.assertEqual(r.returncode, 2)
            self.assertEqual(r.stdout, "")

    # RT-3b-1, RT-3b-2 (briefs/RT-3b.md; local IDs with no SPEC row, so no REQ marker)
    def test_diff_relative_config_does_not_drop_paths(self):
        # diff.relative=true lists only paths under the cwd: from docs/ the
        # image/ change fell out and the docs file set the tier.
        with tempfile.TemporaryDirectory() as d:
            git = self._uncommitted_repo(d)
            git("config", "diff.relative", "true")
            git("tag", "base")
            for p in ("image/build.sh", "docs/x.md"):
                open(os.path.join(d, p), "a").write("y\n")
            git("commit", "-qam", "change")
            git("tag", "change")
            r = self._run(os.path.join(d, "docs"), "--git", "base", "HEAD")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.split()[0], "A", r.stdout)
            # A named head skips the working-tree calls, so only the
            # committed call can see image/.
            r = self._run(os.path.join(d, "docs"), "--git", "base", "change")
            self.assertEqual(r.stdout.split()[0], "A", r.stdout)

    def test_diff_relative_config_keeps_uncommitted_paths(self):
        cases = {
            # Staged then removed: only the index (--cached) still has it.
            "staged": lambda d, git: (open(os.path.join(d, "image", "new.sh"), "w").write("y\n"),
                                      git("add", "image/new.sh"),
                                      os.remove(os.path.join(d, "image", "new.sh"))),
            "unstaged": lambda d, git: open(os.path.join(d, "image", "build.sh"), "a").write("y\n"),
        }
        for name, change in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                git = self._uncommitted_repo(d)
                git("config", "diff.relative", "true")
                change(d, git)
                open(os.path.join(d, "docs", "x.md"), "a").write("y\n")
                r = self._run(os.path.join(d, "docs"), "--git", "main", "HEAD")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertEqual(r.stdout.split()[0], "A", r.stdout)

    def test_markdown_output(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rt.main(["--markdown", "broker/vault/v.go"])
        self.assertIn("Risk tier A", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
