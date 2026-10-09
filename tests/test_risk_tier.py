import contextlib
import io
import pathlib
import sys
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
            "broker/mail/deliver.go": "A",
            "broker/daemon/daemon.go": "A",
            "broker/cmd/agentosd/main.go": "A",
            "broker/sockprobe/probe.go": "A",
            "broker/loop7/loop7.go": "B",
            "broker/recall/index.go": "B",
            "broker/newpkg/x.go": "B",
            "guest/openclaw/Dockerfile": "B",
            "SPEC.md": "B",
            "docs/owners-guide.md": "C",
            "tools/trace.py": "C",
            ".github/workflows/ci.yml": "C",
            "spikes/S8-provider-workers/README.md": "C",
            "BOARD.md": "C",
        }
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path)[0], want)

    def test_highest_tier_wins(self):
        tier, why = rt.tier_of_change(["docs/a.md", "broker/recall/x.go", "broker/vault/y.go"])
        self.assertEqual((tier, why), ("A", ["broker/vault/y.go"]))
        self.assertEqual(rt.tier_of_change(["docs/a.md", "broker/route/r.go"])[0], "B")
        self.assertEqual(rt.tier_of_change([]), ("C", []))

    def test_every_tier_a_package_exists(self):
        # A renamed package must not silently drop to tier B.
        missing = [p for p in sorted(rt.TIER_A_BROKER) if not (ROOT / "broker" / p).is_dir()]
        self.assertEqual(missing, [])

    def test_markdown_output(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rt.main(["--markdown", "broker/vault/v.go"])
        self.assertIn("Risk tier A", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
