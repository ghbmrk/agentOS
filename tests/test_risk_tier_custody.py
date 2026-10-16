"""CRED-1 custody paths are tier A by their own rule (RECALL-canary-5, #885).

broker/recall/scrub.go was tier A only because recall has "shape only" allow
lines in broker/core/core.txt; dropping them would have rated a change to the
scrubber B, so a Sonnet-pilot builder and a lighter review would follow. The
scrubber, the vault's redactors and every file that wires one in are rated A by
TIER_A_BROKER (events and recall under criterion (a), CRED-1 custody) or the
core list (vault), and a new one outside a tier-A package fails here.
"""
import pathlib
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import risk_tier as rt  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

# A file that defines a scrubber or redactor, or builds or wires one in, holds
# CRED-1 custody: an edit to it can let authentication material reach the
# recall index, the event log or a model-readable channel.
CUSTODY = re.compile(
    r"^type \w*(?:Scrubber|Redactor)\b"
    r"|\bNewScrubber\("
    r"|\bNew(?:Hash)?Redactor\("
    r"|\bWithVaultRedactor\b",
    re.M,
)


def custody_files():
    out = []
    for p in sorted((ROOT / "broker").rglob("*.go")):
        if p.name.endswith("_test.go"):
            continue
        if CUSTODY.search(p.read_text(errors="replace")):
            out.append(p.relative_to(ROOT).as_posix())
    return out


class CustodyTierTest(unittest.TestCase):
    # REQ: CRED-1, CRED-7
    def test_scrubber_and_vault_redactor_are_a(self):
        for path, rule in (
            ("broker/vault/redact.go", "core list: broker/vault/"),
            ("broker/vault/hashredact.go", "core list: broker/vault/"),
            ("broker/events/bus.go", "broker/events/"),
        ):
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path), ("A", rule))
        for path in ("broker/recall/scrub.go", "broker/recall/letters.bin",
                     "broker/recall/recall.go"):
            with self.subTest(path=path):
                self.assertEqual(rt.tier_of(path), ("A", "broker/recall/"))

    # REQ: CRED-1
    def test_scrubber_stays_a_without_the_core_list_allow_lines(self):
        core, wiring, allowed = rt.core_list()
        stripped = (core, wiring, allowed - {"recall", "events", "vault"})
        with mock.patch.object(rt, "core_list", return_value=stripped):
            for path, rule in (
                ("broker/recall/scrub.go", "broker/recall/"),
                ("broker/recall/letters.bin", "broker/recall/"),
                ("broker/events/bus.go", "broker/events/"),
                # vault is a core package, not an allow line, so it stays.
                ("broker/vault/hashredact.go", "core list: broker/vault/"),
            ):
                with self.subTest(path=path):
                    self.assertEqual(rt.tier_of(path), ("A", rule))
            self.assertEqual(rt.tier_of_change(["docs/a.md", "broker/recall/scrub.go"]),
                             ("A", ["broker/recall/scrub.go"]))

    # REQ: CRED-1, CRED-7
    def test_every_file_holding_a_scrubber_or_redactor_is_a(self):
        files = custody_files()
        # The scan finds the files this package is about, so a rename that
        # hides them from the pattern fails here rather than passing empty.
        for want in ("broker/recall/scrub.go", "broker/recall/recall.go",
                     "broker/vault/redact.go", "broker/vault/hashredact.go",
                     "broker/events/bus.go"):
            self.assertIn(want, files)
        not_a = [p for p in files if rt.tier_of(p)[0] != "A"]
        self.assertEqual(not_a, [], "add the package to TIER_A_BROKER (CRED-1 custody)")

    def test_pattern_matches_the_shapes_it_names(self):
        for src in ("type Scrubber struct {", "type HashRedactor struct {",
                    "type Redactor func(string) string", "s := recall.NewScrubber(nil)",
                    "r := vault.NewHashRedactor(v)", "events.WithVaultRedactor(r)"):
            with self.subTest(src=src):
                self.assertTrue(CUSTODY.search(src))
        for src in ("// the scrubber runs first", "func redactAll(s string) string {"):
            with self.subTest(src=src):
                self.assertFalse(CUSTODY.search(src))


if __name__ == "__main__":
    unittest.main()
