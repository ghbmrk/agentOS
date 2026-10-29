"""Every gate-list reader in tools/ refuses a hidden line break (REV-CHK-crlf, #3902).

No requirement IDs: assurance tooling (D-086). A list file read with read_text() (which turns
"\\r" into "\\n") or split with splitlines() (which also ends a line at U+0085, U+2028, U+2029,
form feed and others) shows one line in an editor or a diff and gives the reader two, so a
break hidden in a comment can add a `core`, `allow` or baseline line nobody sees (#1347, #1583,
#3721). Each reader splits on "\\n" only and refuses any character outside printable ASCII,
as tools/g1_scope.py does, naming the line.

CASES maps each list file to the functions that read it, each called on a tree holding a
copy of the list. A new tools/*.txt with no case fails test_every_list_file_has_a_reader_case.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import assumptions_ids  # noqa: E402
import doclint  # noqa: E402
import g1_scope  # noqa: E402
import netguardcheck  # noqa: E402
import risk_tier  # noqa: E402
import trace  # noqa: E402
import trusted_base  # noqa: E402


def _old_core_dirs(tree):
    # trace.py reads the list through git (git_tree), so commit the copy and read it back the same way.
    git = ["git", "-C", str(tree), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(git[:3] + ["init", "-q"], check=True)
    subprocess.run(git + ["add", trace.OLD_CORE], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "list"], check=True)
    return trace.old_core_dirs(trace.git_tree(tree, "HEAD"))


def _legacy_growth(tree):
    clean = (ROOT / assumptions_ids.LEGACY).read_bytes().decode("utf-8")
    return list(assumptions_ids.growth(tree, clean))


def _g2_list(tree):
    # As g1_scope.main reads it.
    text = (tree / "tools" / "g1_scope_g2.txt").read_bytes().decode("utf-8", "replace")
    return g1_scope.parse_list(text, "g1_scope_g2.txt")


CASES = {
    "broker/core/core.txt": {
        "risk_tier.core_list": lambda t: risk_tier.core_list.__wrapped__(t / "broker/core/core.txt"),
        "trusted_base.trusted_mains": trusted_base.trusted_mains,
    },
    "tools/trusted_core.txt": {"trusted_base.read_core": trusted_base.read_core},
    "tools/trusted_base_parsers.txt": {"trusted_base.read_rules": lambda t: trusted_base.read_rules(t, True)},
    "tools/old_core.txt": {"trace.old_core_dirs": _old_core_dirs},
    "tools/assumptions_legacy_ids.txt": {
        "assumptions_ids.legacy": assumptions_ids.legacy,
        "assumptions_ids.growth": _legacy_growth,
    },
    "tools/brief_acceptance_baseline.txt": {"doclint.brief_baseline": doclint.brief_baseline},
    "tools/netguard_allow.txt": {"netguardcheck.load_allow": lambda t: netguardcheck.load_allow(t / "tools/netguard_allow.txt")},
    "tools/g1_scope_g2.txt": {"g1_scope.parse_list": _g2_list},
}

# Each is a line end to some reader (read_text, splitlines or str.split) or a character a
# reader may drop, so a line holding one can mean other than it shows.
BREAKS = {
    "lone CR": "\r",
    "CRLF": "\r\n",
    "NEL U+0085": "\x85",
    "LS U+2028": " ",
    "PS U+2029": " ",
    "NUL": "\0",
    "form feed": "\f",
}


def reads(name, reader, text):
    """Run reader on a tree holding `text` as list `name`; return its error text, or None."""
    with tempfile.TemporaryDirectory() as d:
        tree = pathlib.Path(d)
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_bytes(text.encode("utf-8"))
        try:
            reader(tree)
        except SystemExit as e:
            return str(e.code)
        except (trusted_base.MeasureError, g1_scope.ListError) as e:
            return str(e)
        return None


def targets(lines):
    """Line numbers to break: the first line (a comment in most lists, where #1347 hid its
    "\\r") and the first line a reader acts on."""
    first_entry = next(n for n, l in enumerate(lines, 1) if l.strip() and not l.lstrip().startswith("#"))
    return sorted({1, first_entry})


def broken(lines, n, brk):
    out = list(lines)
    line = out[n - 1]
    if brk == "\r\n":
        out[n - 1] = line + "\r"  # the "\n" join supplies the rest
    else:
        k = max(1, len(line) // 2)
        out[n - 1] = line[:k] + brk + line[k:]
    return "\n".join(out)


class ListReadersTest(unittest.TestCase):

    def test_each_list_parses_clean(self):
        # Positive control: the lists on this tree read without error.
        for name, readers in CASES.items():
            text = (ROOT / name).read_bytes().decode("utf-8")
            for rname, reader in readers.items():
                with self.subTest(list=name, reader=rname):
                    self.assertIsNone(reads(name, reader, text))

    def test_each_reader_refuses_hidden_breaks(self):
        for name, readers in CASES.items():
            lines = (ROOT / name).read_bytes().decode("utf-8").split("\n")
            for n in targets(lines):
                for bname, brk in BREAKS.items():
                    text = broken(lines, n, brk)
                    for rname, reader in readers.items():
                        with self.subTest(list=name, reader=rname, line=n, brk=bname):
                            err = reads(name, reader, text)
                            self.assertIsNotNone(err, "accepted")
                            self.assertIn(f":{n}:", err, "the refusal names the line")

    def test_every_list_file_has_a_reader_case(self):
        lists = {str(p.relative_to(ROOT)) for p in (ROOT / "tools").glob("*.txt")} | {"broker/core/core.txt"}
        self.assertEqual(sorted(lists - set(CASES)), [], "a list file with no reader case in CASES")
        self.assertEqual(sorted(set(CASES) - lists), [], "a case for a list file that is gone")

    def test_a_reader_that_splits_on_any_break_fails_the_check(self):
        # Mutation control: a splitlines() reader, as risk_tier.core_list was, is caught.
        def splitlines_reader(tree):
            for line in (tree / "tools/old_core.txt").read_text().splitlines():
                line.split()
        lines = (ROOT / "tools/old_core.txt").read_bytes().decode("utf-8").split("\n")
        self.assertIsNone(reads("tools/old_core.txt", splitlines_reader, broken(lines, 1, "\r")))


if __name__ == "__main__":
    unittest.main()
