"""Vendored injection corpora (LOOP-7, D-067): published, licensed, pinned by
digest, and extracted without running their code."""
# REQ: LOOP-7, LOOP-9

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import corpus  # noqa: E402

CORPORA = ROOT / "assurance" / "corpora"
# The broker embeds this copy (go:embed cannot reach assurance/), so the
# signed binary carries the corpus and reads no drive file (#515 Security 3).
# It holds the vendored items and nothing else: the provenance fields carry
# the upstream URL, which depaudit's static scan of broker/ would flag.
EMBEDDED = ROOT / "broker" / "corpus" / "promptinject.json"
VENDORED = CORPORA / "promptinject" / "items.json"


def embedded_bytes(vendored: pathlib.Path) -> bytes:
    """The one rendering of a vendored items.json the broker may embed: its
    items, written as tools/corpus.py writes items.json."""
    items = json.loads(vendored.read_text())["items"]
    return (json.dumps({"items": items}, indent=1, ensure_ascii=False) + "\n").encode()


class VendoredCorpusTest(unittest.TestCase):
    def test_each_corpus_matches_its_digests_and_items(self):
        dirs = [d for d in CORPORA.iterdir() if d.is_dir()]
        self.assertTrue(dirs)
        for d in dirs:
            src = json.loads((d / "SOURCE.json").read_text())
            self.assertIn(src["license"], corpus.LICENSES)
            self.assertTrue((d / "LICENSE").is_file())
            self.assertEqual(len(src["commit"]), 40)
            corpus.verify(d)  # raises on a digest mismatch
            built = corpus.extract(d)
            self.assertEqual(json.loads((d / "items.json").read_text()), built)
            self.assertGreaterEqual(len(built["items"]), 10)

    def test_a_changed_file_fails_its_digest(self):
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            for f in ("SOURCE.json", "LICENSE", "prompt_data.py"):
                (d / f).write_bytes((CORPORA / "promptinject" / f).read_bytes())
            with open(d / "prompt_data.py", "a") as fh:
                fh.write("\n# changed\n")
            with self.assertRaises(ValueError):
                corpus.verify(d)

    def test_extraction_does_not_run_the_file(self):
        with tempfile.TemporaryDirectory() as t:
            d = pathlib.Path(t)
            data = b'import os\nos.makedirs("ran")\nx = {"a": {"label": "A", "instruction": "hi"}}\n'
            (d / "prompt_data.py").write_bytes(data)
            (d / "SOURCE.json").write_text(json.dumps({"name": "t", "url": "u", "commit": "0" * 40,
                "license": "MIT", "files": {"prompt_data.py": corpus.digest(data)}, "tables": ["x"]}))
            got = corpus.extract(d)
            self.assertFalse((d / "ran").exists())
            self.assertEqual(got["items"], [{"id": "t/x/a", "text": "hi"}])


class EmbeddedCorpusTest(unittest.TestCase):
    def assert_copy_matches(self, copy: pathlib.Path, vendored: pathlib.Path):
        self.assertEqual(copy.read_bytes(), embedded_bytes(vendored))
        self.assertEqual(json.loads(copy.read_text())["items"], json.loads(vendored.read_text())["items"])

    def test_the_embedded_copy_is_the_vendored_items(self):
        self.assert_copy_matches(EMBEDDED, VENDORED)

    def test_a_changed_byte_in_the_copy_fails(self):
        with tempfile.TemporaryDirectory() as t:
            copy = pathlib.Path(t) / "promptinject.json"
            b = bytearray(EMBEDDED.read_bytes())
            b[len(b) // 2] ^= 0x01
            copy.write_bytes(bytes(b))
            with self.assertRaises(AssertionError):
                self.assert_copy_matches(copy, VENDORED)

    def test_a_changed_vendored_item_fails(self):
        with tempfile.TemporaryDirectory() as t:
            v = json.loads(VENDORED.read_text())
            v["items"][0]["text"] += " "
            changed = pathlib.Path(t) / "items.json"
            changed.write_text(json.dumps(v))
            with self.assertRaises(AssertionError):
                self.assert_copy_matches(EMBEDDED, changed)

if __name__ == "__main__":
    unittest.main()
