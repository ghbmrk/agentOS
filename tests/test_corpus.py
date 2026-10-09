"""Vendored injection corpora (LOOP-7, D-067): published, licensed, pinned by
digest, and extracted without running their code."""
# REQ: LOOP-7

import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import corpus  # noqa: E402

CORPORA = ROOT / "assurance" / "corpora"


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


if __name__ == "__main__":
    unittest.main()
