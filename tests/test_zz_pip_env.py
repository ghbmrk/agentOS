"""CI-pin-build-isolation-fu (#6727): a `PIP_*` environment name counts as a fetch site.

REQ: CI-pin-liveness-1 (a pinned download is identified by its sha256, checked before use)

pip reads every `PIP_<option>` variable, and some add to what the command line asks for instead of
yielding to it: `PIP_REQUIREMENT=/abs/x.txt pip install --only-binary=:all: --require-hashes -r
requirements.txt` also reads x.txt, which can name a local sdist pip builds in isolation, fetching its
build backend unhashed. tools/pins.py therefore counts every `PIP_` name wherever it is written, so a
credited install never runs beside one this reader has not seen.
"""
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import pins  # noqa: E402

OK = "python -m pip install --no-deps --only-binary=:all: --require-hashes -r requirements.txt"


class Shell(unittest.TestCase):
    def test_the_credited_install_alone_reads_zero(self):
        self.assertEqual(pins.text_sites(OK), 0)

    def test_each_pip_variable_beside_a_credited_install_is_a_site(self):
        for var in ["PIP_REQUIREMENT=/abs/x.txt", "PIP_CONSTRAINT=c.txt", "PIP_CONFIG_FILE=/tmp/pip.conf",
                    "PIP_NO_BUILD_ISOLATION=0", "PIP_NO_BINARY=:all:", "PIP_ONLY_BINARY=:none:", "PIP_ONLY_BINARY=",
                    "PIP_INDEX_URL=https://h/simple", "PIP_EXTRA_INDEX_URL=https://h/simple", "PIP_EDITABLE=.",
                    "PIP_FIND_LINKS=/d", "PIP_CACHE_DIR=/tmp/c", "pip_requirement=x.txt", "Pip_Requirement=x.txt"]:
            for text in [var + " " + OK, "export " + var + "\n" + OK, "env " + var + " " + OK,
                         'echo "' + var + '" >> "$GITHUB_ENV"\n' + OK, var + "; " + OK]:
                with self.subTest(text=text):
                    self.assertEqual(pins.text_sites(text), 1)

    def test_a_built_or_partly_dynamic_name_is_a_site(self):
        for text in ["PIP_${X}=x.txt " + OK, "export PIP_$X=x.txt", "P{I,}P_REQUIREMENT=x.txt " + OK,
                     "${Y:-PIP_REQUIREMENT}=x", 'P""IP_REQUIREMENT=x.txt ' + OK, "unset PIP_ONLY_BINARY",
                     "read -r PIP_REQUIREMENT", "PIP_=x"]:
            with self.subTest(text=text):
                self.assertGreaterEqual(pins.text_sites(text), 1)

    def test_names_that_only_contain_pip_are_not_sites(self):
        for text in ["MYPIP_X=1 true", "XPIP_Y=1 true", "SKIP_PIP=1 true", "echo pipe_x"]:
            with self.subTest(text=text):
                self.assertEqual(pins.text_sites(text), 0)


class Workflow(unittest.TestCase):
    def test_env_at_workflow_job_and_step_level_is_a_site(self):
        step = "    steps:\n      - run: |\n          " + OK + "\n"
        for doc in ["env:\n  PIP_REQUIREMENT: /abs/x.txt\njobs:\n  a:\n" + step,
                    "jobs:\n  a:\n    env:\n      PIP_CONSTRAINT: c.txt\n" + step,
                    "jobs:\n  a:\n    steps:\n      - run: |\n          " + OK + "\n        env:\n          PIP_NO_BINARY: ':all:'\n",
                    "jobs:\n  a:\n    steps:\n      - run: |\n          " + OK + "\n        env: {PIP_INDEX_URL: 'https://h'}\n",
                    "jobs:\n  a:\n    steps:\n      - run: |\n          export PIP_ONLY_BINARY=\n          " + OK + "\n"]:
            with self.subTest(doc=doc):
                self.assertEqual(pins.yaml_sites(doc), 1)

    def test_a_name_an_expression_spells_is_a_site(self):
        # A `$` already takes the install's credit; this reads the name alone.
        for line in ["${{ 'PIP' }}_REQUIREMENT=x true", "${{ 'P' }}IP_X=1 true", "${{ 'pip' }}_x=1 true"]:
            with self.subTest(line=line):
                self.assertGreaterEqual(pins.yaml_sites("jobs:\n  a:\n    steps:\n      - run: " + line + "\n"), 1)

    def test_the_same_step_without_the_variable_reads_zero(self):
        self.assertEqual(pins.yaml_sites("jobs:\n  a:\n    steps:\n      - run: |\n          " + OK + "\n"), 0)


class Python(unittest.TestCase):
    def test_a_pip_variable_set_from_python_is_a_site(self):
        for src in ['import os\nos.environ["PIP_REQUIREMENT"] = "x.txt"\n',
                    'import os\nos.environ.update(PIP_REQUIREMENT="x.txt")\n',
                    'import subprocess\nsubprocess.run(["true"], env=dict(PIP_NO_BINARY=":all:"))\n',
                    'import os\nos.putenv("PIP_CONFIG_FILE", "/tmp/c")\n']:
            with self.subTest(src=src):
                self.assertEqual(pins.py_sites(src), 1)

    def test_a_python_name_is_not_a_site(self):
        self.assertEqual(pins.py_sites("PIP_MAX = 3\nprint(PIP_MAX)\n"), 0)


if __name__ == "__main__":
    unittest.main()
