"""tests/_nogit_bg.py: git's background maintenance stays off in temporary test repositories (#4815)."""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _nogit_bg  # noqa: E402

KEYS = ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_KEY_1", "GIT_CONFIG_VALUE_1",
        "GIT_CONFIG_KEY_2", "GIT_CONFIG_VALUE_2")


class NoGitBackground(unittest.TestCase):
    def setUp(self):
        self.saved = {k: os.environ.pop(k, None) for k in KEYS}
        self.addCleanup(self.restore)

    def restore(self):
        for k, v in self.saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    def git_config(self, key):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["git", "-C", d, "init", "-q"], check=True, capture_output=True)
            r = subprocess.run(["git", "-C", d, "config", "--get", key], capture_output=True, text=True)
            return r.stdout.strip()

    def test_both_settings_reach_git_and_the_env_is_restored(self):
        _nogit_bg.setUpModule()
        self.assertEqual(self.git_config("gc.auto"), "0")
        self.assertEqual(self.git_config("maintenance.auto"), "false")
        _nogit_bg.tearDownModule()
        self.assertEqual({k: os.environ.get(k) for k in KEYS}, {k: None for k in KEYS})

    def test_a_caller_config_is_appended_to_never_replaced(self):
        os.environ.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "diff.noprefix", "GIT_CONFIG_VALUE_0": "true"})
        _nogit_bg.setUpModule()
        self.assertEqual(self.git_config("diff.noprefix"), "true")
        self.assertEqual(self.git_config("gc.auto"), "0")
        self.assertEqual(os.environ["GIT_CONFIG_COUNT"], "3")
        _nogit_bg.tearDownModule()
        self.assertEqual(os.environ["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(os.environ["GIT_CONFIG_KEY_0"], "diff.noprefix")
        self.assertNotIn("GIT_CONFIG_KEY_1", os.environ)


if __name__ == "__main__":
    unittest.main()
