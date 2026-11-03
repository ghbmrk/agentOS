"""Keep git's background work out of temporary test repositories (#4811, #4815).

A `git commit` may start a detached `git maintenance run --auto` (gc, geometric repack) that writes
into `.git/objects` while `TemporaryDirectory` removes the repository: `OSError: [Errno 39] Directory
not empty`. A test module that commits in a temporary repository adds, after its imports:

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from _nogit_bg import setUpModule, tearDownModule  # noqa: E402,F401

Entries append to any GIT_CONFIG_* the caller already set, and tearDownModule restores the old env.
"""
import os

_SETTINGS = (("gc.auto", "0"), ("maintenance.auto", "false"))
_saved = {}


def setUpModule():
    _saved.clear()
    n = int(os.environ.get("GIT_CONFIG_COUNT") or 0)
    entries = {"GIT_CONFIG_COUNT": str(n + len(_SETTINGS))}
    for i, (k, v) in enumerate(_SETTINGS, start=n):
        entries[f"GIT_CONFIG_KEY_{i}"] = k
        entries[f"GIT_CONFIG_VALUE_{i}"] = v
    for k, v in entries.items():
        _saved[k] = os.environ.get(k)
        os.environ[k] = v


def tearDownModule():
    for k, old in _saved.items():
        if old is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = old
    _saved.clear()
