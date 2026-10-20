#!/usr/bin/env python3
"""Every test that reads a record file is on ci.yml's records-only step (CI-docs, CI-PATHS).

A records-only change can edit any record file (tools/ci_scope.is_record), and the records step
runs a fixed test list, so every test whose outcome rests on a record must be on that list. Full
CI's unit tests run with records_site/ on PYTHONPATH and AGENTOS_RECORD_LOG set. Its
sitecustomize installs install()'s audit hook in every Python process, including subprocesses,
and the hook logs each open of a record file under the test it ran in. `records_audit.py LOG`
then fails unless the records step runs each logged test. The read is caught where it happens,
whatever code built the name. A read with no test to own it, a hook that failed to install, a
Python child that cannot load the hook (-I, -E) and an empty log all fail. Not seen: reads by
programs that are not Python (git, sh), and a record one test of a module read and cached in
memory, reused by a later test of the same module process.
"""
import importlib.util
import os
import re
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
TESTS = os.path.join(ROOT, "tests")
SITE = os.path.join(TESTS, "records_site")
LOG, OWNER = "AGENTOS_RECORD_LOG", "AGENTOS_RECORD_OWNER"
UNKNOWN = "unknown"
# Process-start audit events: the index of their argv and of their environment (None: none).
_SPAWNS = {"subprocess.Popen": (1, 3), "os.posix_spawn": (1, 2), "os.exec": (1, 2), "os.spawn": (2, 3),
           "os.system": (0, None)}
_inherited = None
_seen = set()


def records_run_tests(text=None):
    """The test names ci.yml's records-only step runs. Fails, rather than returning a partial
    list, unless exactly one records-only step runs `python -m unittest` on names, with no option
    but -v: any other option (-k, -p) could keep a listed test from running."""
    if text is None:
        with open(os.path.join(ROOT, ".github", "workflows", "ci.yml")) as f:
            text = f.read()
    lines = text.splitlines()
    steps = [i for i, l in enumerate(lines) if l.strip() == "if: env.RECORDS == 'true'"]
    runs = []
    for i in steps:
        indent = len(lines[i]) - len(lines[i].lstrip())
        end = next((j for j in range(i + 1, len(lines))
                    if lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) < indent), len(lines))
        key = next((j for j in range(i + 1, end) if lines[j].startswith(" " * indent + "run:")), None)
        if key is None:
            continue
        # The run value: inline, a block scalar, or a plain scalar continued on deeper lines.
        value = [lines[key].split(":", 1)[1]] + [l for l in lines[key + 1:end]
                                                 if len(l) - len(l.lstrip()) > indent or not l.strip()]
        words = " ".join(value).replace("\\", " ").split()
        if words[:1] in (["|"], [">"], ["|-"], [">-"]):
            words = words[1:]
        if words[:3] == ["python", "-m", "unittest"]:
            runs.append(words[3:])
    assert len(runs) == 1, f"want one records-only unittest step in ci.yml, found {len(runs)}"
    names = [w for w in runs[0] if w != "-v"]
    assert names and all(re.fullmatch(r"tests(\.\w+)+", n) for n in names), runs[0]
    return names


def _ci_scope():
    spec = importlib.util.spec_from_file_location("_records_ci_scope", os.path.join(ROOT, "tools", "ci_scope.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _test_module(filename):
    """`tests.test_x` for a frame in tests/test_x.py (`test_x` elsewhere), else None."""
    head, base = os.path.split(filename or "")
    if not (base.startswith("test_") and base.endswith(".py")):
        return None
    return ("tests." if os.path.realpath(head) == TESTS else "") + base[:-3]


def _named(cls):
    module = sys.modules.get(cls.__module__)
    return f"{_test_module(getattr(module, '__file__', None)) or cls.__module__}.{cls.__qualname__}"


def owner(frame):
    """The test a frame runs under: the innermost TestCase method (`tests.m.Class.test_x`) or
    class fixture (`tests.m.Class`), else the innermost tests/test_*.py frame (`tests.m`, an
    import), else the test that started this process, else UNKNOWN."""
    case = sys.modules.get("unittest.case")
    f = frame
    while case and f:
        for name in ("self", "cls"):
            v = f.f_locals.get(name)
            if isinstance(v, case.TestCase):
                return f"{_named(type(v))}.{v._testMethodName}"
            if isinstance(v, type) and issubclass(v, case.TestCase):
                return _named(v)
        f = f.f_back
    f = frame
    while f:
        module = _test_module(f.f_code.co_filename)
        if module:
            return module
        f = f.f_back
    return _inherited or UNKNOWN


def _write(line):
    if line in _seen:
        return
    _seen.add(line)
    fd = os.open(os.environ[LOG], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (line + "\n").encode("utf-8", "surrogateescape"))
    finally:
        os.close(fd)


def _isolated(argv):
    """A Python command line that ignores PYTHONPATH, so its process runs without the hook."""
    words = [os.fsdecode(w) for w in argv] if isinstance(argv, (list, tuple)) else str(argv).split()
    if not words or not re.fullmatch(r"python[\d.]*", os.path.basename(words[0])):
        return False
    return any(re.fullmatch(r"-[A-Za-z]*[IE][A-Za-z]*", w) for w in words[1:] if not w.startswith("--"))


def install():
    """Log every record open in this process, and carry the hook and the current test into the
    processes it starts."""
    global _inherited
    is_record = _ci_scope().is_record
    _inherited = os.environ.get(OWNER)
    paths = os.environ.get("PYTHONPATH", "").split(os.pathsep)
    if SITE not in paths:
        os.environ["PYTHONPATH"] = os.pathsep.join([SITE] + [p for p in paths if p])

    def hook(event, args):
        if event == "open":
            path = args[0]
            if isinstance(path, bytes):
                path = os.fsdecode(path)
            if not isinstance(path, str):
                return
            rel = os.path.relpath(os.path.realpath(path), ROOT).replace(os.sep, "/")
            if not rel.startswith("../") and is_record(rel):
                _write(f"{owner(sys._getframe(1))}\t{rel}")
        elif event in _SPAWNS:
            who = owner(sys._getframe(1))
            os.environ[OWNER] = who
            argv, env = _SPAWNS[event]
            argv, env = args[argv], (args[env] if env is not None else None)
            if isinstance(env, dict):
                env[OWNER] = who
                env.setdefault(LOG, os.environ[LOG])
                paths = env.get("PYTHONPATH", "").split(os.pathsep)
                if SITE not in paths:
                    env["PYTHONPATH"] = os.pathsep.join([SITE] + [p for p in paths if p])
            if _isolated(argv):
                _write(f"{who}\tisolated python: {argv!r}")

    sys.addaudithook(hook)


def related(a, b):
    """One dotted test name runs the other: a module or class runs its methods, and running a
    method imports its module and runs its class fixtures."""
    return a == b or a.startswith(b + ".") or b.startswith(a + ".")


def problems(log_text, listed):
    entries = [l.split("\t", 1) for l in log_text.splitlines() if l]
    if not entries:
        return ["no record reads logged: the audit hook did not run"]
    out = set()
    for e in entries:
        if len(e) != 2 or e[0] in (UNKNOWN, "error") or not any(related(e[0], n) for n in listed):
            out.add("\t".join(e))
    return sorted(out)


def main(argv):
    with open(argv[1], encoding="utf-8", errors="surrogateescape") as f:
        found = problems(f.read(), records_run_tests())
    for p in found:
        print(p)
    if found:
        print("Add these tests to ci.yml's records-only step (a test that reads a record must run there).",
              file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
