"""Agent side of S5: talks to executor.py only through the v0 protocol on its stdio.

Task scripts see protocol responses and nothing else; `find` picks refs out of a
snapshot by role and accessible name, as a model would.
"""
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent


class StepFailed(RuntimeError):
    pass


class Session:
    def __init__(self, origins, workspace, storage_state=None):
        cmd = [sys.executable, str(HERE / "executor.py"), "--workspace", str(workspace),
               "--origins", *origins]
        if storage_state:
            cmd += ["--storage-state", str(storage_state)]
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     text=True, bufsize=1)
        self.log = []
        self.raw = []  # every response line, for canary checks
        self.snap = None

    def call(self, verb, **args):
        req = {"v": 0, "verb": verb, **args}
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise StepFailed("executor exited")
        self.raw.append(line)
        res = json.loads(line)
        self.log.append({"req": req, "res": {k: v for k, v in res.items() if k != "snapshot"}})
        if verb == "snapshot" and res.get("ok"):
            self.snap = res
        return res

    def do(self, verb, **args):
        res = self.call(verb, **args)
        if not res.get("ok"):
            raise StepFailed(f"{verb} {args}: {res.get('error')} {res.get('detail', '')}")
        return res

    def look(self):
        return self.do("snapshot")

    def ref(self, role, name=None, nth=0):
        """Ref of the nth node with this role whose name matches the regex `name`."""
        refs = find(self.snap["snapshot"], role, name)
        if len(refs) <= nth:
            raise StepFailed(f"no {role} {name!r} in snapshot of {self.snap['url']}")
        return refs[nth]

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=30)


NODE = re.compile(r"""- '?(?P<role>[\w-]+)(?: "(?P<name>(?:[^"\\]|\\.)*)")?[^\n]*?\[ref=(?P<ref>(?:f\d+)?e\d+)\]""")


def find(snapshot, role, name=None):
    out = []
    for m in NODE.finditer(snapshot):
        if m.group("role") != role:
            continue
        if name is not None and not re.search(name, m.group("name") or "", re.I):
            continue
        out.append(m.group("ref"))
    return out
