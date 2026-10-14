# The Codex provider worker's defensive half (S8-W1, #807 split): the managed config that keeps
# hosted tools off and points the CLI at the in-worker forwarder, and agentos-toolsh, the bwrap
# prefix that cuts Codex's tool subprocesses off from the forwarder's loopback port, the egress
# socket under /run and the placeholder auth.json in CODEX_HOME. Stub CLI and stub tool only, with
# a synthetic canary; no real CLI, no login, no adversarial content (the containment test with the
# pinned CLI stays for the supervised session, D-064).
# REQ: CRED-5, CRED-1, A14, CAP-11
#
# The sandbox half needs root and /usr/bin/bwrap; it skips without them, and fails instead when
# AGENTOS_REQUIRE_BWRAP=1 (CI runs it that way under sudo in the checks job).
import copy
import json
import os
import pathlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CODEX = ROOT / "guest/codex"
CONFIG = CODEX / "managed_config.toml"
TOOLSH = CODEX / "agentos-toolsh"
LAUNCH = CODEX / "launch.json"
STUB_CLI = ROOT / "tests/codex_worker/stub_cli.py"
STUB_TOOL = ROOT / "tests/codex_worker/stub_tool.py"
BWRAP = "/usr/bin/bwrap"
FORWARDER = "http://127.0.0.1:18432"
CODEX_HOME = "/var/lib/agentos-codex"
WORK = "/var/lib/agentos-work"

# Settings that must hold exactly. The hosted-tool rows are the off switches the pinned CLI is
# assumed to read (guest/codex/ASSUMPTIONS.md C1); a missing key counts as on, since the CLI's
# default may be on.
REQUIRED = {
    ("model_provider",): "agentos",
    ("model_providers", "agentos", "base_url"): FORWARDER + "/backend-api/codex",
    ("model_providers", "agentos", "wire_api"): "responses",
    ("model_providers", "agentos", "requires_openai_auth"): True,
    ("web_search",): "disabled",
    ("tools", "web_search"): False,
    ("features", "web_search_request"): False,
    ("features", "web_search_cached"): False,
    ("features", "image_generation"): False,
    ("check_for_update_on_startup",): False,
    ("analytics", "enabled"): False,
    ("otel", "exporter"): "none",
    ("feedback", "enabled"): False,
    ("history", "persistence"): "none",
    ("approval_policy",): "never",
    ("sandbox_mode",): "workspace-write",
    ("sandbox_workspace_write", "network_access"): False,
    ("shell_environment_policy", "inherit"): "none",
}
# Names of tools the provider runs on its side when a request asks for them (OpenAI's hosted tool
# types, plus MCP servers, which the CLI would call on the model's behalf). Any key naming one must
# be set off; an MCP server table must not exist at all.
HOSTED = ("web_search", "file_search", "code_interpreter", "image_generation", "image_gen",
          "computer_use", "hosted", "remote_mcp")
OFF = (False, "disabled", "off", "none")


def hosted_tool_problems(cfg):
    """Return what in a parsed managed config leaves a hosted tool on or the route unpinned."""
    problems = []
    for path, want in REQUIRED.items():
        node = cfg
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        if node != want:
            problems.append(f"{'.'.join(path)} is {node!r}, want {want!r}")

    def walk(node, path):
        for key, value in node.items():
            here = path + (key,)
            if "mcp_servers" in key or key == "mcp":
                problems.append(f"{'.'.join(here)}: no MCP servers in a provider worker")
            elif isinstance(value, dict):
                walk(value, here)
            elif any(h in key for h in HOSTED) and value not in OFF:
                problems.append(f"{'.'.join(here)} = {value!r} leaves a hosted tool on")
    walk(cfg, ())
    return problems


class ManagedConfigTest(unittest.TestCase):
    """The image test for hosted tools (brief: "fails if the managed configuration leaves web
    search or any other hosted tool on")."""

    # REQ: CRED-5, A14
    def test_hosted_tools_off_and_route_pinned(self):
        cfg = tomllib.loads(CONFIG.read_text())
        self.assertEqual(hosted_tool_problems(cfg), [])

    # REQ: CRED-5, A14
    def test_checker_flags_each_bad_config(self):
        good = tomllib.loads(CONFIG.read_text())

        def drop(path):
            def f(c):
                node = c
                for key in path[:-1]:
                    node = node[key]
                del node[path[-1]]
            return f

        def put(path, value):
            def f(c):
                node = c
                for key in path[:-1]:
                    node = node.setdefault(key, {})
                node[path[-1]] = value
            return f

        mutants = {
            "web search live": put(("web_search",), "live"),
            "web search cached": put(("web_search",), "cached"),
            "web search key missing (default on)": drop(("web_search",)),
            "web search request feature on": put(("features", "web_search_request"), True),
            "web search feature missing": drop(("features", "web_search_request")),
            "image generation on": put(("features", "image_generation"), True),
            "file search added": put(("tools", "file_search"), True),
            "code interpreter added": put(("features", "code_interpreter"), "enabled"),
            "computer use added": put(("tools", "computer_use_preview"), True),
            "an MCP server": put(("mcp_servers", "x", "url"), "https://mcp.example/"),
            "base_url off the forwarder": put(("model_providers", "agentos", "base_url"),
                                              "https://chatgpt.com/backend-api/codex"),
            "other provider": put(("model_provider",), "openai"),
            "auto-update check on": put(("check_for_update_on_startup",), True),
            "analytics on": put(("analytics", "enabled"), True),
            "telemetry exported": put(("otel", "exporter"), "otlp-http"),
            "history kept": put(("history", "persistence"), "save-all"),
            "tool network on": put(("sandbox_workspace_write", "network_access"), True),
            "env inherited": put(("shell_environment_policy", "inherit"), "all"),
        }
        for name, mutate in mutants.items():
            with self.subTest(mutant=name):
                cfg = copy.deepcopy(good)
                mutate(cfg)
                self.assertNotEqual(hosted_tool_problems(cfg), [])

    # REQ: CRED-5, CAP-11
    def test_launch_points_refresh_at_forwarder_and_runs_headless(self):
        launch = json.loads(LAUNCH.read_text())
        env = dict(e.split("=", 1) for e in launch["env"])
        self.assertEqual(env["CODEX_REFRESH_TOKEN_URL_OVERRIDE"], FORWARDER + "/oauth/token")
        self.assertEqual(env["CODEX_HOME"], CODEX_HOME)
        self.assertEqual(env["HOME"], WORK)
        self.assertEqual(launch["argv"],
                         ["codex", "exec", "--json", "--skip-git-repo-check", "--cd", WORK, "-"])
        self.assertEqual(launch["cwd"], WORK)
        # Nothing secret-shaped rides in the launch spec; the login stays with the broker (CRED-5).
        for entry in launch["env"]:
            self.assertNotRegex(entry.split("=", 1)[0], r"(?i)key|token$|secret|password")


class ToolshRefusalTest(unittest.TestCase):
    """agentos-toolsh refuses before it starts bwrap, so these run without root."""

    def run_toolsh(self, cwd, *argv):
        # Through its shebang, as the CLI must run it: `bash agentos-toolsh` would drop -p.
        return subprocess.run([str(TOOLSH), *argv], cwd=cwd, capture_output=True,
                              text=True, timeout=30)

    # REQ: CRED-5, A14
    def test_wrapper_is_bash_and_calls_bwrap_by_absolute_path(self):
        # What each flag does is checked by behaviour in ToolSandboxTest; this pins the shape.
        self.assertTrue(os.access(TOOLSH, os.X_OK), "agentos-toolsh must be executable")
        self.assertEqual(subprocess.run(["bash", "-n", str(TOOLSH)]).returncode, 0)
        text = TOOLSH.read_text()
        self.assertTrue(text.startswith("#!/bin/bash -p\n"))
        self.assertIn('BWRAP=/usr/bin/bwrap', text)
        # The workspace root is bound before the hiding mounts, and the working directory is
        # entered with --chdir, never bound (test_cwd_swapped_for_a_symlink_*).
        self.assertLess(text.index('\t--bind "$WORK" "$WORK" \\\n'), text.index('\t"${hide[@]}"'))
        self.assertNotIn('--bind "$cwd"', text)

    # REQ: CRED-5, A14
    def test_refuses_a_working_directory_outside_the_workspace(self):
        # Writable system paths would let a tool reach CODEX_HOME (/var, /var/lib) or replace
        # the wrapper itself (/usr, /usr/local/bin). CODEX_HOME is checked inside the stub worker.
        for cwd in ("/", "/run", "/tmp", "/proc", "/etc", "/var", "/var/lib", "/usr",
                    "/usr/local/bin", "/home"):
            with self.subTest(cwd=cwd):
                if not os.path.isdir(cwd):
                    continue
                r = self.run_toolsh(cwd, "true")
                self.assertEqual(r.returncode, 126, r.stderr)
                self.assertIn("refusing", r.stderr)

    # REQ: CRED-5
    def test_refuses_an_empty_command(self):
        with tempfile.TemporaryDirectory() as d:
            r = self.run_toolsh(d)
            self.assertEqual(r.returncode, 126, r.stderr)


def bwrap_usable():
    return os.geteuid() == 0 and os.access(BWRAP, os.X_OK)


class _Forwarder:
    """Stand-ins for the forwarder's loopback port and the egress socket: each answers one
    line with b"ok\\n" so the stub CLI can show it reaches both."""

    def __init__(self, sock_path):
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(16)
        self.port = self.tcp.getsockname()[1]
        self.unix = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.unix.bind(sock_path)
        self.unix.listen(16)
        for s in (self.tcp, self.unix):
            threading.Thread(target=self.serve, args=(s,), daemon=True).start()

    @staticmethod
    def serve(listener):
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            # One thread per connection: the stub CLI holds one open while its tool connects.
            threading.Thread(target=_Forwarder.answer, args=(conn,), daemon=True).start()

    @staticmethod
    def answer(conn):
        with conn:
            conn.settimeout(5)
            try:
                conn.recv(64)
                conn.sendall(b"ok\n")
            except OSError:
                pass

    def close(self):
        self.tcp.close()
        self.unix.close()


class ToolSandboxTest(unittest.TestCase):
    """A stub worker: an outer bwrap plays the worker machine (its /run/agentos holds the egress
    socket, CODEX_HOME holds a placeholder auth.json carrying a synthetic canary, and the host's
    loopback stands in for the in-worker forwarder). In it the stub CLI first shows it reaches
    all three, then runs a stub tool through agentos-toolsh, which must reach none of them."""

    @classmethod
    def setUpClass(cls):
        if not bwrap_usable():
            if os.environ.get("AGENTOS_REQUIRE_BWRAP") == "1":
                raise AssertionError("AGENTOS_REQUIRE_BWRAP=1 but not root with " + BWRAP)
            raise unittest.SkipTest("needs root and " + BWRAP)

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentos-codex-t-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.run_dir = self.tmp / "run-agentos"
        self.codex_home = self.tmp / "codex-home"
        self.work = self.tmp / "work"
        for d in (self.run_dir, self.codex_home, self.work):
            d.mkdir()
        self.canary = "agentos-synthetic-canary-" + secrets.token_hex(12)
        # The placeholder auth.json (#1015) carries the canary where a login would sit.
        (self.codex_home / "auth.json").write_text(
            json.dumps({"auth_mode": "placeholder", "placeholder": self.canary}))
        self.fwd = _Forwarder(str(self.run_dir / "egress.sock"))
        self.addCleanup(self.fwd.close)

    def worker(self, *command, toolsh=TOOLSH, codex_home=True, chdir=WORK, extra=()):
        argv = [
            BWRAP, "--dev-bind", "/", "/",
            "--tmpfs", "/run", "--bind", str(self.run_dir), "/run/agentos",
            "--tmpfs", "/tmp", "--tmpfs", "/var/tmp",
            "--tmpfs", "/var/lib",
            *(("--bind", str(self.codex_home), CODEX_HOME) if codex_home else ()),
            "--bind", str(self.work), WORK,
            "--ro-bind", str(toolsh), "/usr/local/bin/agentos-toolsh",
            # A system path: the tool runs without CAP_DAC_OVERRIDE, so it cannot
            # traverse a 0750 home such as the CI runner's checkout.
            "--ro-bind", str(STUB_TOOL), "/var/lib/agentos-stub-tool.py",
            *extra,
            "--chdir", chdir,
            "--setenv", "AGENTOS_SYNTHETIC_CANARY", self.canary,
            "--", *command,
        ]
        return subprocess.run(argv, capture_output=True, text=True, timeout=60)

    def script(self, body, toolsh=TOOLSH, extra=()):
        """Run a shell script as the CLI inside the stub worker."""
        s = self.tmp / "cli.sh"
        s.write_text(body)
        return self.worker("/bin/sh", "/var/lib/agentos-cli.sh", toolsh=toolsh,
                           extra=("--ro-bind", str(s), "/var/lib/agentos-cli.sh", *extra))

    def mutant(self, name, *edits):
        """A copy of agentos-toolsh with each (old, new) edit applied once."""
        text = TOOLSH.read_text()
        for old, new in edits:
            self.assertIn(old, text)
            text = text.replace(old, new, 1)
        bad = self.tmp / name
        bad.write_text(text)
        bad.chmod(0o755)
        return bad

    def run_worker(self, toolsh=TOOLSH, codex_home=True):
        r = self.worker(sys.executable, "-I", str(STUB_CLI), str(self.fwd.port), self.canary,
                        toolsh=toolsh, codex_home=codex_home)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def assert_contained(self, tool):
        self.assertEqual(tool["exit"], 0, tool)
        self.assertFalse(tool["tcp"], "tool reached the forwarder's loopback port")
        self.assertFalse(tool["unix"], "tool reached the egress socket")
        self.assertFalse(tool["auth"], "tool read the placeholder auth.json")
        self.assertFalse(tool["env"], "tool saw the CLI's environment")
        self.assertFalse(tool["parent"], "tool saw the CLI's process")
        self.assertFalse(tool["root_write"], "tool wrote outside its workspace")
        self.assertFalse(tool["canary_anywhere"], "the canary reached the tool")
        self.assertFalse(tool["caps"], "tool kept capabilities")
        self.assertFalse(tool["userns"], "tool could create a nested user namespace")
        self.assertFalse(tool["session"], "tool shares the CLI's session")
        self.assertFalse(tool["tmp"], "tool saw the worker's /tmp or /var/tmp")
        self.assertEqual(tool["fds"], [], "tool inherited the CLI's descriptors")
        self.assertFalse(tool["outlives"], "tool outlived its wrapper")
        self.assertTrue(tool["work_write"], "tool must still write its workspace")
        self.assertEqual(tool["ifaces"], ["lo"], "tool must have no interface but its own lo")

    # REQ: CRED-5, CRED-1, A14, CAP-11
    def test_cli_reaches_forwarder_and_login_but_its_tools_do_not(self):
        out = self.run_worker()
        self.assertEqual(out["cli"], {"tcp": True, "unix": True, "auth": True, "env": True},
                         "the control case must reach everything, or the tool result proves nothing")
        self.assert_contained(out["tool"])

    # REQ: CRED-5, A14
    def test_tool_is_contained_in_a_worker_without_codex_home(self):
        # The wrapper's other branch: no CODEX_HOME to hide, the rest unchanged.
        out = self.run_worker(codex_home=False)
        self.assertEqual(out["cli"]["auth"], False)
        self.assertEqual(out["cli"]["tcp"], True)
        self.assertEqual(out["cli"]["unix"], True)
        self.assertEqual(out["tool"]["exit"], 0, out["tool"])
        self.assert_contained(out["tool"])

    # REQ: CRED-5, A14
    def test_refuses_codex_home_and_a_workspace_lookalike_as_working_directory(self):
        for cwd in (CODEX_HOME, "/var/lib/agentos-workx"):
            with self.subTest(cwd=cwd):
                r = self.worker("/usr/local/bin/agentos-toolsh", "true", chdir=cwd,
                                extra=("--dir", "/var/lib/agentos-workx"))
                self.assertEqual(r.returncode, 126, r.stderr)
                self.assertIn("outside " + WORK, r.stderr)
        r = self.worker("/usr/local/bin/agentos-toolsh", "true", chdir=WORK + "/sub",
                        extra=("--dir", WORK + "/sub"))
        self.assertEqual(r.returncode, 0, r.stderr)

    # REQ: CRED-5, A14
    def test_each_removed_wrapper_defence_turns_the_test_red(self):
        # Revert mutants: each edit to agentos-toolsh must let the stub tool reach something.
        mutants = {
            "network shared": (("--unshare-all", "--unshare-user --unshare-pid --unshare-ipc "
                                "--unshare-uts --unshare-cgroup"), "tcp"),
            "socket dir visible": (("hide=(--tmpfs /run ", "hide=("), "unix"),
            "CODEX_HOME visible": (('hide+=(--tmpfs "$CODEX_HOME")', "hide+=()"), "auth"),
            "environment kept": (("--clearenv ", ""), "env"),
            "capabilities kept": (("--cap-drop ALL ", ""), "caps"),
            "nested userns allowed": (("--disable-userns ", ""), "userns"),
            "session shared": (("--new-session ", ""), "session"),
            "/tmp shared": (("--tmpfs /tmp ", ""), "tmp"),
            "/var/tmp shared": (("--tmpfs /var/tmp)", ")"), "tmp"),
            "descriptors kept": (('eval "exec $fd>&-"', ":"), "fds"),
            # What dash could do: the stub CLI also passes descriptors at 200 and 1000.
            "descriptors above 9 kept": (('if [ "$fd" -gt 2 ]; then',
                                          'if [ "$fd" -gt 2 ] && [ "$fd" -le 9 ]; then'), "fds"),
            "survives its parent": (("--die-with-parent ", ""), "outlives"),
        }
        text = TOOLSH.read_text()
        for name, ((old, new), leak) in mutants.items():
            with self.subTest(mutant=name):
                self.assertIn(old, text)
                bad = self.tmp / "toolsh-mutant"
                bad.write_text(text.replace(old, new, 1))
                bad.chmod(0o755)
                got = self.run_worker(bad)["tool"][leak]
                if not got and leak == "userns" and userns_restricted():
                    self.skipTest("the kernel refuses unprivileged user namespaces here anyway")
                self.assertTrue(got, f"{name} went unnoticed")

    # REQ: CRED-5, A14
    def test_allow_list_and_bind_order_each_keep_codex_home_hidden(self):
        # With the allow-list gone the hiding mounts still cover a working directory in
        # CODEX_HOME: the wrapper binds only the workspace root, and --chdir lands in the empty
        # tmpfs. The old design, binding the working directory itself, held only while that
        # bind came before the hiding mounts; with it after them the probe sees the leak.
        no_list = ('*) refuse "working directory $cwd is outside $WORK" ;;', "*) ;;")
        root_bind = '\t--bind "$WORK" "$WORK" \\\n'
        cwd_bind = '\t--bind "$cwd" "$cwd" \\\n'
        hide = '\t"${hide[@]}" \\\n'
        probe = ("/bin/cat", CODEX_HOME + "/auth.json")
        for name, edits, leaks in (
                ("allow-list gone", (no_list,), False),
                ("allow-list gone, cwd bound before hiding", (no_list, (root_bind, cwd_bind)),
                 False),
                ("allow-list gone, cwd bound after hiding",
                 (no_list, (root_bind, ""), (hide, hide + cwd_bind)), True)):
            with self.subTest(mutant=name):
                bad = self.mutant("toolsh-order", *edits)
                r = self.worker("/usr/local/bin/agentos-toolsh", *probe, toolsh=bad,
                                chdir=CODEX_HOME)
                self.assertEqual(self.canary in r.stdout, leaks, r.stderr)

    # REQ: CRED-5, A14
    def test_cwd_swapped_for_a_symlink_after_the_check_cannot_bind_the_root(self):
        # A second tool that can write the workspace swaps WORK/sub for a symlink to the root
        # between the wrapper's check and bwrap's setup. The sleep mutant holds that window open
        # so the race is deterministic. The probe file lands in the stub worker's /var/lib
        # tmpfs, read-only to a contained tool. The target is relative, so bwrap resolves it
        # to the root on both sides of its bind (an absolute one resolves the bind's target
        # outside the new root, where the result depends on the host's mounts).
        window = ('\nexec "$BWRAP"', '\nsleep 2\nexec "$BWRAP"')
        cwd_bind = ('--bind "$WORK" "$WORK"', '--bind "$cwd" "$cwd"')
        for target in ("../../..",):
            for name, edits, writes in (("check-to-bwrap window", (window,), False),
                                        ("window, cwd bound", (window, cwd_bind), True)):
                with self.subTest(target=target, mutant=name):
                    bad = self.mutant("toolsh-race", *edits)
                    r = self.script(f"""cd {WORK}; rm -rf sub sub.real; mkdir sub
( sleep 0.5; mv sub sub.real; ln -s {target} sub; echo SWAPPED ) &
cd {WORK}/sub && /usr/local/bin/agentos-toolsh /bin/sh -c 'touch /var/lib/agentos-race-probe'
echo "tool=$?"
wait
[ -e /var/lib/agentos-race-probe ] && echo ROOT_WRITTEN
true
""", toolsh=bad)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertIn("SWAPPED", r.stdout)
                    self.assertNotIn("refusing", r.stderr, "the swap missed the window")
                    self.assertEqual("ROOT_WRITTEN" in r.stdout, writes, r.stdout + r.stderr)

    # REQ: CRED-5, A14
    def test_symlinked_working_directory_is_refused_and_cannot_bind_the_root(self):
        # A cwd reached through WORK/link -> / or WORK/rel -> ../../.. resolves outside the
        # workspace and is refused. Even with the check weakened to the logical path (the
        # allow-list then passes), the root stays read-only, since only WORK is bound; binding
        # that path, as the old wrapper did, mounts the root read-write (shown for the relative
        # link only: see the race test on absolute targets).
        logical = ("cwd=$(pwd -P)", "cwd=$(pwd)")
        cwd_bind = ('--bind "$WORK" "$WORK"', '--bind "$cwd" "$cwd"')
        (self.work / "link").symlink_to("/")
        (self.work / "rel").symlink_to("../../..")
        for link in ("link", "rel"):
            cases = [("as shipped", (), True, False), ("logical cwd", (logical,), False, False)]
            if link == "rel":
                cases.append(("logical cwd, cwd bound", (logical, cwd_bind), False, True))
            for name, edits, refused, writes in cases:
                with self.subTest(cwd=link, mutant=name):
                    bad = self.mutant("toolsh-link", *edits)
                    r = self.script(f"""cd {WORK}/{link} || exit 9
/usr/local/bin/agentos-toolsh /bin/sh -c 'touch /var/lib/agentos-race-probe'
echo "tool=$?"
[ -e /var/lib/agentos-race-probe ] && echo ROOT_WRITTEN
true
""", toolsh=bad)
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual("tool=126" in r.stdout, refused, r.stdout + r.stderr)
                    self.assertEqual("ROOT_WRITTEN" in r.stdout, writes, r.stdout + r.stderr)

    # REQ: CRED-5, A14
    def test_no_startup_code_from_the_environment(self):
        # The CLI may pass the wrapper a BASH_ENV file or exported functions. bash -p ignores
        # both; plain bash would run them outside bwrap, before the check: an exported pwd
        # reads auth.json unsandboxed and answers WORK to pass the allow-list.
        body = f"""cd {WORK}
printf 'echo BASH_ENV_SOURCED >&2\n' > rc.sh
BASH_ENV={WORK}/rc.sh /usr/local/bin/agentos-toolsh /bin/true
echo "bash_env=$?"
cd {CODEX_HOME}
env 'BASH_FUNC_pwd%%=() {{ echo FUNC_IMPORTED >&2; cat auth.json >&2; echo {WORK}; }}' \
    /usr/local/bin/agentos-toolsh /bin/true
echo "func=$?"
"""
        for name, edits, imported in (("as shipped", (), False),
                                      ("without -p", (("#!/bin/bash -p\n", "#!/bin/bash\n"),),
                                       True)):
            with self.subTest(mutant=name):
                r = self.script(body, toolsh=self.mutant("toolsh-env", *edits))
                self.assertEqual(r.returncode, 0, r.stderr)
                out = r.stdout + r.stderr
                self.assertIn("bash_env=0", r.stdout, out)
                self.assertEqual("BASH_ENV_SOURCED" in r.stderr, imported, out)
                self.assertEqual("FUNC_IMPORTED" in r.stderr, imported, out)
                self.assertEqual(self.canary in out, imported, "auth.json read unsandboxed")
                self.assertEqual("func=126" in r.stdout, not imported, out)

    # REQ: CRED-5, A14
    def test_refuses_without_proc_to_close_descriptors(self):
        # The descriptor loop reads /proc/$$/fd; without it the wrapper refuses outright
        # rather than leaning on bwrap failing later.
        no_check = ('[ -d "/proc/$$/fd" ] || refuse "no /proc to find inherited descriptors"\n',
                    "")
        for name, edits, refused in (("as shipped", (), True), ("check removed", (no_check,),
                                                                  False)):
            with self.subTest(mutant=name):
                r = self.worker("/usr/local/bin/agentos-toolsh", "/bin/true",
                                toolsh=self.mutant("toolsh-proc", *edits),
                                extra=("--tmpfs", "/proc"))
                self.assertEqual(r.returncode == 126 and "no /proc" in r.stderr, refused,
                                 r.stderr)

def userns_restricted():
    try:
        return pathlib.Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
                            ).read_text().strip() == "1"
    except OSError:
        return False


if __name__ == "__main__":
    unittest.main()
