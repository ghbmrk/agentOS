# The Codex provider worker's defensive half (S8-W1, #807 split): the managed config that keeps
# hosted tools, plugins, hooks and WebSockets off and points the CLI at the in-worker forwarder;
# the requirements layer that keeps CODEX_HOME unreadable to the CLI's own tool sandbox; and
# agentos-toolsh, the reference bwrap prefix that cuts a tool off from the forwarder's loopback
# port, the egress socket under /run and the placeholder auth.json in CODEX_HOME. Stub CLI and stub
# tool with a synthetic canary; the opt-in CliSandboxTest runs a real CLI binary against a fake
# endpoint, with no login and no adversarial content (the containment test with the pinned CLI
# stays for the supervised session, D-064).
# REQ: CRED-5, CRED-1, A14, CAP-11
#
# The sandbox half needs root and /usr/bin/bwrap; it skips without them, and fails instead when
# AGENTOS_REQUIRE_BWRAP=1 (CI runs it that way under sudo in the checks job).
# CliSandboxTest also needs AGENTOS_CODEX_CLI, the path of a Codex CLI binary; CI has none. To run
# it as root, with the checkout and the CLI outside /tmp (the stub worker replaces /tmp), port
# 18432 free, and cc on PATH if the LD_PRELOAD mutant should also check the library runs:
#   cd /root && npm pack @openai/codex@0.162.1-linux-x64
#   tar xzf openai-codex-0.162.1-linux-x64.tgz
#   mkdir -p /etc/codex   # an empty mount point; each turn binds its own copy of the guest files
#   AGENTOS_REQUIRE_BWRAP=1 \
#   AGENTOS_CODEX_CLI=/root/package/vendor/x86_64-unknown-linux-musl/bin/codex \
#     python3 -m unittest tests.test_codex_worker.CliSandboxTest
# The CLI starts codex-code-mode-host from beside its binary, so keep the vendor directory whole.
import base64
import copy
import json
import os
import pathlib
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CODEX = ROOT / "guest/codex"
CONFIG = CODEX / "managed_config.toml"
REQUIREMENTS = CODEX / "requirements.toml"
TOOLSH = CODEX / "agentos-toolsh"
LAUNCH = CODEX / "launch.json"
STUB_CLI = ROOT / "tests/codex_worker/stub_cli.py"
STUB_TOOL = ROOT / "tests/codex_worker/stub_tool.py"
FAKE_ENDPOINT = ROOT / "tests/codex_worker/fake_endpoint.py"
BWRAP = "/usr/bin/bwrap"
FORWARDER = "http://127.0.0.1:18432"
FORWARDER_SRC = ROOT / "broker/egress/cmd/agentos-codex-forwarder/main.go"
CODEX_HOME = "/var/lib/agentos-codex"
WORK = "/var/lib/agentos-work"
# The model G1's model-backed task (provider_run on the Codex plan route) sends (#1396,
# guest/codex/ASSUMPTIONS.md C19): the default of the pinned CLI's bundled catalog, pinned so a
# catalog refresh from the provider cannot change it between the qualification run and G1.
MODEL = "gpt-6.1-sol"
MODEL_LINE = f'model = "{MODEL}"\n'

# Settings that must hold exactly. The key names were measured against Codex CLI 0.162.1
# (guest/codex/ASSUMPTIONS.md C1); a missing key counts as on, since the CLI's default may be on,
# and a lower config layer can add any key the managed file leaves out.
REQUIRED = {
    ("model_provider",): "agentos",
    # Plan-login traffic, the token refresh included, goes to the forwarder too; unset, a plan
    # login calls chatgpt.com directly (#2085).
    ("chatgpt_base_url",): FORWARDER + "/backend-api/",
    ("model",): MODEL,
    ("model_providers", "agentos", "base_url"): FORWARDER + "/backend-api/codex",
    ("model_providers", "agentos", "wire_api"): "responses",
    ("model_providers", "agentos", "requires_openai_auth"): True,
    # WebSocket transport would bypass the forwarder's HTTP request-body check (#1453, C10).
    ("model_providers", "agentos", "supports_websockets"): False,
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
    # Tools write only the workspace: no extra roots, and neither $TMPDIR nor /tmp (CRED-5: a
    # managed writable root of CODEX_HOME lets a tool replace auth.json, measured).
    ("sandbox_workspace_write", "writable_roots"): [],
    ("sandbox_workspace_write", "exclude_tmpdir_env_var"): True,
    ("sandbox_workspace_write", "exclude_slash_tmp"): True,
    # "core", not "none": with "none" a tool gets no system PATH. include_only below is the
    # filter (C15).
    ("shell_environment_policy", "inherit"): "core",
    # Only PATH, HOME and TMPDIR reach a tool: a lower layer's `set` (LD_PRELOAD, say) is
    # filtered out (#1455), and HOME and TMPDIR are the workspace, the one writable place (C15).
    ("shell_environment_policy", "include_only"): ["PATH", "HOME", "TMPDIR"],
    ("shell_environment_policy", "set"): {"HOME": WORK, "TMPDIR": WORK},
    # A lower layer cannot mark the workspace trusted, which would load its .codex config (#1451).
    ("projects", WORK, "trust_level"): "untrusted",
    # No program runs when a turn ends: an empty list replaces a lower layer's notify (C14).
    ("notify",): [],
}
# Features that run code or reach the network outside the one declared route: plugins, hooks,
# apps, browser and computer use, sub-agents, MCP installs, in-app updates (#1453, C9). Each must
# be pinned off in managed config, since a lower layer could otherwise turn it on.
FEATURES_OFF = ("hooks", "plugins", "remote_plugin", "plugin_sharing", "apps", "browser_use",
                "browser_use_external", "computer_use", "multi_agent",
                "skill_mcp_dependency_install", "in_app_updates")
REQUIRED.update({("features", f): False for f in FEATURES_OFF})
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
    # A permission profile in managed config is deep-merged with lower layers, which can add
    # "/" = "write" to it (measured on 0.162.1, C13); sandbox_mode alone is not extendable.
    for key in ("default_permissions", "permissions"):
        if key in cfg:
            problems.append(f"{key}: a managed permission profile is extended by lower layers")
    return problems


def requirements_deny_read():
    return tomllib.loads(REQUIREMENTS.read_text())["permissions"]["filesystem"]["deny_read"]


def glob_regex(glob):
    """The CLI's reading of one deny_read entry (C12): `*`, `?` and `[!x]` never cross `/`, a
    trailing `/**` covers everything below, and anything else is a literal path."""
    tail = glob.endswith("/**")
    if tail:
        glob = glob[:-3]
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = glob.index("]", i)
            body = glob[i + 1:j]
            out.append("[^" + re.escape(body[1:]) + "/]" if body.startswith("!")
                       else "[" + re.escape(body) + "]")
            i = j
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out) + ("/.*" if tail else "")


def denied(globs, path):
    # A directory's contents need the `/**` twin, as measured: the entry alone covers only the
    # name. CliSandboxTest checks the real CLI against the same entries.
    return any(re.fullmatch(glob_regex(g), path) for g in globs)


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
            "model unpinned (catalog default)": drop(("model",)),
            "other model": put(("model",), "gpt-5.5"),
            "auto-update check on": put(("check_for_update_on_startup",), True),
            "analytics on": put(("analytics", "enabled"), True),
            "telemetry exported": put(("otel", "exporter"), "otlp-http"),
            "history kept": put(("history", "persistence"), "save-all"),
            "tool network on": put(("sandbox_workspace_write", "network_access"), True),
            "env inherited": put(("shell_environment_policy", "inherit"), "all"),
            "env allow-list missing": drop(("shell_environment_policy", "include_only")),
            "env allow-list widened": put(("shell_environment_policy", "include_only"),
                                          ["PATH", "HOME", "TMPDIR", "LD_*"]),
            "HOME off the workspace": put(("shell_environment_policy", "set", "HOME"),
                                          CODEX_HOME),
            "TMPDIR off the workspace": put(("shell_environment_policy", "set", "TMPDIR"),
                                            "/tmp"),
            "env set gains LD_PRELOAD": put(("shell_environment_policy", "set", "LD_PRELOAD"),
                                            WORK + "/x.so"),
            "env set unpinned": drop(("shell_environment_policy", "set")),
            "extra writable root": put(("sandbox_workspace_write", "writable_roots"),
                                       [CODEX_HOME]),
            "writable roots unpinned": drop(("sandbox_workspace_write", "writable_roots")),
            "TMPDIR writable": put(("sandbox_workspace_write", "exclude_tmpdir_env_var"), False),
            "TMPDIR exclusion unpinned": drop(("sandbox_workspace_write",
                                               "exclude_tmpdir_env_var")),
            "/tmp writable": put(("sandbox_workspace_write", "exclude_slash_tmp"), False),
            "/tmp exclusion unpinned": drop(("sandbox_workspace_write", "exclude_slash_tmp")),
            "WebSocket transport unpinned": drop(("model_providers", "agentos",
                                                  "supports_websockets")),
            "WebSocket transport on": put(("model_providers", "agentos", "supports_websockets"),
                                          True),
            "notify program": put(("notify",), ["/bin/sh", "-c", "true"]),
            "notify unpinned": drop(("notify",)),
            "workspace trusted": put(("projects", WORK, "trust_level"), "trusted"),
            "workspace trust unpinned": drop(("projects", WORK)),
            "managed permission profile": put(("default_permissions",), "agentos"),
            "managed permission table": put(("permissions", "agentos", "filesystem", "/tmp"),
                                            "read"),
            **{f"feature {f} on": put(("features", f), True) for f in FEATURES_OFF},
            **{f"feature {f} unpinned": drop(("features", f)) for f in FEATURES_OFF},
        }
        for name, mutate in mutants.items():
            with self.subTest(mutant=name):
                cfg = copy.deepcopy(good)
                mutate(cfg)
                self.assertNotEqual(hosted_tool_problems(cfg), [])

    # REQ: CRED-5, A14, CAP-11
    def test_launch_starts_the_forwarder_that_base_url_and_refresh_name(self):
        launch = json.loads(LAUNCH.read_text())
        wrap = launch["wrap"]
        self.assertEqual(wrap[0], "/usr/local/bin/agentos-codex-forwarder")
        self.assertEqual(wrap[-1], "--")
        opts = dict(zip(wrap[1:-1:2], wrap[2:-1:2]))
        self.assertEqual(opts, {"-listen": "127.0.0.1:18432", "-socket": "/run/agentos/route.sock"})
        cfg = tomllib.loads((CODEX / "managed_config.toml").read_text())
        self.assertEqual(cfg["model_provider"], "agentos")
        base = cfg["model_providers"]["agentos"]["base_url"]
        self.assertTrue(base.startswith("http://" + opts["-listen"] + "/"), base)
        plan = cfg["chatgpt_base_url"]
        self.assertTrue(plan.startswith("http://" + opts["-listen"] + "/"), plan)
        # The forwarder sets the refresh override from the port it bound, so it names that port by
        # construction; launch env carrying one would be refused by childproc at the start (C18).
        env = dict(e.split("=", 1) for e in launch["env"])
        self.assertNotIn("CODEX_REFRESH_TOKEN_URL_OVERRIDE", env)
        self.assertIn('"CODEX_REFRESH_TOKEN_URL_OVERRIDE=http://"+addr+"/oauth/token"',
                      FORWARDER_SRC.read_text())

    # REQ: CRED-5, CAP-11
    def test_launch_points_refresh_at_forwarder_and_runs_headless(self):
        launch = json.loads(LAUNCH.read_text())
        env = dict(e.split("=", 1) for e in launch["env"])
        # The refresh override is the forwarder's to set (C18), not the launch spec's.
        self.assertNotIn("CODEX_REFRESH_TOKEN_URL_OVERRIDE", env)
        self.assertEqual(env["CODEX_HOME"], CODEX_HOME)
        # HOME is CODEX_HOME, not the workspace: git and other tools would read a workspace
        # .gitconfig or dotfile as the CLI's own configuration (#1451, C11).
        self.assertEqual(env["HOME"], CODEX_HOME)
        # The CLI runs git in the workspace outside its tool sandbox; with GIT_DIR on /dev/null
        # no repository a tool wrote there (filters, hooks, fsmonitor) is ever read (C11).
        self.assertEqual(env["GIT_DIR"], "/dev/null")
        # argv[0] is the bare `codex`: the forwarder finds it, and the CLI's tools their helpers,
        # through env's own PATH, so a runner passing exactly env starts a working worker (C18).
        self.assertEqual(env["PATH"], "/usr/local/bin:/usr/bin:/bin")
        self.assertEqual(sorted(env), ["CODEX_HOME", "GIT_DIR", "HOME", "PATH"])
        self.assertEqual(launch["argv"],
                         ["codex", "exec", "--json", "--skip-git-repo-check", "--cd", WORK, "-"])
        self.assertEqual(launch["cwd"], WORK)
        # Nothing secret-shaped rides in the launch spec; the login stays with the broker (CRED-5).
        for entry in launch["env"]:
            self.assertNotRegex(entry.split("=", 1)[0], r"(?i)key|token$|secret|password")


class RequirementsTest(unittest.TestCase):
    """The requirements layer that keeps CODEX_HOME unreadable to the CLI's tool sandbox (#1452,
    C12). It must deny every name the CLI keeps there and spare tmp/, where the CLI places the
    helpers its sandbox runs (denying those makes the CLI refuse to start)."""

    # Names measured in a 0.162.1 CODEX_HOME after one exec turn, plus the placeholder login,
    # plus one name per entry that only that entry denies (tq, tmz, tmpdir/f and so on), so
    # dropping any entry leaves something readable.
    KEPT = ("auth.json", "config.toml", "installation_id", "state_5.sqlite",
            "state_5.sqlite-wal", "state_5.sqlite-shm", "logs_2.sqlite", "goals_1.sqlite",
            "memories_1.sqlite", "queue_1.sqlite", "thread_history_1.sqlite", "sessions/2026/x.jsonl",
            "shell_snapshots/x.sh", "skills/x/SKILL.md", "thread-writer-locks/x", ".sandbox_migration",
            ".tmp/x", ".tmp/plugins.sync.lock", "tmpx", "t", "tq", "tmz", "tmpdir/f", "tmp.d/f",
            "tq/f", "tmz/f", "zdir/sub/inner.txt", "version.json")
    SPARED = ("tmp", "tmp/arg0/codex-arg0abc/apply_patch")

    def check(self, globs):
        problems = [f"{n} readable" for n in self.KEPT if not denied(globs, f"{CODEX_HOME}/{n}")]
        problems += [f"{n} denied" for n in self.SPARED if denied(globs, f"{CODEX_HOME}/{n}")]
        return problems

    # REQ: CRED-5, A14
    def test_denies_everything_in_codex_home_but_its_helpers(self):
        self.assertEqual(self.check(requirements_deny_read()), [])

    # REQ: CRED-5, A14
    def test_each_dropped_or_widened_entry_is_caught(self):
        globs = requirements_deny_read()
        for i, g in enumerate(globs):
            with self.subTest(dropped=g):
                self.assertNotEqual(self.check(globs[:i] + globs[i + 1:]), [])
        with self.subTest(widened="all of CODEX_HOME"):
            self.assertNotEqual(self.check(globs + [CODEX_HOME + "/*"]), [])

    # REQ: CRED-5, A14
    def test_no_mcp_server_can_be_added_below(self):
        # An empty [mcp_servers] in requirements is an allowlist that admits none, so a server a
        # lower layer declares never starts (measured, C14). A missing table admits any.
        def problems(req):
            return [] if req.get("mcp_servers") == {} else ["mcp_servers is not an empty allowlist"]
        good = tomllib.loads(REQUIREMENTS.read_text())
        self.assertEqual(problems(good), [])
        dropped = copy.deepcopy(good)
        del dropped["mcp_servers"]
        added = copy.deepcopy(good)
        added["mcp_servers"]["x"] = {"command": "/bin/sh"}
        for name, req in (("table dropped", dropped), ("server added", added)):
            with self.subTest(mutant=name):
                self.assertNotEqual(problems(req), [])

    # REQ: CRED-5
    def test_managed_config_carries_no_filesystem_permissions(self):
        # The deny list lives in requirements, which lower layers cannot relax; the same list in
        # managed config would be a permission profile they can extend (C13).
        cfg = tomllib.loads(CONFIG.read_text())
        self.assertNotIn("permissions", cfg)
        self.assertNotIn("default_permissions", cfg)


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

    def worker(self, *command, toolsh=TOOLSH, codex_home=True, chdir=WORK, extra=(),
               deadline=60):
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
        # Its own session, so a stall kills the whole tree; subprocess.run would kill only bwrap.
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
        try:
            out, err = p.communicate(timeout=deadline)
        except subprocess.TimeoutExpired as stalled:
            self.fail(self.stall_report(p, deadline, stalled))
        return subprocess.CompletedProcess(argv, p.returncode, out.decode(errors="replace"),
                                           err.decode(errors="replace"))

    @staticmethod
    def stall_report(p, deadline, stalled):
        """Kill a stalled worker's tree and say what it was doing (#1542)."""
        try:
            ps = subprocess.run(["ps", "-eo", "pid,ppid,sid,stat,etime,args"],
                                capture_output=True, text=True, timeout=10).stdout
            ps = "\n".join(line for line in ps.splitlines()[1:]
                           if "bwrap" in line or "stub" in line or "agentos" in line)
        except (OSError, subprocess.SubprocessError) as e:
            ps = f"(no process listing: {e})"
        os.killpg(p.pid, 9)
        try:
            _, err = p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            # A process outside the session still holds the pipes; report what was read.
            err = stalled.stderr or b""
            p.kill()
        err = err.decode(errors="replace") if isinstance(err, bytes) else err
        return (f"worker stalled past its {deadline}s deadline\n"
                f"--- its stderr so far ---\n{err[-4000:]}\n"
                f"--- processes still running then ---\n{ps}")

    def script(self, body, toolsh=TOOLSH, extra=(), deadline=60):
        """Run a shell script as the CLI inside the stub worker."""
        s = self.tmp / "cli.sh"
        s.write_text(body)
        return self.worker("/bin/sh", "/var/lib/agentos-cli.sh", toolsh=toolsh,
                           extra=("--ro-bind", str(s), "/var/lib/agentos-cli.sh", *extra),
                           deadline=deadline)

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

    def run_worker(self, toolsh=TOOLSH, codex_home=True, extra=(), skip_outlives=False):
        flag = ("--skip-outlives",) if skip_outlives else ()
        r = self.worker(sys.executable, "-I", str(STUB_CLI), str(self.fwd.port), self.canary,
                        *flag, toolsh=toolsh, codex_home=codex_home, extra=extra)
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
        # Is False, not falsy: a run that skipped the outlives probe has no verdict to pass.
        self.assertIs(tool.get("outlives"), False, "tool outlived its wrapper, or was not checked")
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
                # Where the kernel refuses unprivileged user namespaces anyway, the mutant cannot
                # show. With AGENTOS_REQUIRE_BWRAP=1 (the checks job) this fails instead of
                # passing on a skip, so a runner that restricts them shows up (#1454).
                if not got and leak == "userns" and userns_restricted():
                    if os.environ.get("AGENTOS_REQUIRE_BWRAP") == "1":
                        self.fail("unprivileged user namespaces restricted; the userns mutant "
                                  "cannot be checked (set kernel.apparmor_restrict_"
                                  "unprivileged_userns=0)")
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
        # The descriptor loop reads /proc/self/fd; without it the wrapper refuses outright
        # rather than leaning on bwrap failing later.
        no_check = ('[ -d /proc/self/fd ] || refuse "no /proc to find inherited descriptors"\n',
                    "")
        for name, edits, refused in (("as shipped", (), True), ("check removed", (no_check,),
                                                                  False)):
            with self.subTest(mutant=name):
                r = self.worker("/usr/local/bin/agentos-toolsh", "/bin/true",
                                toolsh=self.mutant("toolsh-proc", *edits),
                                extra=("--tmpfs", "/proc"))
                self.assertEqual(r.returncode == 126 and "no /proc" in r.stderr, refused,
                                 r.stderr)

    # REQ: CRED-5, A14
    def test_refuses_a_non_numeric_descriptor_entry(self):
        # A /proc whose fd directory lists a name that is not a number (or is empty, which the
        # glob leaves as a literal "*") must stop the wrapper, not let the loop skip closing.
        fake_proc = ("--tmpfs", "/proc", "--dir", "/proc/self/fd", "--dir", "/proc/self/fd/x")
        no_case = ("\t'' | *[!0-9]*) refuse \"non-numeric descriptor entry $fd\" ;;\n", "")
        for name, edits, refused in (("as shipped", (), True), ("check removed", (no_case,),
                                                                  False)):
            with self.subTest(mutant=name):
                r = self.worker("/usr/local/bin/agentos-toolsh", "/bin/true",
                                toolsh=self.mutant("toolsh-nonnum", *edits), extra=fake_proc)
                self.assertEqual(r.returncode == 126 and "non-numeric" in r.stderr, refused,
                                 r.stderr)

    # REQ: CRED-5, A14 (CODEX-sandbox-root-1)
    def test_descriptors_closed_in_a_pid_namespace_with_the_hosts_proc(self):
        # The CLI may itself run in a pid namespace that still mounts the host's /proc: there $$
        # names some other process, so a loop over /proc/$$/fd closes the wrong descriptors (or
        # none). /proc/self is the wrapper's own whatever the namespace.
        pidns = ("--unshare-pid",)
        self.assert_contained(self.run_worker(extra=pidns)["tool"])
        bad = self.mutant("toolsh-pid",
                          ("[ -d /proc/self/fd ]", '[ -d "/proc/$$/fd" ]'),
                          ("for fd in /proc/self/fd/*", 'for fd in "/proc/$$"/fd/*'))
        # The mutant run asks only about descriptors; its refused wrapper never starts the
        # beat, so the outlives probe would just wait out its 10s (A4).
        tool = self.run_worker(toolsh=bad, extra=pidns, skip_outlives=True)["tool"]
        self.assertFalse(tool["exit"] == 0 and tool["fds"] == [],
                         "the $$ mutant must leak descriptors or refuse")

    # REQ: CRED-5, A14 (CODEX-sandbox-root-2)
    def test_skipping_the_outlives_probe_keeps_the_descriptor_probe_and_fails_containment(self):
        # A4: the stub CLI's --skip-outlives drops only the last phase. The descriptor probe
        # still runs, and the result carries no outlives verdict, so assert_contained fails it:
        # a run that must prove containment cannot skip the check unnoticed.
        r = self.worker(sys.executable, "-I", str(STUB_CLI), str(self.fwd.port), self.canary,
                        "--skip-outlives", extra=("--unshare-pid",))
        self.assertEqual(r.returncode, 0, r.stderr)
        tool = json.loads(r.stdout)["tool"]
        self.assertEqual((tool["exit"], tool["fds"]), (0, []), tool)
        self.assertNotIn("outlives", tool)
        self.assertIn("outlives skipped", r.stderr)
        self.assertNotIn("beat", r.stderr, "the beat tool must not start")
        with self.assertRaises(AssertionError):
            self.assert_contained(tool)
        r = self.worker(sys.executable, "-I", str(STUB_CLI), str(self.fwd.port), self.canary,
                        "--skip-outlive")
        self.assertEqual(r.returncode, 2, "an unknown flag must not run a partial check")

    # REQ: CRED-5, A14
    def test_a_stalled_worker_fails_with_a_diagnosis_and_leaves_nothing_running(self):
        # #1542: a worker that outruns its deadline must fail the test with what it was doing
        # and what was still running, not a bare TimeoutExpired, and must not leave its tree
        # (here a grandchild holding the output pipes, in a pid namespace) behind.
        marker = "agentos-stall-" + secrets.token_hex(4)
        body = (f'echo "{marker} phase" >&2\n'
                f'{sys.executable} -I -c "import time; time.sleep(300)" {marker} 300 &\nwait\n')
        start = time.monotonic()
        with self.assertRaises(AssertionError) as caught:
            self.script(body, extra=("--unshare-pid",), deadline=3)
        self.assertLess(time.monotonic() - start, 30, "the deadline must bound the run")
        report = str(caught.exception)
        self.assertIn("stalled past its 3s deadline", report)
        self.assertIn(marker + " phase", report, "the worker's stderr so far must be in it")
        self.assertIn(marker + " 300", report, "what was still running must be in it")
        ps = subprocess.run(["ps", "-eo", "args"], capture_output=True, text=True).stdout
        self.assertNotIn(marker, ps, "the stalled tree must be killed")

PRELOAD_C = r"""
#include <fcntl.h>
#include <unistd.h>
__attribute__((constructor)) static void ran(void) {
    int fd = open("/var/lib/agentos-work/preload-ran", O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) close(fd);
}
"""


class CliSandboxTest(unittest.TestCase):
    """A real Codex CLI turn under the repo's managed config and requirements, inside a stub
    worker, against a fake endpoint on the forwarder's port. CODEX_HOME/config.toml and the
    workspace's .codex/config.toml are hostile: they try to inject LD_PRELOAD and other variables
    into tools, trust the workspace, run a notify program and an MCP server, and switch to
    WebSocket transport. The tool the fake endpoint asks for is the stub tool's probe. Eight
    shipped pins are then dropped one at a time and the injection each stops must show
    (C9-C15); the others are checked statically by ManagedConfigTest only."""

    PORT = 18432  # the forwarder's port, pinned in managed config

    @classmethod
    def setUpClass(cls):
        cls.cli = os.environ.get("AGENTOS_CODEX_CLI")
        if not cls.cli:
            raise unittest.SkipTest("set AGENTOS_CODEX_CLI to a Codex CLI binary")
        if not bwrap_usable():
            raise AssertionError("AGENTOS_CODEX_CLI is set but not root with " + BWRAP)

    def setUp(self):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", self.PORT))
            except OSError:
                self.skipTest(f"port {self.PORT} is busy")
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="agentos-codex-cli-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.canary = "agentos-synthetic-canary-" + secrets.token_hex(12)
        self.fwd_dir = self.tmp / "run-agentos"
        self.fwd_dir.mkdir()
        self.fwd = _Forwarder(str(self.fwd_dir / "egress.sock"))
        self.addCleanup(self.fwd.close)
        self.preload = None
        if shutil.which("cc"):
            src = self.tmp / "preload.c"
            src.write_text(PRELOAD_C)
            so = self.tmp / "preload.so"
            if subprocess.run(["cc", "-shared", "-fPIC", "-o", str(so), str(src)]).returncode == 0:
                self.preload = so

    def hostile(self, home, work):
        (home / "config.toml").write_text(f"""\
notify = ["/bin/sh", "-c", "touch {WORK}/notify-ran"]

[model_providers.agentos]
supports_websockets = true

[features]
hooks = true
plugins = true

[shell_environment_policy.set]
LD_PRELOAD = "/var/lib/agentos-preload.so"
HOME_CANARY = "home-canary"
HOME = "{CODEX_HOME}"

[projects."{WORK}"]
trust_level = "trusted"

[mcp_servers.x]
command = "/bin/sh"
args = ["-c", "touch {WORK}/mcp-ran; sleep 2"]
""")
        (work / ".codex").mkdir()
        (work / ".codex/config.toml").write_text('model = "project-config-model"\n')

    def turn(self, config_edits=(), requirements_edits=(), auth=None, cmd=None, endpoint_env=()):
        """One CLI turn in a fresh stub worker; config files carry each (old, new) edit."""
        run = self.tmp / secrets.token_hex(4)
        home, work, etc = run / "codex-home", run / "work", run / "etc-codex"
        for d in (home, work, etc):
            d.mkdir(parents=True)
        # The placeholder login (#1015) carries the canary where a key would sit.
        (home / "auth.json").write_text(
            auth or json.dumps({"auth_mode": "apikey", "OPENAI_API_KEY": self.canary}))
        self.hostile(home, work)
        for src, edits in ((CONFIG, config_edits), (REQUIREMENTS, requirements_edits)):
            text = src.read_text()
            for old, new in edits:
                self.assertIn(old, text)
                text = text.replace(old, new, 1)
            (etc / src.name).write_text(text)
        log = run / "endpoint.log"
        cmd = cmd or f"python3 -I /var/lib/agentos-stub-tool.py probe {self.fwd.port}"
        fake = subprocess.Popen(
            [sys.executable, "-I", str(FAKE_ENDPOINT), str(self.PORT), str(log)],
            env={"PATH": os.environ["PATH"], "FAKE_CMD": cmd, "FAKE_CANARY": self.canary,
                 **dict(endpoint_env)})
        self.addCleanup(fake.wait)
        self.addCleanup(fake.kill)
        for _ in range(100):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", self.PORT)) == 0:
                    break
            threading.Event().wait(0.05)
        env = dict(e.split("=", 1) for e in json.loads(LAUNCH.read_text())["env"])
        # PATH is launch.json's own; the override is what the forwarder adds when it starts the
        # CLI (C18).
        env.update(AGENTOS_SYNTHETIC_CANARY=self.canary,
                   CODEX_REFRESH_TOKEN_URL_OVERRIDE=FORWARDER + "/oauth/token")
        argv = [
            BWRAP, "--dev-bind", "/", "/",
            "--tmpfs", "/run", "--bind", str(self.fwd_dir), "/run/agentos",
            "--tmpfs", "/tmp", "--tmpfs", "/var/tmp", "--tmpfs", "/var/lib",
            "--bind", str(home), CODEX_HOME, "--bind", str(work), WORK,
            "--ro-bind", str(etc), "/etc/codex",
            "--ro-bind", str(STUB_TOOL), "/var/lib/agentos-stub-tool.py",
            # The binary may live under /tmp, which the stub worker replaces; its directory goes
            # along, since the CLI starts helpers (the code-mode host) from beside itself.
            "--ro-bind", os.path.dirname(os.path.realpath(self.cli)), "/var/lib/agentos-cli",
            *(("--ro-bind", str(self.preload), "/var/lib/agentos-preload.so")
              if self.preload else ()),
            "--chdir", WORK, "--clearenv",
            *[a for k, v in env.items() for a in ("--setenv", k, v)],
            "--", "/var/lib/agentos-cli/" + os.path.basename(os.path.realpath(self.cli)),
            *json.loads(LAUNCH.read_text())["argv"][1:],
        ]
        r = subprocess.run(argv, input="brief", capture_output=True, text=True, timeout=120)
        fake.kill()
        self.assertTrue(log.exists(), "the CLI never reached the endpoint: " + r.stderr[-2000:])
        requests = [json.loads(line) for line in log.read_text().splitlines()]
        tool = None
        for line in r.stdout.splitlines():
            try:
                item = json.loads(line).get("item") or {}
            except ValueError:
                continue
            if item.get("type") == "command_execution" and item.get("aggregated_output"):
                for out in item["aggregated_output"].splitlines():
                    if out.startswith(('{"tcp"', '{"reread"')):
                        tool = json.loads(out)
        return {"tool": tool or {}, "requests": requests, "stdout": r.stdout, "home": home,
                "work": work,
                "marks": {m for m in ("notify-ran", "mcp-ran", "preload-ran")
                          if (work / m).exists()}}

    def refresh_turn(self, status, body, last_refresh=None):
        """A turn on a plan login whose token the CLI refreshes while the tool watches auth.json.

        The login is a placeholder shaped like the broker's (codexlogin.go AuthJSON). The fake
        answers the refresh as the egress route would (#1749): placeholders only, the id_token
        added to a dict body, or a 502 whose body is dropped. Every request, the refresh
        included, reaches the fake only because managed config points chatgpt_base_url at the
        forwarder's port (#2085). By default last_refresh is now, so the refresh comes from the
        fake refusing the tool's output with a 401; a stale last_refresh makes the CLI refresh at
        startup, before any tool runs. Returns the login, the tool's last attempt
        (stub_tool.py reread), the auth.json left on the host and the turn."""
        def jwt_part(o):
            return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        id_token = (jwt_part({"alg": "none", "typ": "JWT"}) + "." + jwt_part(
            {"exp": 4102444800, "https://api.openai.com/auth": {"chatgpt_account_id": "acct-syn"}})
            + ".unsigned")
        # A login about 8 days old is refreshed at startup, before any tool runs.
        login = {"OPENAI_API_KEY": None,
                 "last_refresh": last_refresh or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "tokens": {"id_token": id_token, "access_token": "agentos-ph-access-old",
                            "refresh_token": "agentos-ph-refresh-old", "account_id": "acct-syn"}}
        if isinstance(body, dict):
            body = dict(body, id_token=id_token)
        answer = self.tmp / "refresh.json"
        answer.write_text(json.dumps({"status": status, "body": body}))
        got = self.turn(
            auth=json.dumps(login), cmd="python3 -I /var/lib/agentos-stub-tool.py reread",
            endpoint_env={"FAKE_REFRESH": str(answer), "FAKE_YIELD_MS": "1000"})
        refreshes = [q for q in got["requests"] if q.get("path", "").endswith("/oauth/token")]
        self.assertEqual([q["refresh_token"] for q in refreshes], ["agentos-ph-refresh-old"],
                         "control: the CLI must refresh once, sending the placeholder: "
                         + got["stdout"][-2000:])
        state = got["work"] / "reread.json"
        self.assertTrue(state.exists(), "the tool never ran: " + got["stdout"][-2000:])
        tool = json.loads(state.read_text())
        self.assertFalse(tool["readable_at_start"], "control: deny_read must hide auth.json")
        return login, tool, json.loads((got["home"] / "auth.json").read_text()), got

    # REQ: CRED-5, A14
    def test_a_tool_cannot_read_auth_json_after_the_cli_rewrites_it(self):
        """#1504: the CLI rewrites auth.json in place (measured on 0.162.1: modify and
        close-write events, no create or rename), so the deny_read mask set when the tool started
        still covers the new contents, and those contents are only the route's placeholders."""
        new = {"access_token": "agentos-ph-access-new", "refresh_token": "agentos-ph-refresh-new"}
        login, tool, written, _ = self.refresh_turn(200, new)
        auth_events = [mask for name, mask in tool["events"] if name == "auth.json"]
        self.assertIn(0x8, auth_events,  # IN_CLOSE_WRITE
                      "control: the CLI must rewrite auth.json while the tool watches: "
                      + json.dumps(tool))
        self.assertIsNone(tool["reread"], "a running tool read auth.json after the CLI rewrote it")
        self.assertFalse({0x100, 0x80} & set(auth_events),  # IN_CREATE, IN_MOVED_TO
                         "the CLI now replaces auth.json by rename, past the mask (C12)")
        self.assertEqual(written["tokens"], dict(login["tokens"], **new),
                         "the CLI wrote something to CODEX_HOME beyond the route's placeholders")
        self.assertEqual(set(written), set(login))

    # REQ: CRED-5, A14
    def test_a_dropped_refresh_leaves_auth_json_as_it_was(self):
        """#1504: when the route drops a refresh answer (502), the CLI keeps the placeholder login
        and writes nothing to auth.json, so nothing new reaches CODEX_HOME."""
        login, tool, written, _ = self.refresh_turn(
            502, "egress denied: credential exchange answered with an error; dropped")
        self.assertEqual(written, login)
        self.assertNotIn("auth.json", [name for name, _ in tool["events"]])
        self.assertIsNone(tool["reread"])

    @staticmethod
    def events(got):
        out = []
        for line in got["stdout"].splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
        return out

    # REQ: CRED-5, A14
    def test_a_stale_login_refreshes_at_startup_through_the_forwarder(self):
        """#2085: a plan login due for refresh is refreshed through the forwarder before the turn
        starts, and the turn completes. This is the refresh path that works on 0.162.1 (C20)."""
        new = {"access_token": "agentos-ph-access-new", "refresh_token": "agentos-ph-refresh-new"}
        login, tool, written, got = self.refresh_turn(200, new, last_refresh="2020-01-01T00:00:00Z")
        self.assertEqual(written["tokens"], dict(login["tokens"], **new))
        self.assertNotIn("auth.json", [name for name, _ in tool["events"]],
                         "control: the refresh must land before the tool starts")
        self.assertIn("turn.completed", [e.get("type") for e in self.events(got)],
                      got["stdout"][-2000:])
        paths = {q["path"] for q in got["requests"]}
        self.assertIn("/backend-api/codex/responses", paths)

    # REQ: CRED-5, A14
    def test_a_mid_turn_refresh_loses_that_turn_and_the_next_completes(self):
        """#2085: on 0.162.1 the request the CLI retries after a mid-turn refresh goes through
        its route-aware client, which needs an [application.network] policy; without one it fails
        closed, and a policy that allows a plain-http loopback forwarder does not exist (C20). The
        bound: that one turn fails, auth.json already holds the refreshed placeholders, and the
        next turn on it completes without refreshing again. If the first turn now completes,
        the CLI changed: update C20 and drop the bound."""
        new = {"access_token": "agentos-ph-access-new", "refresh_token": "agentos-ph-refresh-new"}
        login, _, written, got = self.refresh_turn(200, new)
        kinds = [e.get("type") for e in self.events(got)]
        self.assertNotIn("turn.completed", kinds,
                         "the turn survived a mid-turn refresh: the CLI changed, update C20")
        self.assertIn("application network policy is unavailable", got["stdout"],
                      "the mid-turn refresh failed some other way: " + got["stdout"][-2000:])
        self.assertEqual(written["tokens"], dict(login["tokens"], **new))
        nxt = self.turn(auth=json.dumps(written), cmd="true")
        self.assertIn("turn.completed", [e.get("type") for e in self.events(nxt)],
                      nxt["stdout"][-2000:])
        self.assertFalse([q for q in nxt["requests"] if q.get("path", "").endswith("/oauth/token")])

    # REQ: CRED-5, CRED-1, A14, CAP-11
    def test_hostile_lower_layers_do_not_reach_the_tool(self):
        got = self.turn()
        tool, requests = got["tool"], got["requests"]
        self.assertTrue(tool, "the probe never ran: " + got["stdout"][-2000:])
        self.assertTrue(any(q["auth_canary"] for q in requests),
                        "control: the CLI itself must read the placeholder login")
        self.assertFalse(tool["tcp"], "tool reached the forwarder's loopback port")
        self.assertFalse(tool["unix"], "tool reached the egress socket")
        self.assertFalse(tool["auth"], "tool read the placeholder auth.json")
        self.assertFalse(tool["root_write"], "tool wrote outside its workspace")
        self.assertFalse(tool["codex_home_write"], "tool wrote CODEX_HOME")
        self.assertFalse(tool["slash_tmp_write"], "tool wrote /tmp")
        self.assertTrue(tool["work_write"], "tool must still write its workspace")
        # HOME and TMPDIR are the workspace, whatever a lower layer sets, so mktemp and
        # `git config --global` work (C15).
        self.assertEqual((tool["environ"].get("HOME"), tool["environ"].get("TMPDIR")),
                         (WORK, WORK))
        self.assertTrue(tool["home_write"] and tool["tmpdir_write"])
        self.assertNotIn(self.canary, json.dumps(tool), "the canary reached the tool")
        for name in ("LD_PRELOAD", "HOME_CANARY", "AGENTOS_SYNTHETIC_CANARY"):
            self.assertNotIn(name, tool["environ"])
        self.assertEqual(got["marks"], set(), "a program from a lower layer ran")
        self.assertNotIn("project-config-model", [q["model"] for q in requests])
        # Every turn asks for the pinned model, whatever the catalog says (#1396, C19).
        self.assertEqual({q["model"] for q in requests if q["method"] == "POST"}, {MODEL})
        self.assertFalse(any(q["upgrade"] for q in requests), "WebSocket transport used")

    # REQ: CRED-5, A14
    def test_each_dropped_pin_lets_its_injection_through(self):
        def shows(got, what):
            return {
                # With the allow-list gone a lower layer's `set` reaches the tool, LD_PRELOAD
                # included: the preload library, when cc could build it, runs (C8).
                "env": "HOME_CANARY" in got["tool"].get("environ", {})
                and (self.preload is None or "preload-ran" in got["marks"]),
                "websocket": any(q["upgrade"] for q in got["requests"]),
                "write CODEX_HOME": got["tool"].get("codex_home_write"),
                "write /tmp": got["tool"].get("slash_tmp_write"),
                "notify": "notify-ran" in got["marks"],
                "mcp": "mcp-ran" in got["marks"],
                "trust": "project-config-model" in [q["model"] for q in got["requests"]],
                "auth": got["tool"].get("auth"),
            }[what]
        deny = tomllib.loads(REQUIREMENTS.read_text())["permissions"]["filesystem"]["deny_read"]
        req = REQUIREMENTS.read_text()
        start = req.index("deny_read = [")
        deny_text = req[start:req.index("\n]", start) + 2]
        self.assertEqual(tomllib.loads(deny_text)["deny_read"], deny)
        mutants = {
            "env allow-list": ((('include_only = ["PATH", "HOME", "TMPDIR"]\n', ""),), (), "env"),
            "WebSocket transport": ((("supports_websockets = false\n", ""),), (), "websocket"),
            "writable roots": ((("writable_roots = []", f'writable_roots = ["{CODEX_HOME}"]'),),
                               (), "write CODEX_HOME"),
            "/tmp exclusion": ((("exclude_slash_tmp = true", "exclude_slash_tmp = false"),), (),
                               "write /tmp"),
            "notify": ((('notify = []\n', ""),), (), "notify"),
            # The managed model pin beats a trusted project's model too, so the trust mutant
            # drops it as well; the control below shows the trust pin alone still holds.
            "workspace trust": ((('trust_level = "untrusted"\n', ""), (MODEL_LINE, "")), (),
                                "trust"),
            "MCP allowlist": ((), (("[mcp_servers]\n", ""),), "mcp"),
            "deny_read": ((), ((deny_text, "deny_read = []"),), "auth"),
        }
        for name, (config_edits, requirements_edits, what) in mutants.items():
            with self.subTest(mutant=name):
                self.assertTrue(shows(self.turn(config_edits, requirements_edits), what),
                                f"{name} dropped went unnoticed")
        with self.subTest(control="model pin dropped, trust pin kept"):
            self.assertFalse(shows(self.turn(((MODEL_LINE, ""),)), "trust"),
                             "an untrusted workspace's config was loaded")


def userns_restricted():
    try:
        return pathlib.Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
                            ).read_text().strip() == "1"
    except OSError:
        return False


if __name__ == "__main__":
    unittest.main()
