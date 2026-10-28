package gvisor

// REQ: ARC-5

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// fakeOneShotRunsc is a runsc that logs each call's argv to $DIR/calls,
// copies a run's config.json to $DIR/config.json, and then acts as
// $DIR/mode says: echo stdin, exit 3, sleep, fail as runsc (a --log
// line and exit 1), or be killed at the memory cap (an OOM kill counted
// in the run's group, $DIR/cg/oneshot-t, and exit 137).
const fakeOneShotRunsc = `#!/bin/sh
D=%DIR%
echo "$*" >> $D/calls
log=
for a; do case "$a" in --log=*) log=${a#--log=};; esac; done
case " $* " in *" run --bundle "*) ;; *) exit 0;; esac
b=$(echo "$*" | sed 's/.* run --bundle \([^ ]*\) .*/\1/')
cp "$b/config.json" $D/config.json
case "$(cat $D/mode)" in
echo) cat;;
exit3) echo out; echo err >&2; exit 3;;
big) head -c 5000 /dev/zero;;
sleep) exec sleep 30;;
fail) echo '{"msg":"FAKE-RUNSC-FAILURE"}' > "$log"; echo FAKE-RUNSC-FAILURE >&2; exit 1;;
oom) echo out; echo "oom_kill 1" > $D/cg/oneshot-t/memory.events; exit 137;;
esac
`

func oneShotRig(t *testing.T, mode string) (*Runtime, string) {
	t.Helper()
	d := t.TempDir()
	bin := filepath.Join(d, "runsc")
	if err := os.WriteFile(bin, []byte(strings.ReplaceAll(fakeOneShotRunsc, "%DIR%", d)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "mode"), []byte(mode), 0o600); err != nil {
		t.Fatal(err)
	}
	// A cgroup parent of plain files, and the run's group already in it
	// holding the files the kernel would give it, which RunOnce reuses.
	leaf := filepath.Join(d, "cg", "oneshot-t")
	if err := os.MkdirAll(leaf, 0o700); err != nil {
		t.Fatal(err)
	}
	for f, v := range map[string]string{"cg/cgroup.controllers": "cpu io memory pids", "cg/cgroup.subtree_control": "",
		"cg/oneshot-t/memory.events": "oom_kill 0\n", "cg/oneshot-t/cgroup.events": "populated 0\n"} {
		if err := os.WriteFile(filepath.Join(d, f), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The fake's group is no cgroup to clone3 into; record it instead.
	old := startIn
	startIn = func(path string, _ *childproc.Options) (func(), error) {
		return func() {}, os.WriteFile(filepath.Join(d, "startedin"), []byte(path), 0o600)
	}
	t.Cleanup(func() { startIn = old })
	return &Runtime{Bin: bin, StateDir: filepath.Join(d, "state")}, d
}

func oneShot(argv ...string) OneShot {
	return OneShot{Name: "t", Root: "/nonexistent-root", Argv: argv, MaxOutput: 1 << 10, MemBytes: 64 << 20, Timeout: 5 * time.Second, Cgroup: "%CG%"}
}

// oneShotIn is oneShot run under the rig in d's cgroup parent.
func oneShotIn(d string, argv ...string) OneShot {
	o := oneShot(argv...)
	o.Cgroup = filepath.Join(d, "cg")
	return o
}

func calls(t *testing.T, d string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(d, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// TestRunOnceBundle: the sandbox has no network, a read-only root, no
// capabilities or new privileges, an unprivileged user, and no mount but
// /proc and a read-only /tmp; runsc starts in the run's own cgroup, which
// holds it to MemBytes with no swap and a task cap (ARC-5).
func TestRunOnceBundle(t *testing.T) {
	r, d := oneShotRig(t, "echo")
	o := oneShotIn(d, "/prog", "a")
	o.Stdin = []byte("in")
	res, err := r.RunOnce(context.Background(), o)
	if err != nil || string(res.Stdout) != "in" || res.ExitCode != 0 {
		t.Fatalf("RunOnce = %+v, %v", res, err)
	}
	var run string
	for _, c := range calls(t, d) {
		if strings.Contains(c, " run ") {
			run = c
		}
	}
	for _, want := range []string{"--network=none", "--root " + r.StateDir, "run --bundle "} {
		if !strings.Contains(run, want) {
			t.Errorf("run argv %q lacks %q", run, want)
		}
	}
	b, err := os.ReadFile(filepath.Join(d, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Process struct {
			User            struct{ UID, GID int }
			Capabilities    map[string][]string
			NoNewPrivileges bool
			Rlimits         []struct {
				Type       string
				Hard, Soft int64
			}
			Args []string
		}
		Root struct {
			Path     string
			Readonly bool
		}
		Mounts []struct {
			Destination, Type string
			Options           []string
		}
		Linux struct{ Namespaces []struct{ Type string } }
	}
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	p := spec.Process
	if p.User.UID == 0 || p.User.GID == 0 || !p.NoNewPrivileges {
		t.Errorf("process runs as %+v, noNewPrivileges %v", p.User, p.NoNewPrivileges)
	}
	for k, v := range p.Capabilities {
		if len(v) > 0 {
			t.Errorf("capabilities %s = %v", k, v)
		}
	}
	leaf := filepath.Join(d, "cg", "oneshot-t")
	if b, err := os.ReadFile(filepath.Join(d, "startedin")); err != nil || string(b) != leaf {
		t.Errorf("runsc started in %q, %v; want %s", b, err, leaf)
	}
	for f, want := range map[string]string{"memory.max": "67108864", "memory.high": "67108864", "memory.swap.max": "0", "memory.oom.group": "1", "pids.max": "256", "cpu.max": "100000 100000"} {
		if b, err := os.ReadFile(filepath.Join(leaf, f)); err != nil || string(b) != want {
			t.Errorf("%s = %q, %v; want %q", f, b, err, want)
		}
	}
	if strings.Join(p.Args, " ") != "/prog a" || spec.Root.Path != o.Root || !spec.Root.Readonly {
		t.Errorf("args %v, root %+v", p.Args, spec.Root)
	}
	if len(spec.Mounts) != 2 || spec.Mounts[0].Destination != "/proc" || spec.Mounts[1].Destination != "/tmp" ||
		spec.Mounts[1].Type != "tmpfs" || len(spec.Mounts[1].Options) == 0 || spec.Mounts[1].Options[0] != "ro" {
		t.Errorf("mounts %+v, want only /proc and a read-only /tmp", spec.Mounts)
	}
	ns := map[string]bool{}
	for _, n := range spec.Linux.Namespaces {
		ns[n.Type] = true
	}
	for _, n := range []string{"pid", "network", "ipc", "uts", "mount"} {
		if !ns[n] {
			t.Errorf("no %s namespace", n)
		}
	}
}

// TestRunOnceRemovesSandbox: on every return path the sandbox is killed
// and deleted after the run, and one left under the name is killed and
// deleted before it; the bundle does not outlive the run.
func TestRunOnceRemovesSandbox(t *testing.T) {
	for _, mode := range []string{"echo", "exit3", "fail", "sleep", "oom"} {
		t.Run(mode, func(t *testing.T) {
			r, d := oneShotRig(t, mode)
			o := oneShotIn(d, "/prog")
			o.Timeout = time.Second
			r.RunOnce(context.Background(), o)
			var verbs []string
			for _, c := range calls(t, d) {
				f := strings.Fields(c)
				for i, w := range f {
					if w == "kill" || w == "delete" || w == "run" {
						verbs = append(verbs, w+" "+strings.Join(f[i+1:], " "))
						break
					}
				}
			}
			id := cid("oneshot-t")
			want := []string{"kill " + id + " KILL", "delete -force " + id, "run", "kill " + id + " KILL", "delete -force " + id}
			if len(verbs) != len(want) {
				t.Fatalf("runsc calls %q, want %q", verbs, want)
			}
			for i := range want {
				if !strings.HasPrefix(verbs[i], want[i]) {
					t.Fatalf("runsc calls %q, want %q", verbs, want)
				}
			}
			if _, err := os.Stat(filepath.Join(r.StateDir, "oneshot-t")); !os.IsNotExist(err) {
				t.Errorf("bundle directory left: %v", err)
			}
			if _, err := os.Stat(filepath.Join(d, "cg", "oneshot-t", "cgroup.kill")); err != nil {
				t.Errorf("run's cgroup not killed: %v", err)
			}
		})
	}
}

// TestRunOnceResults: the program's exit code and output are its own;
// output past MaxOutput is cut and reported; a runsc failure answers
// ErrOneShotFailed with none of runsc's text; a kill at the memory cap
// answers ErrOneShotMemory, but one counted before the run does not; the
// deadline answers the context's error; a run with no cgroup does not
// start.
func TestRunOnceResults(t *testing.T) {
	r, d := oneShotRig(t, "exit3")
	res, err := r.RunOnce(context.Background(), oneShotIn(d, "/prog"))
	if err != nil || res.ExitCode != 3 || string(res.Stdout) != "out\n" || string(res.Stderr) != "err\n" {
		t.Errorf("exit3: %+v, %v", res, err)
	}
	r, d = oneShotRig(t, "big")
	res, err = r.RunOnce(context.Background(), oneShotIn(d, "/prog"))
	if err != nil || len(res.Stdout) != 1<<10 || !res.Truncated {
		t.Errorf("big: %d bytes, truncated %v, %v", len(res.Stdout), res.Truncated, err)
	}
	r, d = oneShotRig(t, "fail")
	res, err = r.RunOnce(context.Background(), oneShotIn(d, "/prog"))
	if !errors.Is(err, ErrOneShotFailed) || len(res.Stderr) > 0 || strings.Contains(err.Error(), "FAKE") {
		t.Errorf("fail: %+v, %v", res, err)
	}
	if b, _ := os.ReadFile(r.execLog()); !strings.Contains(string(b), "FAKE-RUNSC-FAILURE") {
		t.Errorf("exec log lacks runsc's message: %q", b)
	}
	r, d = oneShotRig(t, "oom")
	if res, err := r.RunOnce(context.Background(), oneShotIn(d, "/prog")); !errors.Is(err, ErrOneShotMemory) || len(res.Stdout) > 0 {
		t.Errorf("oom: %+v, %v", res, err)
	}
	r, d = oneShotRig(t, "echo")
	if err := os.WriteFile(filepath.Join(d, "cg", "oneshot-t", "memory.events"), []byte("oom_kill 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RunOnce(context.Background(), oneShotIn(d, "/prog")); err != nil {
		t.Errorf("earlier kills counted against the run: %v", err)
	}
	if err := os.Remove(filepath.Join(d, "startedin")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RunOnce(context.Background(), oneShot("/prog")); err == nil {
		t.Error("ran with no usable cgroup")
	}
	if _, err := os.Stat(filepath.Join(d, "startedin")); !os.IsNotExist(err) {
		t.Errorf("runsc started with no usable cgroup: %v", err)
	}
	r, d = oneShotRig(t, "sleep")
	o := oneShotIn(d, "/prog")
	o.Timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := r.RunOnce(context.Background(), o); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("sleep: %v", err)
	}
	if d := time.Since(start); d > ExecWaitDelay+5*time.Second {
		t.Errorf("sleep took %v", d)
	}
	ok := OneShot{Name: "a", Argv: []string{"x"}, MemBytes: 1, Timeout: 1, Cgroup: filepath.Join(d, "cg")}
	bads := []OneShot{{}, ok, ok, ok, ok, ok}
	bads[1].Name, bads[2].Name, bads[3].MemBytes, bads[4].Timeout, bads[5].Cgroup = "a_b", "a.b", 0, 0, ""
	for _, bad := range bads {
		if _, err := r.RunOnce(context.Background(), bad); err == nil {
			t.Errorf("RunOnce(%+v) ran", bad)
		}
	}
}

// oneShotRoot builds testdata/oneshot into a root directory for RunOnce
// with a real runsc and a real cgroup v2 parent; the tests skip without
// them, like the package's others. realOneShot runs under that parent.
func oneShotRoot(t *testing.T) (*Runtime, string) {
	t.Helper()
	bin, cg := os.Getenv("AGENTOS_RUNSC"), os.Getenv("AGENTOS_CGROUP_PARENT")
	if bin == "" || cg == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC to a runsc binary and AGENTOS_CGROUP_PARENT to a cgroup v2 group, and run as root (CI integration job)")
	}
	root := t.TempDir()
	for _, d := range []string{"proc", "dev", "sys"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	build := exec.Command("go", "build", "-o", filepath.Join(root, "oneshot"), "./testdata/oneshot")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building oneshot: %v\n%s", err, out)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Bin: bin, StateDir: filepath.Join(t.TempDir(), "runsc")}
	// --network=none leaves a bind mount runsc does not remove.
	t.Cleanup(func() { syscall.Unmount(filepath.Join(r.StateDir, "null-netns"), syscall.MNT_DETACH) })
	return r, root
}

func realOneShot(root string, args ...string) OneShot {
	return OneShot{Name: "it", Root: root, Argv: append([]string{"/oneshot"}, args...), MaxOutput: 1 << 20, MemBytes: 64 << 20, Timeout: 20 * time.Second,
		Cgroup: os.Getenv("AGENTOS_CGROUP_PARENT")}
}

// TestRunOnceNoNetwork: the program sees only loopback and cannot dial
// out, to an address the host itself can reach included.
func TestRunOnceNoNetwork(t *testing.T) {
	r, root := oneShotRoot(t)
	res, err := r.RunOnce(context.Background(), realOneShot(root, "net", "1.1.1.1:53"))
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("RunOnce = %+v, %v", res, err)
	}
	out := string(res.Stdout)
	if !strings.Contains(out, "dial failed") {
		t.Errorf("program dialled out: %q", out)
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(l, "iface ") && l != "iface lo" {
			t.Errorf("program sees %q", l)
		}
	}
}

// TestRunOnceReadOnlyRoot: the program writes nowhere, /tmp, /dev and
// its own binary included, and the host root is untouched.
func TestRunOnceReadOnlyRoot(t *testing.T) {
	r, root := oneShotRoot(t)
	res, err := r.RunOnce(context.Background(), realOneShot(root, "write"))
	if err != nil || res.ExitCode != 0 || strings.TrimSpace(string(res.Stdout)) != "done" {
		t.Fatalf("RunOnce = %+v (%q), %v", res, res.Stdout, err)
	}
	if _, err := os.Stat(filepath.Join(root, "x")); !os.IsNotExist(err) {
		t.Errorf("root gained /x: %v", err)
	}
}

// TestRunOnceMemoryCap: the run is held to MemBytes. Under the cap it
// runs; asking for four times the cap, it is killed rather than gets it,
// and the run's cgroup is gone after.
func TestRunOnceMemoryCap(t *testing.T) {
	r, root := oneShotRoot(t)
	res, err := r.RunOnce(context.Background(), realOneShot(root, "alloc", "16"))
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("16 MiB under a 64 MiB cap: %+v, %v", res, err)
	}
	res, err = r.RunOnce(context.Background(), realOneShot(root, "alloc", "256"))
	if !errors.Is(err, ErrOneShotMemory) || strings.Contains(string(res.Stdout), "allocated") {
		t.Fatalf("256 MiB under a 64 MiB cap: exit %d, %q, %v", res.ExitCode, res.Stdout, err)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("AGENTOS_CGROUP_PARENT"), "oneshot-it")); !os.IsNotExist(err) {
		t.Errorf("run's cgroup left: %v", err)
	}
}

// TestRunOnceTimeoutKills: at the deadline the run ends with the
// context's error, and the sandbox is gone: a run of the same name
// starts and finishes after it.
func TestRunOnceTimeoutKills(t *testing.T) {
	r, root := oneShotRoot(t)
	o := realOneShot(root, "sleep")
	o.Timeout = 3 * time.Second
	start := time.Now()
	if _, err := r.RunOnce(context.Background(), o); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RunOnce = %v, want the deadline", err)
	}
	if d := time.Since(start); d > o.Timeout+ExecWaitDelay+oneShotCleanup {
		t.Errorf("run took %v past its deadline", d)
	}
	out, _ := exec.Command(r.Bin, "--root", r.StateDir, "list", "-quiet").Output()
	if strings.Contains(string(out), cid("oneshot-it")) {
		t.Errorf("sandbox still listed: %q", out)
	}
	o = realOneShot(root, "echo")
	o.Stdin = []byte("again")
	if res, err := r.RunOnce(context.Background(), o); err != nil || string(res.Stdout) != "again" {
		t.Errorf("next run: %+v, %v", res, err)
	}
}
