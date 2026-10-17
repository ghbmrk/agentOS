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
	"testing"
	"time"
)

// fakeOneShotRunsc is a runsc that logs each call's argv to $DIR/calls,
// copies a run's config.json to $DIR/config.json, and then acts as
// $DIR/mode says: echo stdin, exit 3, sleep, or fail as runsc (a --log
// line and exit 1).
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
	return &Runtime{Bin: bin, StateDir: filepath.Join(d, "state")}, d
}

func oneShot(argv ...string) OneShot {
	return OneShot{Name: "t", Root: "/nonexistent-root", Argv: argv, MaxOutput: 1 << 10, MemBytes: 64 << 20, Timeout: 5 * time.Second}
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
// capabilities or new privileges, an unprivileged user, the memory limit,
// and no mount but /proc (ARC-5).
func TestRunOnceBundle(t *testing.T) {
	r, d := oneShotRig(t, "echo")
	o := oneShot("/prog", "a")
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
		Mounts []struct{ Destination, Type string }
		Linux  struct{ Namespaces []struct{ Type string } }
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
	data := false
	for _, l := range p.Rlimits {
		data = data || l.Type == "RLIMIT_DATA" && l.Hard == o.MemBytes && l.Soft == o.MemBytes
	}
	if !data {
		t.Errorf("rlimits %+v lack RLIMIT_DATA %d", p.Rlimits, o.MemBytes)
	}
	if strings.Join(p.Args, " ") != "/prog a" || spec.Root.Path != o.Root || !spec.Root.Readonly {
		t.Errorf("args %v, root %+v", p.Args, spec.Root)
	}
	if len(spec.Mounts) != 1 || spec.Mounts[0].Destination != "/proc" {
		t.Errorf("mounts %+v, want only /proc", spec.Mounts)
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
	for _, mode := range []string{"echo", "exit3", "fail", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			r, d := oneShotRig(t, mode)
			o := oneShot("/prog")
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
		})
	}
}

// TestRunOnceResults: the program's exit code and output are its own;
// output past MaxOutput is cut and reported; a runsc failure answers
// ErrOneShotFailed with none of runsc's text; the deadline answers the
// context's error.
func TestRunOnceResults(t *testing.T) {
	r, _ := oneShotRig(t, "exit3")
	res, err := r.RunOnce(context.Background(), oneShot("/prog"))
	if err != nil || res.ExitCode != 3 || string(res.Stdout) != "out\n" || string(res.Stderr) != "err\n" {
		t.Errorf("exit3: %+v, %v", res, err)
	}
	r, _ = oneShotRig(t, "big")
	res, err = r.RunOnce(context.Background(), oneShot("/prog"))
	if err != nil || len(res.Stdout) != 1<<10 || !res.Truncated {
		t.Errorf("big: %d bytes, truncated %v, %v", len(res.Stdout), res.Truncated, err)
	}
	r, _ = oneShotRig(t, "fail")
	res, err = r.RunOnce(context.Background(), oneShot("/prog"))
	if !errors.Is(err, ErrOneShotFailed) || len(res.Stderr) > 0 || strings.Contains(err.Error(), "FAKE") {
		t.Errorf("fail: %+v, %v", res, err)
	}
	if b, _ := os.ReadFile(r.execLog()); !strings.Contains(string(b), "FAKE-RUNSC-FAILURE") {
		t.Errorf("exec log lacks runsc's message: %q", b)
	}
	r, _ = oneShotRig(t, "sleep")
	o := oneShot("/prog")
	o.Timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := r.RunOnce(context.Background(), o); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("sleep: %v", err)
	}
	if d := time.Since(start); d > ExecWaitDelay+5*time.Second {
		t.Errorf("sleep took %v", d)
	}
	for _, bad := range []OneShot{{}, {Name: "a_b", Argv: []string{"x"}, MemBytes: 1, Timeout: 1}, {Name: "a", Argv: []string{"x"}, Timeout: 1}, {Name: "a", Argv: []string{"x"}, MemBytes: 1}} {
		if _, err := r.RunOnce(context.Background(), bad); err == nil {
			t.Errorf("RunOnce(%+v) ran", bad)
		}
	}
}

// oneShotRoot builds testdata/oneshot into a root directory for RunOnce
// with a real runsc; the tests skip without one, like the package's others.
func oneShotRoot(t *testing.T) (*Runtime, string) {
	t.Helper()
	bin := os.Getenv("AGENTOS_RUNSC")
	if bin == "" || os.Geteuid() != 0 {
		t.Skip("set AGENTOS_RUNSC to a runsc binary and run as root (CI integration job)")
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
	return &Runtime{Bin: bin, StateDir: filepath.Join(t.TempDir(), "runsc")}, root
}

func realOneShot(root string, args ...string) OneShot {
	return OneShot{Name: "it", Root: root, Argv: append([]string{"/oneshot"}, args...), MaxOutput: 1 << 20, MemBytes: 64 << 20, Timeout: 20 * time.Second}
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

// TestRunOnceReadOnlyRoot: the program writes nowhere, its own binary
// included, and the host root is untouched.
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

// TestRunOnceMemoryCap: the program is held to MemBytes. Under the cap it
// runs; asking for four times the cap, it dies rather than gets it.
func TestRunOnceMemoryCap(t *testing.T) {
	r, root := oneShotRoot(t)
	res, err := r.RunOnce(context.Background(), realOneShot(root, "alloc", "16"))
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("16 MiB under a 64 MiB cap: %+v, %v", res, err)
	}
	res, err = r.RunOnce(context.Background(), realOneShot(root, "alloc", "256"))
	if err != nil || res.ExitCode == 0 || strings.Contains(string(res.Stdout), "allocated") {
		t.Fatalf("256 MiB under a 64 MiB cap: exit %d, %q, %v", res.ExitCode, res.Stdout, err)
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
