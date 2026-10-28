package gvisor

// REQ: NET-2

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// fakeStreamRunsc is fakeOneShotRunsc for streams: it logs each call,
// copies a run's config.json, and acts as $DIR/mode says: echo stdin
// until it ends, fail as runsc, or be killed at the memory cap (an OOM
// kill counted in $DIR/cg/stream-t).
const fakeStreamRunsc = `#!/bin/sh
D=%DIR%
echo "$*" >> $D/calls
log=
for a; do case "$a" in --log=*) log=${a#--log=};; esac; done
case " $* " in *" run --bundle "*) ;; *) exit 0;; esac
b=$(echo "$*" | sed 's/.* run --bundle \([^ ]*\) .*/\1/')
cp "$b/config.json" $D/config.json
case "$(cat $D/mode)" in
echo) exec cat;;
fail) echo '{"msg":"FAKE-RUNSC-FAILURE"}' > "$log"; exit 1;;
oom) echo "oom_kill 1" > $D/cg/stream-t/memory.events; exit 137;;
esac
`

func streamRig(t *testing.T, mode string) (*Runtime, string) {
	t.Helper()
	d := t.TempDir()
	bin := filepath.Join(d, "runsc")
	if err := os.WriteFile(bin, []byte(strings.ReplaceAll(fakeStreamRunsc, "%DIR%", d)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "mode"), []byte(mode), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(d, "cg", "stream-t"), 0o700); err != nil {
		t.Fatal(err)
	}
	for f, v := range map[string]string{"cg/cgroup.controllers": "cpu io memory pids", "cg/cgroup.subtree_control": "",
		"cg/stream-t/memory.events": "oom_kill 0\n", "cg/stream-t/cgroup.events": "populated 0\n"} {
		if err := os.WriteFile(filepath.Join(d, f), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := startIn
	startIn = func(path string, _ *childproc.Options) (func(), error) {
		return func() {}, os.WriteFile(filepath.Join(d, "startedin"), []byte(path), 0o600)
	}
	t.Cleanup(func() { startIn = old })
	return &Runtime{Bin: bin, StateDir: filepath.Join(d, "state")}, d
}

func streamIn(d string) Stream {
	return Stream{Name: "t", Root: "/nonexistent-root", Argv: []string{"/agentos-camdecode", "-video", "8x8"},
		MemBytes: 64 << 20, Cgroup: filepath.Join(d, "cg")}
}

// TestDecoderHasNoNetwork: a camera decoder's sandbox is started with
// runsc's --network=none and an empty network namespace of its own, a
// read-only root, no capabilities, an unprivileged user, no mount but
// /proc and a read-only /tmp, and in its own cgroup at its memory cap
// (NET-2: decoded in a sandbox; ARC-5).
func TestDecoderHasNoNetwork(t *testing.T) {
	r, d := streamRig(t, "echo")
	s := streamIn(d)
	run, err := r.StartStream(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Stop()
	// One round trip: the program, so the fake's copy of the bundle, runs.
	run.In().Write([]byte("x"))
	if _, err := io.ReadFull(run.Out(), make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	var runArgv string
	for _, c := range calls(t, d) {
		if strings.Contains(c, " run ") {
			runArgv = c
		}
	}
	if !strings.Contains(runArgv, "--network=none") || !strings.Contains(runArgv, "--root "+r.StateDir) {
		t.Errorf("run argv %q", runArgv)
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
			Args            []string
		}
		Root struct {
			Path     string
			Readonly bool
		}
		Mounts []struct {
			Destination, Type string
			Options           []string
		}
		Linux struct {
			Namespaces []struct{ Type, Path string }
		}
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
	if strings.Join(p.Args, " ") != strings.Join(s.Argv, " ") || spec.Root.Path != s.Root || !spec.Root.Readonly {
		t.Errorf("args %v, root %+v", p.Args, spec.Root)
	}
	if len(spec.Mounts) != 2 || spec.Mounts[0].Destination != "/proc" || spec.Mounts[1].Destination != "/tmp" ||
		len(spec.Mounts[1].Options) == 0 || spec.Mounts[1].Options[0] != "ro" {
		t.Errorf("mounts %+v", spec.Mounts)
	}
	netns := false
	for _, n := range spec.Linux.Namespaces {
		if n.Type == "network" && n.Path == "" {
			netns = true
		}
	}
	if !netns {
		t.Errorf("no fresh network namespace: %+v", spec.Linux.Namespaces)
	}
	leaf := filepath.Join(d, "cg", "stream-t")
	if b, err := os.ReadFile(filepath.Join(d, "startedin")); err != nil || string(b) != leaf {
		t.Errorf("runsc started in %q, %v; want %s", b, err, leaf)
	}
	for f, want := range map[string]string{"memory.max": "67108864", "memory.swap.max": "0", "memory.oom.group": "1", "pids.max": "256"} {
		if b, err := os.ReadFile(filepath.Join(leaf, f)); err != nil || string(b) != want {
			t.Errorf("%s = %q, %v; want %q", f, b, err, want)
		}
	}
}

// TestStreamFeedsAndStops: bytes written to the run reach the program
// and its output comes back while it runs; Stop kills and deletes the
// sandbox, removes its bundle, and closes both ends.
func TestStreamFeedsAndStops(t *testing.T) {
	r, d := streamRig(t, "echo")
	run, err := r.StartStream(context.Background(), streamIn(d))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.In().Write([]byte("frame")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(run.Out(), got); err != nil || string(got) != "frame" {
		t.Fatalf("read %q, %v", got, err)
	}
	run.Stop()
	run.Stop()
	select {
	case <-run.Done():
	default:
		t.Fatal("Done not closed after Stop")
	}
	if _, err := run.In().Write([]byte("x")); err == nil {
		t.Error("stdin still open after Stop")
	}
	last := calls(t, d)
	var tail []string
	for _, c := range last {
		if f := strings.Fields(c); len(f) > 0 && (strings.Contains(c, " kill ") || strings.Contains(c, " delete ")) {
			tail = append(tail, c)
		}
	}
	if len(tail) < 4 || !strings.Contains(tail[len(tail)-1], "delete -force stream-t_") {
		t.Errorf("kill and delete calls %q", tail)
	}
	if _, err := os.Stat(filepath.Join(r.StateDir, "stream-t")); !os.IsNotExist(err) {
		t.Errorf("bundle directory left: %v", err)
	}
}

// TestStreamEndReported: a run's end is reported as the memory cap or a
// runsc failure, and the sandbox is deleted without a Stop.
func TestStreamEndReported(t *testing.T) {
	for mode, want := range map[string]error{"oom": ErrOneShotMemory, "fail": ErrOneShotFailed} {
		t.Run(mode, func(t *testing.T) {
			r, d := streamRig(t, mode)
			run, err := r.StartStream(context.Background(), streamIn(d))
			if err != nil {
				t.Fatal(err)
			}
			defer run.Stop()
			select {
			case <-run.Done():
			case <-time.After(10 * time.Second):
				t.Fatal("run did not end")
			}
			if err := run.Err(); !errors.Is(err, want) {
				t.Errorf("Err = %v, want %v", err, want)
			}
			if _, err := io.ReadAll(run.Out()); err != nil {
				t.Errorf("stdout did not end cleanly: %v", err)
			}
		})
	}
}

// TestStreamOneAtATime: a second start of a name waits until the first
// run is stopped, so two sandboxes never share a container ID.
func TestStreamOneAtATime(t *testing.T) {
	r, d := streamRig(t, "echo")
	first, err := r.StartStream(context.Background(), streamIn(d))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan *StreamRun)
	go func() {
		second, err := r.StartStream(context.Background(), streamIn(d))
		if err != nil {
			t.Error(err)
		}
		started <- second
	}()
	select {
	case <-started:
		t.Fatal("second run started while the first ran")
	case <-time.After(200 * time.Millisecond):
	}
	first.Stop()
	select {
	case second := <-started:
		if second != nil {
			second.Stop()
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second run never started")
	}
}

// TestStreamBadSpec: a stream with no name, a name runsc would read as
// another ID, no program, no memory cap or no cgroup is refused before
// anything starts.
func TestStreamBadSpec(t *testing.T) {
	r, d := streamRig(t, "echo")
	for _, mut := range []func(*Stream){
		func(s *Stream) { s.Name = "" }, func(s *Stream) { s.Name = "a_b" }, func(s *Stream) { s.Name = "a/b" },
		func(s *Stream) { s.Argv = nil }, func(s *Stream) { s.MemBytes = 0 }, func(s *Stream) { s.Cgroup = "" },
	} {
		s := streamIn(d)
		mut(&s)
		if run, err := r.StartStream(context.Background(), s); err == nil {
			run.Stop()
			t.Errorf("%+v started", s)
		}
	}
	if _, err := os.Stat(filepath.Join(d, "calls")); !os.IsNotExist(err) {
		t.Errorf("runsc called for a bad spec: %v", err)
	}
}

// realStream is realOneShot's program as a stream.
func realStream(root string, args ...string) Stream {
	return Stream{Name: "it", Root: root, Argv: append([]string{"/oneshot"}, args...), MemBytes: 64 << 20,
		Cgroup: os.Getenv("AGENTOS_CGROUP_PARENT")}
}

// TestStreamRealNoNetwork: under runsc, a stream's program sees only
// loopback and cannot dial out (CI integration job).
func TestStreamRealNoNetwork(t *testing.T) {
	r, root := oneShotRoot(t)
	run, err := r.StartStream(context.Background(), realStream(root, "net", "1.1.1.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer run.Stop()
	b, _ := io.ReadAll(run.Out())
	out := string(b)
	if !strings.Contains(out, "dial failed") {
		t.Errorf("program dialled out: %q", out)
	}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(l, "iface ") && l != "iface lo" {
			t.Errorf("program sees %q", l)
		}
	}
}

// TestStreamRealMemoryCap: under runsc, a stream asking for four times
// its cap is killed and reports the cap, and its cgroup is gone after.
func TestStreamRealMemoryCap(t *testing.T) {
	r, root := oneShotRoot(t)
	run, err := r.StartStream(context.Background(), realStream(root, "alloc", "256"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(run.Out())
	if err := run.Err(); !errors.Is(err, ErrOneShotMemory) || strings.Contains(string(b), "allocated") {
		t.Fatalf("256 MiB under a 64 MiB cap: %q, %v", b, err)
	}
	run.Stop()
	if _, err := os.Stat(filepath.Join(os.Getenv("AGENTOS_CGROUP_PARENT"), "stream-it")); !os.IsNotExist(err) {
		t.Errorf("stream's cgroup left: %v", err)
	}
}
