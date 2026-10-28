package supervise

// REQ: RES-2, DEV-7

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/cgroup"
)

// helperArg makes the test binary the service stand-in: it serves the
// listener on fd 3, answering each connection with one JSON line about
// itself, as the mode asks.
const helperArg = "vision-supervise-helper"

// The service's user in these tests: nobody.
const testUID, testGID = 65534, 65534

// canary is what the noisy helper writes to its stdout and stderr.
const canary = "VISION-CANARY-ENCODING-0.125,0.5,0.875"

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == helperArg {
		os.Exit(helper(os.Args[2]))
	}
	os.Exit(m.Run())
}

func helper(mode string) int {
	switch mode {
	case "noisy":
		fmt.Fprintln(os.Stdout, canary)
		fmt.Fprintln(os.Stderr, canary)
		return 3
	case "alloc":
		var keep [][]byte
		for {
			b := make([]byte, 8<<20)
			for i := range b {
				b[i] = 1
			}
			keep = append(keep, b)
		}
	}
	ln, err := net.FileListener(os.NewFile(3, "listener"))
	if err != nil {
		return 4
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return 5
		}
		b, _ := json.Marshal(probe(mode))
		c.Write(append(b, '\n'))
		c.Close()
	}
}

func probe(mode string) string {
	switch mode {
	case "cgroup":
		b, _ := os.ReadFile("/proc/self/cgroup")
		return string(b)
	case "jail":
		b, _ := os.ReadFile("/proc/self/status")
		var keep []string
		for _, l := range strings.Split(string(b), "\n") {
			for _, k := range []string{"Uid:", "NoNewPrivs:", "CapEff:"} {
				if strings.HasPrefix(l, k) {
					keep = append(keep, strings.Join(strings.Fields(l), " "))
				}
			}
		}
		_, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("tcp", "192.0.2.1:9")
		if errors.Is(err, syscall.ENETUNREACH) {
			keep = append(keep, "net: ENETUNREACH")
		}
		return strings.Join(keep, "\n")
	}
	return "unknown mode"
}

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the service runs as another user in new namespaces (CI machines job)")
	}
}

// service starts the helper in mode under Start and returns its
// supervisor and socket.
func service(t *testing.T, o Options, mode string) (*Supervisor, string) {
	t.Helper()
	base, err := os.MkdirTemp("", "vision-supervise-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	o.Path = filepath.Join(base, "helper")
	if err := os.WriteFile(o.Path, b, 0o755); err != nil {
		t.Fatal(err)
	}
	o.Args = []string{helperArg, mode}
	o.Socket = filepath.Join(base, "run", "vision.sock")
	o.UID, o.GID = testUID, testGID
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Start(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		<-s.Done()
	})
	return s, o.Socket
}

// ask dials the service until it answers, and returns its answer.
func ask(t *testing.T, sock string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("unix", sock, time.Second)
		if err == nil {
			c.SetDeadline(time.Now().Add(5 * time.Second))
			line, rerr := bufio.NewReader(c).ReadBytes('\n')
			c.Close()
			var s string
			if rerr == nil && json.Unmarshal(line, &s) == nil {
				return s
			}
			err = fmt.Errorf("bad answer %q: %v", line, rerr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("service never answered on %s: %v", sock, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func cgroupParent(t *testing.T) *cgroup.Group {
	t.Helper()
	needRoot(t)
	p := os.Getenv("AGENTOS_CGROUP_PARENT")
	if p == "" {
		t.Skip("set AGENTOS_CGROUP_PARENT to a writable cgroup v2 group (CI machines job)")
	}
	dir := filepath.Join(p, fmt.Sprintf("vision-%d", time.Now().UnixNano()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := cgroup.Open(dir)
	if err != nil {
		os.Remove(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, c := range []string{"inference", "broker", "browser", "machines"} {
			g := &cgroup.Group{Path: filepath.Join(dir, c)}
			g.Kill(ctx)
			g.Remove()
		}
		os.Remove(dir)
	})
	return root
}

func TestStartRefusesRootAndRelativePaths(t *testing.T) {
	for name, o := range map[string]Options{
		"root":            {Path: "/bin/true", Socket: "/run/v.sock"},
		"relative binary": {Path: "true", Socket: "/run/v.sock", UID: testUID, GID: testGID},
	} {
		if _, err := Start(context.Background(), o); err == nil {
			t.Errorf("%s: started", name)
		}
	}
}

// RES-2: the vision service runs in the inference leaf, whose memory.max
// is the budget's InferenceMB.
func TestVisionRunsInInferenceLeaf(t *testing.T) {
	root := cgroupParent(t)
	m := budget.Memory{HostMB: 16, InferenceMB: 64, PoolMB: 64, HeadroomMB: 16}
	g, err := m.Apply(root)
	if err != nil {
		t.Fatal(err)
	}
	_, sock := service(t, Options{Cgroup: g.Inference}, "cgroup")
	got := ask(t, sock)
	rel := strings.TrimPrefix(g.Inference.Path, "/sys/fs/cgroup")
	if strings.TrimSpace(got) != "0::"+rel {
		t.Fatalf("service cgroup %q, want 0::%s", got, rel)
	}
	b, err := os.ReadFile(filepath.Join(g.Inference.Path, "memory.max"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != strconv.FormatInt(m.InferenceMB<<20, 10) {
		t.Fatalf("leaf memory.max %s, want %d MiB", b, m.InferenceMB)
	}
}

// RES-2: a vision service allocating past the leaf's limit is OOM-killed
// in the leaf; the supervisor (this process) survives and reports it.
func TestVisionOOMStaysInLeaf(t *testing.T) {
	root := cgroupParent(t)
	g, err := budget.Memory{HostMB: 16, InferenceMB: 32, PoolMB: 64, HeadroomMB: 16}.Apply(root)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := service(t, Options{Cgroup: g.Inference, Backoff: Backoff{Min: time.Hour, Max: time.Hour, Reset: time.Hour}}, "alloc")
	deadline := time.Now().Add(30 * time.Second)
	for s.State().Restarts == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the allocating service was never stopped: %+v", s.State())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st := s.State(); !strings.HasPrefix(st.Cause, "oom: ") || st.State != Unavailable {
		t.Fatalf("state %+v, want unavailable with an oom cause", st)
	}
	n, err := g.Inference.OOMKills()
	if err != nil || n == 0 {
		t.Fatalf("leaf oom_kill %d, %v", n, err)
	}
}

// DEV-7: nothing the service writes reaches the log; the supervisor's
// own lines do, naming the vision service.
func TestVisionOutputNeverLogged(t *testing.T) {
	needRoot(t)
	var mu sync.Mutex
	var buf strings.Builder
	s, _ := service(t, Options{Log: lockedWriter{&mu, &buf}, Backoff: Backoff{Min: time.Hour, Max: time.Hour, Reset: time.Hour}}, "noisy")
	deadline := time.Now().Add(10 * time.Second)
	for s.State().Restarts == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the noisy service never exited: %+v", s.State())
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	got := buf.String()
	mu.Unlock()
	if strings.Contains(got, "CANARY") {
		t.Fatalf("the service's output reached the log:\n%s", got)
	}
	if !strings.HasPrefix(got, "vision: service stopped (exited: exit status 3); restart 1 in ") {
		t.Fatalf("log %q", got)
	}
}

// The vision service gets infer/supervise's jail: its own user,
// no_new_privs, no capability and no network.
func TestVisionIsJailed(t *testing.T) {
	needRoot(t)
	_, sock := service(t, Options{}, "jail")
	got := ask(t, sock)
	for _, want := range []string{"Uid: 65534 65534 65534 65534", "NoNewPrivs: 1", "CapEff: 0000000000000000", "net: ENETUNREACH"} {
		if !strings.Contains(got, want) {
			t.Errorf("service lacks %q:\n%s", want, got)
		}
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *strings.Builder
}

func (l lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}
