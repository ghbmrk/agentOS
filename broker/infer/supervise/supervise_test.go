package supervise

// REQ: RES-2, DEP-1, REV-6

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
const helperArg = "infer-supervise-helper"

// The service's user in these tests: nobody.
const testUID, testGID = 65534, 65534

func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == helperArg {
		os.Exit(helper(os.Args[2], os.Args[3:]))
	}
	os.Exit(m.Run())
}

// startFDs are the helper's descriptors before it opens any: what the
// supervisor passed, plus what the Go runtime opened itself.
var startFDs string

func helper(mode string, args []string) int {
	startFDs = fdList()
	switch mode {
	case "exit":
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
		fmt.Fprintln(os.Stderr, "helper: no listener on fd 3")
		return 4
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return 5
		}
		b, _ := json.Marshal(probe(mode, args))
		c.Write(append(b, '\n'))
		c.Close()
	}
}

func probe(mode string, args []string) string {
	switch mode {
	case "pid":
		return strconv.Itoa(os.Getpid())
	case "net":
		d := net.Dialer{Timeout: 2 * time.Second}
		_, err := d.Dial("tcp", "192.0.2.1:9")
		return errnoName(err)
	case "unix":
		_, err := net.Dial("unix", args[0])
		return errnoName(err)
	case "env":
		return strings.Join(os.Environ(), "\n")
	case "cgroup":
		b, _ := os.ReadFile("/proc/self/cgroup")
		return string(b)
	case "status":
		b, _ := os.ReadFile("/proc/self/status")
		var keep []string
		for _, l := range strings.Split(string(b), "\n") {
			for _, k := range []string{"Uid:", "Gid:", "Groups:", "NoNewPrivs:", "CapEff:"} {
				if strings.HasPrefix(l, k) {
					keep = append(keep, strings.Join(strings.Fields(l), " "))
				}
			}
		}
		return strings.Join(keep, "\n")
	case "fds":
		return startFDs
	}
	return "unknown mode"
}

func fdList() string {
	es, _ := os.ReadDir("/proc/self/fd")
	var fds []string
	for _, e := range es {
		l, _ := os.Readlink("/proc/self/fd/" + e.Name())
		fds = append(fds, e.Name()+"="+l)
	}
	return strings.Join(fds, " ")
}

func errnoName(err error) string {
	switch {
	case err == nil:
		return "connected"
	case errors.Is(err, syscall.ENETUNREACH):
		return "ENETUNREACH"
	case errors.Is(err, syscall.EACCES):
		return "EACCES"
	}
	return err.Error()
}

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: the service runs as another user in new namespaces (CI machines job)")
	}
}

// helperBin copies the test binary into a directory the service's user
// can traverse, so it can exec it.
func helperBin(t *testing.T) (bin, base string) {
	t.Helper()
	base, err := os.MkdirTemp("", "infer-supervise-")
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
	bin = filepath.Join(base, "helper")
	if err := os.WriteFile(bin, b, 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, base
}

// service starts the helper in mode under a supervisor and returns its
// socket.
func service(t *testing.T, o Options, mode string, args ...string) (*Supervisor, string) {
	t.Helper()
	bin, base := helperBin(t)
	o.Path = bin
	o.Args = append([]string{helperArg, mode}, args...)
	if o.Socket == "" {
		o.Socket = filepath.Join(base, "run", "infer.sock")
	}
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

func TestStartRefusesRootAndRelativePaths(t *testing.T) {
	ctx := context.Background()
	for _, o := range []Options{
		{Path: "/bin/true", Socket: "/run/x/s", UID: 0, GID: 1},
		{Path: "/bin/true", Socket: "/run/x/s", UID: 1, GID: 0},
		{Path: "true", Socket: "/run/x/s", UID: 1, GID: 1},
		{Path: "/bin/true", Socket: "s", UID: 1, GID: 1},
		{Path: "/bin/true", Socket: "/run/x/s", UID: 1, GID: 1, Backoff: Backoff{Min: 2, Max: 1}},
		// A control socket beside the listener only, never elsewhere or on it.
		{Path: "/bin/true", Socket: "/run/x/s", Control: "/run/y/c", UID: 1, GID: 1},
		{Path: "/bin/true", Socket: "/run/x/s", Control: "/run/x/s", UID: 1, GID: 1},
		{Path: "/bin/true", Socket: "/run/x/s", Control: "c", UID: 1, GID: 1},
	} {
		if s, err := Start(ctx, o); err == nil {
			t.Errorf("Start(%+v) succeeded", o)
			<-s.Done()
		}
	}
}

// INF-4: a service that exits at once is restarted after 1 unit, then 2,
// 4, ... up to the cap; State says unavailable with the cause and count
// meanwhile, and a run that lasted Reset puts the delay back to Min.
func TestSupervisorRestartsWithBackoff(t *testing.T) {
	// Reset is far above a quick run, so a busy machine cannot make one
	// count as long.
	b := Backoff{Min: 25 * time.Millisecond, Max: 200 * time.Millisecond, Reset: time.Second}
	var tmu sync.Mutex
	var slept []time.Duration // what each restart's timer was set to
	s := newSupervisor(Options{Backoff: b, timer: func(d time.Duration) *time.Timer {
		tmu.Lock()
		slept = append(slept, d)
		tmu.Unlock()
		return time.NewTimer(d)
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var starts, ends []time.Time
	var bad []string
	const quick = 7
	run := func(ctx context.Context) string {
		mu.Lock()
		n := len(starts)
		starts = append(starts, time.Now())
		mu.Unlock()
		if st := s.State(); st.Restarts != n || (n > 0 && (st.State != Starting || st.Cause != "exited: exit status 3")) {
			mu.Lock()
			bad = append(bad, fmt.Sprintf("start %d: state %+v", n, st))
			mu.Unlock()
		}
		if n == quick {
			// One long run: the next delay is Min again.
			time.Sleep(b.Reset + 10*time.Millisecond)
		}
		mu.Lock()
		ends = append(ends, time.Now())
		mu.Unlock()
		if n > quick {
			<-ctx.Done()
		}
		return "exited: exit status 3"
	}
	go s.loop(ctx, run)
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n, e := len(starts), len(ends)
		mu.Unlock()
		// Run quick+1 has checked its state and recorded its end, so it
		// needs mu no more and returns once ctx ends.
		if n > quick+1 && e > quick+1 {
			break
		}
		if n < quick && n > 0 {
			if st := s.State(); st.State == Unavailable && st.Cause != "exited: exit status 3" {
				t.Fatalf("unavailable state without its cause: %+v", st)
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d starts", n)
		}
		time.Sleep(time.Millisecond)
	}
	// Measure the gaps under mu, then release it: a run still holding or
	// awaiting mu would otherwise keep <-s.Done() below from ever returning.
	mu.Lock()
	gaps := make([]time.Duration, quick+1)
	for i := range gaps {
		gaps[i] = starts[i+1].Sub(ends[i])
	}
	failed := bad
	mu.Unlock()
	if len(failed) > 0 {
		t.Fatal(failed)
	}
	// The delays the loop handed its timer must be exact; wall-clock gaps
	// are bounded loosely, since a busy machine can stretch any gap.
	tmu.Lock()
	got := append([]time.Duration(nil), slept...)
	tmu.Unlock()
	want := []time.Duration{25, 50, 100, 200, 200, 200, 200, 25} // the last after the long run
	if len(got) != len(want) {
		t.Fatalf("timers %v, want %d", got, len(want))
	}
	for i, w := range want {
		w *= time.Millisecond
		if got[i] != w {
			t.Errorf("restart %d timer %v, want %v", i+1, got[i], w)
		}
		if gaps[i] < w || gaps[i] >= w+time.Second {
			t.Errorf("restart %d after %v, want %v to %v", i+1, gaps[i], w, w+time.Second)
		}
	}
	if st := s.State(); st.Restarts != quick+1 {
		t.Errorf("restarts %d, want %d", st.Restarts, quick+1)
	}
	cancel()
	<-s.Done()
	if st := s.State(); st.State != Stopped {
		t.Errorf("state after the context ended: %+v", st)
	}
}

// The same with the real start: a service that exits is counted and
// restarted, and its socket path goes with it.
func TestSupervisorRestartsTheRealService(t *testing.T) {
	needRoot(t)
	s, _ := service(t, Options{Backoff: Backoff{Min: 20 * time.Millisecond, Max: 40 * time.Millisecond, Reset: time.Hour}}, "exit")
	deadline := time.Now().Add(10 * time.Second)
	for {
		st := s.State()
		if st.Restarts >= 3 {
			if !strings.Contains(st.Cause, "exit status 3") {
				t.Fatalf("cause %q", st.Cause)
			}
			break
		}
		if strings.HasPrefix(st.Cause, "start:") || strings.HasPrefix(st.Cause, "listen:") {
			t.Fatalf("service did not start: %+v", st)
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %+v", st)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Lifecycle, broker restart: a stale socket file at the path is replaced,
// and a restarted service answers on a fresh listener at the same path.
func TestSupervisorRestartReplacesSocket(t *testing.T) {
	needRoot(t)
	bin, base := helperBin(t)
	sock := filepath.Join(base, "run", "infer.sock")
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	// A previous broker's socket, still bound by nobody serving it.
	old, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()

	ctx, cancel := context.WithCancel(context.Background())
	o := Options{Path: bin, Args: []string{helperArg, "pid"}, Socket: sock, UID: testUID, GID: testGID,
		Backoff: Backoff{Min: 10 * time.Millisecond, Max: 10 * time.Millisecond, Reset: time.Hour}}
	s, err := Start(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-s.Done() }()
	first := ask(t, sock)
	fi, err := os.Stat(filepath.Dir(sock))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("socket directory mode %v, want 0700", fi.Mode().Perm())
	}
	pid, _ := strconv.Atoi(first)
	if pid <= 0 {
		t.Fatalf("pid %q", first)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if second := ask(t, sock); second != first {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the service was not restarted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := s.State(); st.Restarts < 1 || !strings.Contains(st.Cause, "killed") {
		t.Errorf("state %+v", st)
	}
	cancel()
	<-s.Done()
	if _, err := os.Lstat(sock); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("socket left after stop: %v", err)
	}
}

// INF-1, INF-6: the service runs as its user, with no supplementary group,
// no capability and no_new_privs.
func TestServiceRunsAsItsUserWithNoNewPrivs(t *testing.T) {
	needRoot(t)
	_, sock := service(t, Options{}, "status")
	got := ask(t, sock)
	for _, want := range []string{"Uid: 65534 65534 65534 65534", "Gid: 65534 65534 65534 65534", "NoNewPrivs: 1", "CapEff: 0000000000000000"} {
		if !strings.Contains(got, want) {
			t.Errorf("service status lacks %q:\n%s", want, got)
		}
	}
	for _, l := range strings.Split(got, "\n") {
		if strings.HasPrefix(l, "Groups:") && l != "Groups:" {
			t.Errorf("supplementary groups: %q", l)
		}
	}
}

// INF-6: only a down loopback, so no address is reachable.
func TestServiceHasNoNetwork(t *testing.T) {
	needRoot(t)
	_, sock := service(t, Options{}, "net")
	if got := ask(t, sock); got != "ENETUNREACH" {
		t.Fatalf("tcp dial from the service: %s, want ENETUNREACH", got)
	}
}

// INF-6: a socket in another user's 0700 directory, as the vault
// process's are, is refused.
func TestServiceCannotOpenEgressSocket(t *testing.T) {
	needRoot(t)
	dir, err := os.MkdirTemp("", "infer-egress-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(dir, "vault.sock")
	ln, err := net.Listen("unix", vault)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, sock := service(t, Options{}, "unix", vault)
	if got := ask(t, sock); got != "EACCES" {
		t.Fatalf("dial of %s from the service: %s, want EACCES", vault, got)
	}
}

// INF-6: in the production layout (agentos-egress and broker/sockets: a
// 0711 directory, a 0666 socket) the service's connect succeeds, since it
// has no mount namespace; what refuses it is the listener's SO_PEERCRED
// check. So the peer credential must carry the service's real uid and gid,
// never root's or the broker's, whatever its user namespace maps.
func TestEgressPeerCheckSeesTheServiceUID(t *testing.T) {
	needRoot(t)
	dir, err := os.MkdirTemp("", "infer-egress-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(dir, "vault.sock")
	ln, err := net.Listen("unix", vault)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(vault, 0o666); err != nil {
		t.Fatal(err)
	}
	peer := make(chan *syscall.Ucred, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		raw, err := c.(*net.UnixConn).SyscallConn()
		if err != nil {
			return
		}
		raw.Control(func(fd uintptr) {
			cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			if err == nil {
				peer <- cred
			}
		})
	}()
	_, sock := service(t, Options{}, "unix", vault)
	if got := ask(t, sock); got != "connected" {
		t.Fatalf("dial of %s from the service: %s, want connected (the production layout lets it connect)", vault, got)
	}
	select {
	case cred := <-peer:
		if cred.Uid != testUID || cred.Gid != testGID {
			t.Fatalf("peer credential uid %d gid %d, want the service's %d/%d", cred.Uid, cred.Gid, testUID, testGID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never read a peer credential")
	}
}

// INF-6, INF-8: the service's environment is childproc's allowlist with
// only PATH, so a variable set in the parent never reaches it.
func TestServiceEnvIsAllowlist(t *testing.T) {
	needRoot(t)
	const canary = "synthetic-infer-canary-7c1f"
	t.Setenv("INFER_TEST_CANARY", canary)
	_, sock := service(t, Options{}, "env")
	got := ask(t, sock)
	if got != "PATH=/usr/bin:/bin" {
		t.Fatalf("service environment %q, want only PATH", got)
	}
	if strings.Contains(got, canary) {
		t.Fatal("the canary reached the service")
	}
}

// INF-6: no file descriptor but stdin (/dev/null), stdout, stderr and
// the listener; anything else the service holds at its start the Go
// runtime opened itself (its epoll, and the cgroup CPU limit files).
func TestServiceGetsOnlyItsListener(t *testing.T) {
	needRoot(t)
	_, sock := service(t, Options{}, "fds")
	got := strings.Fields(ask(t, sock))
	seen := map[string]bool{}
	for _, f := range got {
		n, target, _ := strings.Cut(f, "=")
		seen[n] = true
		switch {
		case n == "0" && target == "/dev/null",
			(n == "1" || n == "2") && strings.HasPrefix(target, "pipe:"),
			n == "3" && strings.HasPrefix(target, "socket:"),
			strings.HasPrefix(target, "anon_inode:"),
			strings.HasPrefix(target, "/sys/fs/cgroup/"),
			// The listing's own directory, closed by the time it is read.
			target == "":
		default:
			t.Errorf("service started holding fd %s", f)
		}
	}
	for _, n := range []string{"0", "1", "2", "3"} {
		if !seen[n] {
			t.Errorf("fd %s missing: %v", n, got)
		}
	}
}

// cgroupParent returns a fresh writable cgroup v2 group under
// AGENTOS_CGROUP_PARENT, or skips.
func cgroupParent(t *testing.T) *cgroup.Group {
	t.Helper()
	needRoot(t)
	p := os.Getenv("AGENTOS_CGROUP_PARENT")
	if p == "" {
		t.Skip("set AGENTOS_CGROUP_PARENT to a writable cgroup v2 group (CI machines job)")
	}
	dir := filepath.Join(p, fmt.Sprintf("infer-%d", time.Now().UnixNano()))
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

// INF-1: the service runs in the inference leaf, whose memory.max is the
// budget's InferenceMB.
func TestServiceRunsInInferenceLeaf(t *testing.T) {
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

// INF-1, INF-4: a service allocating past the leaf's limit is OOM-killed
// in the leaf, the supervisor (this process) survives and reports it.
func TestServiceOOMStaysInLeaf(t *testing.T) {
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

// INF-8: the supervisor's own lines carry causes and counts only.
func TestSupervisorLogIsCauseOnly(t *testing.T) {
	var buf strings.Builder
	var mu sync.Mutex
	s := newSupervisor(Options{Backoff: Backoff{Min: time.Millisecond, Max: time.Millisecond, Reset: time.Hour},
		Log: lockedWriter{&mu, &buf}})
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	go s.loop(ctx, func(context.Context) string {
		n++
		if n == 3 {
			cancel()
		}
		return "exited: exit status 3"
	})
	<-s.Done()
	mu.Lock()
	defer mu.Unlock()
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if !strings.HasPrefix(l, "infer: service stopped (exited: exit status 3); restart ") {
			t.Errorf("log line %q", l)
		}
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(b)
}

// A supervisor started with a Name says it in its lines (VIS-svc).
func TestSupervisorLogNamesTheService(t *testing.T) {
	var buf strings.Builder
	var mu sync.Mutex
	s := newSupervisor(Options{Name: "vision", Backoff: Backoff{Min: time.Millisecond, Max: time.Millisecond, Reset: time.Hour},
		Log: lockedWriter{&mu, &buf}})
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	go s.loop(ctx, func(context.Context) string {
		if n++; n == 2 {
			cancel()
		}
		return "exited"
	})
	<-s.Done()
	mu.Lock()
	defer mu.Unlock()
	if !strings.HasPrefix(buf.String(), "vision: service stopped (exited); restart 1 in ") {
		t.Fatalf("log %q", buf.String())
	}
}
