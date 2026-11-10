package run

// REQ: NET-2, NET-3

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/dns"
)

// The test binary is the fake dnsmasq: started with the set's arguments,
// it appends "start <file content>" to ./events (the set's directory),
// and "stop <content>" when it is sent SIGTERM. A file holding "crash"
// exits at once with status 1, and one holding "lasts" after 700 ms.
func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == "--keep-in-foreground" && os.Args[2] == "--pid-file=" {
		fakeDnsmasq(strings.TrimPrefix(os.Args[3], "--conf-file="))
		return
	}
	os.Exit(m.Run())
}

func fakeDnsmasq(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		os.Exit(2)
	}
	conf := string(b)
	if len(os.Environ()) != 0 {
		event("env " + conf)
	}
	sig := make(chan os.Signal, 1)
	if strings.Contains(conf, "stubborn") {
		signal.Ignore(syscall.SIGTERM)
	} else {
		signal.Notify(sig, syscall.SIGTERM)
	}
	os.Stderr.WriteString("said " + conf + "\n")
	if strings.Contains(conf, "holds") {
		// A child in a group of its own that keeps the instance's standard
		// error open after the instance exits, which a stop's kill of the
		// instance's group does not reach.
		c := exec.Command("/bin/sh", "-c", "sleep 20")
		c.Stderr = os.Stderr
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if c.Start() == nil {
			event("holder_" + strconv.Itoa(c.Process.Pid) + " " + conf)
		}
	}
	if strings.Contains(conf, "forks") {
		// A TCP child of its own, which ignores SIGTERM.
		c := exec.Command("/bin/sh", "-c", "trap '' TERM; sleep 60")
		if c.Start() == nil {
			event("child_" + strconv.Itoa(c.Process.Pid) + " " + conf)
		}
	}
	event("start " + conf)
	if strings.Contains(conf, "crash") {
		os.Exit(1)
	}
	if strings.Contains(conf, "lasts") {
		select {
		case <-sig:
		case <-time.After(700 * time.Millisecond):
			os.Exit(1)
		}
	} else {
		<-sig
	}
	event("stop " + conf)
	os.Exit(0)
}

func event(s string) {
	f, err := os.OpenFile("events", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(3)
	}
	f.WriteString(s + "\n")
	f.Close()
}

func events(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "events"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(b)), " ", "_"))
}

// waitEvents waits until the events include every one of want.
func waitEvents(t *testing.T, dir string, want ...string) []string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := events(t, dir)
		ok := true
		for _, w := range want {
			ok = ok && slices.Contains(got, w)
		}
		if ok {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("events %v, want %v among them", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newSet(t *testing.T) (*Set, string) {
	s, dir, _ := newLoggedSet(t, os.Args[0])
	return s, dir
}

// newLoggedSet is a set running bin, and its log so far.
func newLoggedSet(t *testing.T, bin string) (*Set, string, func() string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var log []string
	s, err := New(bin, dir, func(l string) { mu.Lock(); log = append(log, l); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, dir, func() string { mu.Lock(); defer mu.Unlock(); return strings.Join(log, "\n") }
}

// waitLog waits until the log holds want.
func waitLog(t *testing.T, logs func() string, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("log %q, want %q in it", logs(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func files(core, tv string) dns.Files {
	return dns.Files{Listed: []dns.Listed{{Iface: "core0", Conf: core}, {Iface: "vlan10", Conf: tv}}, People: "people", DHCP: "dhcp"}
}

// TestApplyStopsBeforeLoad: an instance whose file changes has exited
// before the new ruleset loads, and starts on its new file only after
// it (ENF-l-dns-step, #4464): no old list fills the new ruleset's sets.
// An unchanged instance keeps running.
func TestApplyStopsBeforeLoad(t *testing.T) {
	s, dir, logs := newLoggedSet(t, os.Args[0])
	if err := s.Apply(files("core-a", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-a", "start_tv-a", "start_people", "start_dhcp")
	loaded := false
	err := s.Apply(files("core-b", "tv-a"), func() error {
		got := events(t, dir)
		if !slices.Contains(got, "stop_core-a") {
			t.Errorf("the load ran while the old core list's instance was running: %v", got)
		}
		if slices.Contains(got, "start_core-b") {
			t.Errorf("the new core list's instance started before the load: %v", got)
		}
		loaded = true
		return nil
	})
	if err != nil || !loaded {
		t.Fatalf("Apply: %v, loaded %v", err, loaded)
	}
	got := waitEvents(t, dir, "start_core-b")
	for _, e := range []string{"stop_tv-a", "stop_people", "stop_dhcp"} {
		if slices.Contains(got, e) {
			t.Errorf("an unchanged instance was restarted: %v", got)
		}
	}
	if slices.ContainsFunc(got, func(e string) bool { return strings.HasPrefix(e, "env_") }) {
		t.Errorf("an instance got an environment: %v", got)
	}
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(logs(), "exited") {
		t.Errorf("an instance Apply stopped was taken as exited on its own: %q", logs())
	}
}

// TestWriteFailure: a file that cannot be written fails the start, and
// the set stays usable.
func TestWriteFailure(t *testing.T) {
	s, dir, logs := newLoggedSet(t, os.Args[0])
	blocker := confPath(dir, "listed-core0", "core-a") + ".tmp"
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	// A start failure is not the load's: Apply returns nil, logs it and
	// tries again with the backoff (L3 6655898360 point 2).
	if err := s.Apply(files("core-a", "tv-a"), func() error { return nil }); err != nil {
		t.Fatalf("Apply = %v: a failed start read as a refused load", err)
	}
	waitLog(t, logs, "dns: listed-core0: starting it again in 1s")
	if slices.Contains(events(t, dir), "start_core-a") {
		t.Fatal("started on a file that was not written")
	}
	// It has never run, so it is not running (#5164 R5 b).
	if got := s.Flapping(); len(got) != 1 || got[0] != (Flap{Name: "listed-core0", Exits: 1}) {
		t.Fatalf("an instance whose file could not be written: Flapping = %v", got)
	}
	os.Remove(blocker)
	waitEvents(t, dir, "start_core-a")
	if err := s.Apply(files("core-b", "tv-a"), func() error { return nil }); err != nil {
		t.Fatalf("the set after a failed write: %v", err)
	}
	waitEvents(t, dir, "start_core-b")
}

// TestEmptyFilesRunNothing (L3 6655898360 point 1): dns.Files{} stops
// every instance and starts none, since dnsmasq on an empty file is an
// open resolver on every interface.
func TestEmptyFilesRunNothing(t *testing.T) {
	s, dir := newSet(t)
	if err := s.Apply(files("core-a", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-a", "start_tv-a", "start_people", "start_dhcp")
	if err := s.Apply(dns.Files{}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	n := len(s.procs)
	s.mu.Unlock()
	got := waitEvents(t, dir, "stop_core-a", "stop_tv-a", "stop_people", "stop_dhcp")
	if n != 0 || slices.Contains(got, "start_") {
		t.Fatalf("instances running on empty files: %d, events %v", n, got)
	}
	if m := Names(dns.Files{Listed: []dns.Listed{{Iface: "x", Conf: ""}}}); len(m) != 0 {
		t.Fatalf("Names keeps empty files: %v", m)
	}
}

// TestApplyFailedLoad: when the load is refused, the previous ruleset
// stays, so the instances stopped for it start again on their previous
// files, and Apply returns the load's error.
func TestApplyFailedLoad(t *testing.T) {
	s, dir := newSet(t)
	if err := s.Apply(files("core-a", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-a")
	refused := errors.New("refused")
	if err := s.Apply(files("core-b", "tv-a"), func() error { return refused }); !errors.Is(err, refused) {
		t.Fatalf("Apply = %v, want the load's error", err)
	}
	got := waitEvents(t, dir, "stop_core-a")
	time.Sleep(50 * time.Millisecond)
	got = events(t, dir)
	if n := strings.Count(strings.Join(got, " "), "start_core-a"); n != 2 {
		t.Errorf("the old core list's instance started %d times, want 2 (again after the refused load): %v", n, got)
	}
	if slices.Contains(got, "start_core-b") {
		t.Errorf("an instance started on the refused document's file: %v", got)
	}
}

// TestCrashRestartsInForce: an instance that exits on its own starts again
// on its file in force, and a stale restart never runs once Apply has
// moved on.
func TestCrashRestartsInForce(t *testing.T) {
	s, dir := newSet(t)
	if err := s.Apply(files("core-crash", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-crash")
	// The first restart waits RestartMin; Apply replaces it meanwhile.
	if err := s.Apply(files("core-b", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-b")
	time.Sleep(RestartMin + 200*time.Millisecond)
	got := events(t, dir)
	if n := strings.Count(strings.Join(got, " "), "start_core-crash"); n != 1 {
		t.Errorf("the replaced instance started again on its old file (%d starts): %v", n, got)
	}
}

// TestRestartAfterExit: an instance in force that exits is started again.
func TestRestartAfterExit(t *testing.T) {
	s, dir := newSet(t)
	if err := s.Apply(files("core-crash", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(strings.Join(events(t, dir), " "), "start_core-crash") < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("an exited instance was not started again: %v", events(t, dir))
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = s
}

// TestCloseStopsAll: Close stops every instance and waits for it, and the
// set then refuses Apply. Files of documents no longer in force are
// removed.
func TestCloseStopsAll(t *testing.T) {
	s, dir := newSet(t)
	if err := s.Apply(files("core-a", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(files("core-b", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-b", "start_tv-a", "start_people", "start_dhcp")
	confs, _ := filepath.Glob(filepath.Join(dir, "*.conf"))
	if len(confs) != 4 {
		t.Errorf("files kept: %v, want the four in force", confs)
	}
	s.Close()
	got := events(t, dir)
	for _, e := range []string{"stop_core-b", "stop_tv-a", "stop_people", "stop_dhcp"} {
		if !slices.Contains(got, e) {
			t.Errorf("Close returned before %s: %v", e, got)
		}
	}
	if err := s.Apply(files("core-c", "tv-a"), func() error { t.Error("load after Close"); return nil }); !errors.Is(err, ErrRun) {
		t.Errorf("Apply after Close = %v, want ErrRun", err)
	}
}

func TestNewRefuses(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := New("dnsmasq", dir, nil); !errors.Is(err, ErrRun) {
		t.Errorf("relative binary: %v", err)
	}
	good := t.TempDir()
	if err := os.Chmod(good, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := New("dnsmasq", good, nil); !errors.Is(err, ErrRun) {
		t.Errorf("relative binary in a good directory: %v", err)
	}
	if _, err := New("/usr/sbin/dnsmasq", filepath.Join(good, "absent"), nil); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing directory: %v", err)
	}
	if _, err := New("/usr/sbin/dnsmasq", dir, nil); !errors.Is(err, ErrRun) {
		t.Errorf("group-readable directory: %v", err)
	}
}

// TestStartFailureLogged: an instance that cannot start is logged and
// returned, with no log function given too.
func TestStartFailureLogged(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := New(filepath.Join(dir, "no-dnsmasq"), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Apply(files("core-a", "tv-a"), func() error { return nil }); err != nil {
		t.Fatalf("Apply = %v: a failed start read as a refused load", err)
	}
	s2, _, logs := newLoggedSet(t, filepath.Join(dir, "no-dnsmasq"))
	s2.Apply(files("core-a", "tv-a"), func() error { return nil })
	// Logged by the start itself, not only by the retry RestartMin later.
	if !strings.Contains(logs(), "dns: listed-core0: dns/run: refused") {
		t.Fatalf("a failed start was not logged when it failed: %q", logs())
	}
	// Each failed retry doubles the wait before the next.
	waitLog(t, logs, "dns: listed-core0: starting it again in "+(2*RestartMin).String())
}

// TestStopNotHeldByAHeldStderr: a stop is not held past WaitDelay by a
// process outside the instance's group that keeps its standard error.
func TestStopNotHeldByAHeldStderr(t *testing.T) {
	s, dir := newSet(t)
	if err := s.Apply(files("core-holds", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-holds")
	for _, e := range events(t, dir) {
		if rest, ok := strings.CutPrefix(e, "holder_"); ok {
			if pid, err := strconv.Atoi(strings.SplitN(rest, "_", 2)[0]); err == nil {
				t.Cleanup(func() { syscall.Kill(pid, syscall.SIGKILL) })
			}
		}
	}
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a stop waited on a process holding the instance's standard error")
	}
}

// TestStderrLogged: an instance's standard error reaches the log, by
// instance.
func TestStderrLogged(t *testing.T) {
	s, _, logs := newLoggedSet(t, os.Args[0])
	if err := s.Apply(files("core-a", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "dns: listed-core0: said core-a")
}

// TestNoRestartDuringLoad: an instance that exited on its own, whose
// file the next document changes, is not started again on its old file
// while the load runs.
func TestNoRestartDuringLoad(t *testing.T) {
	s, dir, logs := newLoggedSet(t, os.Args[0])
	if err := s.Apply(files("core-crash", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "listed-core0 exited")
	err := s.Apply(files("core-b", "tv-a"), func() error {
		time.Sleep(RestartMin + 300*time.Millisecond)
		if n := strings.Count(strings.Join(events(t, dir), " "), "start_core-crash"); n != 1 {
			t.Errorf("the old core list's instance started again during the load (%d starts)", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRestartBacksOff: an instance that keeps exiting is started again
// only after RestartMin, not at once.
func TestRestartBacksOff(t *testing.T) {
	s, dir := newSet(t)
	if err := s.Apply(files("core-crash", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-crash")
	time.Sleep(RestartMin / 2)
	if n := strings.Count(strings.Join(events(t, dir), " "), "start_core-crash"); n != 1 {
		t.Errorf("restarted %d times within RestartMin/2", n-1)
	}
}

// TestRestartFailureLogged: a restart that cannot start is logged.
func TestRestartFailureLogged(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fake-dnsmasq")
	b, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, b, 0o700); err != nil {
		t.Fatal(err)
	}
	s, dir, logs := newLoggedSet(t, bin)
	if err := s.Apply(files("core-crash", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-crash")
	os.Remove(bin)
	waitLog(t, logs, "dns: listed-core0: dns/run: refused")
}

// TestChildrenStopped (Security 6655916292 release point): a stop reaches
// the instance's own children, so no TCP child of an old list outlives it.
func TestChildrenStopped(t *testing.T) {
	stopWait = 200 * time.Millisecond
	defer func() { stopWait = StopWait }()
	s, dir := newSet(t)
	if err := s.Apply(files("core-forks", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	got := waitEvents(t, dir, "start_core-forks")
	deadline := time.Now().Add(5 * time.Second)
	var pid int
	for pid == 0 {
		for _, e := range events(t, dir) {
			if rest, ok := strings.CutPrefix(e, "child_"); ok {
				pid, _ = strconv.Atoi(strings.SplitN(rest, "_", 2)[0])
			}
		}
		if pid == 0 && time.Now().After(deadline) {
			t.Fatalf("no child started: %v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := s.Apply(files("core-b", "tv-a"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitUntilDead(t, pid)
}

// waitUntilDead waits until pid is gone or a zombie.
func waitUntilDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			return
		}
		if f := strings.Fields(string(b)); len(f) > 2 && f[2] == "Z" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the instance's child %d outlived its stop", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestStubbornKilled: an instance that ignores SIGTERM is killed after
// the stop wait, so Close and Apply never hang on it.
func TestStubbornKilled(t *testing.T) {
	stopWait = 200 * time.Millisecond
	defer func() { stopWait = StopWait }()
	s, dir := newSet(t)
	all := dns.Files{Listed: []dns.Listed{{Iface: "core0", Conf: "stubborn-core"}}, People: "stubborn-people", DHCP: "stubborn-dhcp"}
	if err := s.Apply(all, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_stubborn-core", "start_stubborn-people", "start_stubborn-dhcp")
	done := make(chan struct{})
	go func() { s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close hung on an instance that ignores SIGTERM")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, p := range s.procs {
		select {
		case <-p.done:
		default:
			t.Errorf("Close returned before %s had exited", name)
		}
	}
}

func TestLineLogCuts(t *testing.T) {
	var got []string
	l := &lineLog{logf: func(s string) { got = append(got, s) }, prefix: "p: "}
	l.Write([]byte("one\ntw"))
	l.Write([]byte("o\n" + strings.Repeat("x", 600)))
	l.Write([]byte("y\n" + strings.Repeat("z", 600) + "\n"))
	want := []string{"p: one", "p: two", "p: " + strings.Repeat("x", 512), "p: y", "p: " + strings.Repeat("z", 512)}
	if !slices.Equal(got, want) {
		t.Errorf("lines %q", got)
	}
	// An empty line is a line, and a partial line of exactly 512 bytes
	// waits for more.
	got = nil
	l.Write([]byte("\nafter\n" + strings.Repeat("w", 512)))
	if want := []string{"p: ", "p: after"}; !slices.Equal(got, want) {
		t.Errorf("lines %q, want %q", got, want)
	}
	l.Write([]byte("w"))
	if want := []string{"p: ", "p: after", "p: " + strings.Repeat("w", 512)}; !slices.Equal(got, want) {
		t.Errorf("lines %q, want %q", got, want)
	}
}

// TestFlapping (#5164 R5 b): an instance that exits on its own reads as
// flapping, with its exits in a row, until a process of it has stayed up
// StayUp; an exit after that starts the count again, and a new file
// clears it. The others, which stay up, never read so.
func TestFlapping(t *testing.T) {
	stayUp = 400 * time.Millisecond
	defer func() { stayUp = StayUp }()
	s, dir := newSet(t)
	if got := s.Flapping(); len(got) != 0 {
		t.Fatalf("an empty set flaps: %v", got)
	}
	if err := s.Apply(files("core-crash", "tv-lasts"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	waitEvents(t, dir, "start_core-crash", "start_tv-lasts")
	flap := func(name string) (int, bool) {
		for _, f := range s.Flapping() {
			if f.Name == name {
				return f.Exits, true
			}
		}
		return 0, false
	}
	// tv-lasts is up and has not exited: not flapping.
	if n, ok := flap("listed-vlan10"); ok {
		t.Fatalf("a running instance that never exited flaps (%d)", n)
	}
	// core-crash: exits in a row, counted while it never stays up.
	deadline := time.Now().Add(8 * time.Second)
	for {
		if n, ok := flap("listed-core0"); ok && n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a crash loop does not count its exits in a row: %v", s.Flapping())
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, f := range s.Flapping() {
		if f.Name == "people" || f.Name == "dhcp" {
			t.Fatalf("an instance that stays up flaps: %v", s.Flapping())
		}
	}
	// tv-lasts ran past StayUp before each exit: it flaps after its first
	// exit, no longer once its next process has stayed up StayUp, and
	// after its next exit counts 1 again, not 2.
	deadline = time.Now().Add(8 * time.Second)
	phase := 0 // 0: before its first exit, 1: flapping, 2: cleared, 3: flapping again
	for phase < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("the instance that stays up between exits stopped at phase %d: %v", phase, s.Flapping())
		}
		n, ok := flap("listed-vlan10")
		if ok && n != 1 {
			t.Fatalf("an instance that stayed up before each exit counts %d in a row, want 1", n)
		}
		if ok == (phase%2 == 0) {
			phase++
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A refused load puts core-crash's file back in force, and its count
	// with it; a new file in force clears the count at once.
	n, _ := flap("listed-core0")
	if err := s.Apply(files("core-b", "tv-b"), func() error { return errors.New("refused") }); err == nil {
		t.Fatal("fixture: the load was not refused")
	}
	if m, ok := flap("listed-core0"); !ok || m < n {
		t.Fatalf("a refused load restarted the count of the file it put back: %d, was %d", m, n)
	}
	if err := s.Apply(files("core-b", "tv-b"), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if got := s.Flapping(); len(got) != 0 {
		t.Fatalf("instances on new files still flap: %v", got)
	}
}

// TestFlappingNeverStarted (#5164 R5 b, L3 and Security on #5318): an
// instance whose start keeps failing has never served, so Flapping names
// it with each failed start counted, the first at once and the next at
// its retry.
func TestFlappingNeverStarted(t *testing.T) {
	s, _, logs := newLoggedSet(t, "/nonexistent/dnsmasq")
	if err := s.Apply(files("core-a", "tv-a"), func() error { return nil }); err != nil {
		t.Fatalf("Apply = %v: a failed start read as a refused load", err)
	}
	want := []Flap{{"dhcp", 1}, {"listed-core0", 1}, {"listed-vlan10", 1}, {"people", 1}}
	if got := s.Flapping(); !slices.Equal(got, want) {
		t.Fatalf("instances that could not start: Flapping = %v, want %v", got, want)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := s.Flapping()
		if len(got) == 4 && got[0].Exits >= 2 && got[1].Exits >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a failed retry is not counted: %v\n%s", got, logs())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
