package loop7

// REQ: LOOP-1, LOOP-7
//
// P3-4b-3r-confine: a fuzz child cannot take the broker down. It runs
// without root and without the network, in a cgroup leaf with its own
// memory and process limits, and its cache cannot fill the state disk.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/loops"
)

// nobody is the unprivileged user the root tests jail children as; the
// image's is agentos-fuzz.
const nobody = 65534

// cacheFile writes size bytes at CacheDir-relative rel, last modified age
// ago.
func cacheFile(t *testing.T, dir, rel string, size int, age time.Duration) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-age)
	if err := os.Chtimes(p, at, at); err != nil {
		t.Fatal(err)
	}
	return p
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

// LOOP-1: before the fuzz step, the target's package cache is pruned to
// its cap and the whole cache to the box's, oldest entries first; the
// step itself sees the pruned cache. Crash inputs in the target's corpus
// are evidence and are never pruned, however old or large.
func TestTheFuzzCacheIsPrunedToItsCapsBeforeTheStep(t *testing.T) {
	release, cache := t.TempDir(), t.TempDir()
	seen := filepath.Join(t.TempDir(), "seen")
	tg := fakeTarget(t, release, `case "$2" in -test.fuzz=*) ls -R `+cache+`/fuzz > `+seen+`;; esac; exit 0`)
	crash := cacheFile(t, tg.Dir, "testdata/fuzz/FuzzFake/0crash", 5000, 300*time.Hour)
	old := cacheFile(t, cache, "fuzz/fake/FuzzFake/old", 400, 3*time.Hour)
	mid := cacheFile(t, cache, "fuzz/fake/FuzzFake/mid", 400, 2*time.Hour)
	newest := cacheFile(t, cache, "fuzz/fake/FuzzFake/new", 400, time.Hour)
	// Another package's cache: within its own cap, but the oldest of all,
	// so the box cap takes it first.
	other := cacheFile(t, cache, "fuzz/other/FuzzOther/a", 900, 4*time.Hour)
	otherNew := cacheFile(t, cache, "fuzz/other/FuzzOther/b", 100, 30*time.Minute)
	g := newFake()
	s := newSource(t, g, Config{Targets: []Target{tg}, CacheDir: cache, CacheCap: 1000, CacheTotal: 1200})
	if n, err := s.Fuzz(context.Background(), tg); n != 0 || err != nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
	// fake: 1200 > 1000, so "old" goes; then the box holds 800 + 1000 >
	// 1200, so "other/a", the oldest left, goes.
	for p, want := range map[string]bool{old: false, mid: true, newest: true, other: false, otherNew: true, crash: true} {
		if exists(p) != want {
			t.Errorf("%s kept = %v, want %v", p, !want, want)
		}
	}
	b, err := os.ReadFile(seen)
	if err != nil {
		t.Fatalf("the fuzz step did not run: %v", err)
	}
	if strings.Contains(string(b), "old") || !strings.Contains(string(b), "mid") {
		t.Fatalf("the step saw an unpruned cache:\n%s", b)
	}
}

// LOOP-1: a cache under its caps is left alone, and a package's cap
// counts only its own targets' entries, not a nested package's.
func TestACacheUnderItsCapIsUntouched(t *testing.T) {
	release, cache := t.TempDir(), t.TempDir()
	tg := fakeTarget(t, release, "exit 0")
	tg.Pkg = "modem"
	files := []string{
		cacheFile(t, cache, "fuzz/modem/FuzzFake/a", 600, 2*time.Hour),
		cacheFile(t, cache, "fuzz/modem/at/FuzzDecode/b", 600, 3*time.Hour),
	}
	s := newSource(t, newFake(), Config{Targets: []Target{tg}, CacheDir: cache, CacheCap: 1000, CacheTotal: 2000})
	if _, err := s.Fuzz(context.Background(), tg); err != nil {
		t.Fatal(err)
	}
	for _, p := range files {
		if !exists(p) {
			t.Errorf("%s pruned under the cap", p)
		}
	}
}

// LOOP-1: the caps default to 64 MiB a package and 512 MiB for the box.
func TestTheCacheCapsDefault(t *testing.T) {
	s := newSource(t, newFake(), Config{})
	if s.cfg.CacheCap != 64<<20 || s.cfg.CacheTotal != 512<<20 {
		t.Fatalf("caps %d, %d", s.cfg.CacheCap, s.cfg.CacheTotal)
	}
}

// LOOP-1, ARC-2: a jail must name an unprivileged user.
func TestAJailForRootIsRefused(t *testing.T) {
	_, err := New(Config{Inner: newFake(), Report: newFake(), Jail: &Jail{UID: 0, GID: 0}})
	if err == nil {
		t.Fatal("a jail running children as root was accepted")
	}
}

// needRoot skips unless the test runs as root (CI's machines job).
func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (CI machines job)")
	}
}

// testLeaf is a cgroup leaf under AGENTOS_CGROUP_PARENT with a hard
// memory limit of maxBytes, as agentosd's fuzz leaf has.
func testLeaf(t *testing.T, name string, maxBytes int64) *cgroup.Group {
	t.Helper()
	needRoot(t)
	parent := os.Getenv("AGENTOS_CGROUP_PARENT")
	if parent == "" {
		t.Skip("set AGENTOS_CGROUP_PARENT to a writable cgroup v2 group (root only)")
	}
	p, err := cgroup.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := p.Component(name, cgroup.Limits{MaxBytes: maxBytes, HighBytes: maxBytes, Pids: 64, CPUWeight: 1, IOWeight: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		leaf.Kill(ctx)
		leaf.Remove()
	})
	return leaf
}

// jailDir is a directory nobody can traverse, as /var/lib/agentos is for
// agentos-fuzz (its ACL); t.TempDir's parent is 0700.
func jailDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "loop7-jail-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	if err := os.Chmod(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

// jailed is a source whose one target, built by bin in a release under
// a traversable directory, runs jailed as nobody in leaf ("" for none),
// with its state owned by nobody as agentosd's wiring leaves it.
func jailed(t *testing.T, g *fakeGuard, leaf string, bin func(release string) string) (*Source, Target) {
	t.Helper()
	base := jailDir(t)
	release := filepath.Join(base, "release")
	if err := os.Mkdir(release, 0o755); err != nil {
		t.Fatal(err)
	}
	tg := Target{Pkg: "fake", Name: "FuzzFake", Binary: bin(release), Dir: filepath.Join(base, "state", "targets", "fake")}
	if err := os.MkdirAll(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzFake"), 0o700); err != nil {
		t.Fatal(err)
	}
	cacheFile(t, tg.Dir, "testdata/fuzz/FuzzFake/0crash", 10, 0)
	j := &Jail{Leaf: leaf, UID: nobody, GID: nobody, State: filepath.Join(base, "state")}
	if err := j.Own(); err != nil {
		t.Fatal(err)
	}
	s := newSource(t, g, Config{Targets: []Target{tg}, CacheDir: filepath.Join(base, "state", "cache"), Jail: j})
	return s, tg
}

// helperBin copies this test binary into release as jail.test, where
// TestJailedChildHelper runs as the child.
func helperBin(t *testing.T) func(string) string {
	return func(release string) string {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		in, err := os.Open(self)
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		p := filepath.Join(release, "jail.test")
		out, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, in); err != nil {
			t.Fatal(err)
		}
		if err := out.Close(); err != nil {
			t.Fatal(err)
		}
		return p
	}
}

// TestJailedChildHelper is not a test: it is the child the jail tests
// start, from this binary copied as jail.test. It prints its ids,
// capabilities and cgroup, and what dialing each network:address
// argument gave.
func TestJailedChildHelper(t *testing.T) {
	if filepath.Base(os.Args[0]) != "jail.test" {
		t.Skip("the jail tests' child, not a test")
	}
	st, _ := os.ReadFile("/proc/self/status")
	for _, l := range strings.Split(string(st), "\n") {
		for _, k := range []string{"Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "NoNewPrivs:"} {
			if strings.HasPrefix(l, k) {
				fmt.Println(strings.Join(strings.Fields(l), " "))
			}
		}
	}
	cg, _ := os.ReadFile("/proc/self/cgroup")
	fmt.Printf("cgroup %s\n", strings.TrimSpace(string(cg)))
	for _, a := range flag.Args() {
		network, addr, _ := strings.Cut(a, ":")
		fmt.Printf("dial %s %s\n", network, dialed(network, addr))
	}
}

// dialed dials addr and, for UDP, which has no handshake, sends a datagram.
func dialed(network, addr string) string {
	c, err := net.DialTimeout(network, addr, 2*time.Second)
	if err == nil {
		_, err = c.Write([]byte("x"))
		c.Close()
	}
	if err != nil {
		return "failed: " + err.Error()
	}
	return "ok"
}

// childSays runs the helper as s's jailed child and returns its lines.
func childSays(t *testing.T, s *Source, tg Target, args ...string) map[string]string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := s.run(ctx, tg, append([]string{"-test.run=^TestJailedChildHelper$", "-test.v"}, args...)...)
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	said := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, " "); ok && (strings.HasSuffix(k, ":") || k == "cgroup" || k == "dial") {
			if k == "dial" {
				k, v, _ = strings.Cut(v, " ")
			}
			said[k] = v
		}
	}
	return said
}

// LOOP-1, ARC-2: a jailed child is not root, holds no capability and no
// supplementary group, and cannot reach the host's network over TCP or
// UDP, which the test process itself reaches.
func TestAJailedChildIsUnprivilegedAndOffline(t *testing.T) {
	needRoot(t)
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	ul, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	tcp, udp := "tcp:"+tl.Addr().String(), "udp:"+ul.LocalAddr().String()
	for _, a := range []string{tcp, udp} {
		n, addr, _ := strings.Cut(a, ":")
		if r := dialed(n, addr); r != "ok" {
			t.Fatalf("the host cannot dial its own %s: %s", a, r)
		}
	}
	s, tg := jailed(t, newFake(), "", helperBin(t))
	said := childSays(t, s, tg, tcp, udp)
	if f := strings.Fields(said["Uid:"]); len(f) != 4 || f[0] != "65534" || f[1] != "65534" || f[2] != "65534" || f[3] != "65534" {
		t.Errorf("child uids %q, want 65534 throughout", said["Uid:"])
	}
	if f := strings.Fields(said["Gid:"]); len(f) != 4 || f[0] != "65534" || f[1] != "65534" {
		t.Errorf("child gids %q", said["Gid:"])
	}
	if said["Groups:"] != "" {
		t.Errorf("child keeps supplementary groups %q", said["Groups:"])
	}
	for _, k := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"} {
		if said[k] != "0000000000000000" {
			t.Errorf("child %s %q, want none", k, said[k])
		}
	}
	for _, n := range []string{"tcp", "udp"} {
		if !strings.HasPrefix(said[n], "failed") {
			t.Errorf("a jailed child dialed the host over %s: %q", n, said[n])
		}
	}
}

// LOOP-7: a jailed child runs with no_new_privs, so no setuid or
// file-capability binary in the image (su, mount, passwd) can raise it
// back to root across exec (P3-4b-3r-confine-r3; #588 Security R1).
func TestAJailedChildCannotGainPrivileges(t *testing.T) {
	needRoot(t)
	s, tg := jailed(t, newFake(), "", helperBin(t))
	if got := childSays(t, s, tg)["NoNewPrivs:"]; got != "1" {
		t.Fatalf("jailed child NoNewPrivs %q, want 1", got)
	}
}

// helperSource is an unjailed source whose one target is this test
// binary, as TestJailedChildHelper.
func helperSource(t *testing.T) (*Source, Target) {
	t.Helper()
	release := t.TempDir()
	tg := Target{Pkg: "fake", Name: "FuzzFake", Binary: helperBin(t)(release), Dir: t.TempDir()}
	return newSource(t, newFake(), Config{Targets: []Target{tg}}), tg
}

// noNewPrivs reads the NoNewPrivs field of a /proc status file.
func noNewPrivs(t *testing.T, status string) string {
	t.Helper()
	b, err := os.ReadFile(status)
	if err != nil {
		return "gone"
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "NoNewPrivs:"); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("%s has no NoNewPrivs line", status)
	return ""
}

// LOOP-7: the flag is set in loop7's start path, not only by the unit,
// so every fuzz child carries it whoever starts agentosd; here as a
// user, with no jail.
func TestEveryFuzzChildHasNoNewPrivs(t *testing.T) {
	s, tg := helperSource(t)
	if got := childSays(t, s, tg)["NoNewPrivs:"]; got != "1" {
		t.Fatalf("fuzz child NoNewPrivs %q, want 1", got)
	}
}

// LOOP-7: the flag is per thread. The one loop7 sets it on is locked to
// the starting goroutine and ends with it, so no thread that runs Go
// code afterwards carries it, and children the daemon starts afterwards
// from other goroutines, outside loop7, do not. The process's main
// thread is the one exception the runtime makes: a locked goroutine that
// exits there wedges it for good (runtime.mexit), and no goroutine runs
// on it again, so it starts no child; it is left out of the scan. With
// the unit's NoNewPrivileges=yes every child carries the flag and this is
// moot.
func TestNoNewPrivsStaysOffTheDaemonsOtherThreads(t *testing.T) {
	if noNewPrivs(t, fmt.Sprintf("/proc/%d/status", os.Getppid())) != "0" {
		t.Skip("the test process was started with no_new_privs")
	}
	s, tg := helperSource(t)
	for range 5 {
		childSays(t, s, tg)
	}
	main := fmt.Sprintf("/proc/self/task/%d/status", os.Getpid())
	// A flagged thread may still be exiting: wait for it to go.
	deadline := time.Now().Add(5 * time.Second)
	for {
		tasks, err := filepath.Glob("/proc/self/task/*/status")
		if err != nil || len(tasks) == 0 {
			t.Fatalf("no threads listed: %v", err)
		}
		var flagged []string
		for _, st := range tasks {
			if st != main && noNewPrivs(t, st) == "1" {
				flagged = append(flagged, st)
			}
		}
		if len(flagged) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon threads still carry no_new_privs: %v", flagged)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Children from many goroutines, so they start on many threads.
	const n = 20
	out := make(chan string, n)
	for range n {
		go func() {
			b, err := exec.Command(tg.Binary, "-test.run=^TestJailedChildHelper$", "-test.v").CombinedOutput()
			if err != nil {
				out <- "error: " + err.Error()
				return
			}
			out <- string(b)
		}()
	}
	for range n {
		if said := <-out; !strings.Contains(said, "NoNewPrivs: 0") {
			t.Fatalf("a child started outside loop7 says:\n%s\nwant NoNewPrivs: 0", said)
		}
	}
}

// LOOP-1: a jailed child starts in the fuzz leaf, never in the broker's
// group (here, the test's), through CLONE_INTO_CGROUP.
func TestAJailedChildStartsInTheLeaf(t *testing.T) {
	leaf := testLeaf(t, "loop7-leaf", 256<<20)
	s, tg := jailed(t, newFake(), leaf.Path, helperBin(t))
	said := childSays(t, s, tg)
	parent := os.Getenv("AGENTOS_CGROUP_PARENT")
	rel := strings.TrimPrefix(leaf.Path, "/sys/fs/cgroup")
	if said["cgroup"] != "0::"+rel {
		t.Fatalf("child in %q, want 0::%s (parent %s)", said["cgroup"], rel, parent)
	}
	own, _ := os.ReadFile("/proc/self/cgroup")
	if strings.Contains(string(own), rel) {
		t.Fatalf("the test process moved into the leaf: %s", own)
	}
}

// LOOP-1, F12: a stored input that blows the leaf's memory.max is killed
// there by the kernel, not the test process (agentosd), and is reported
// as a crash finding naming that input: the whole replay dies with no
// "--- FAIL" line, so each input is replayed alone and the one killed is
// named.
func TestAnInputPastMemoryMaxIsKilledInTheLeafAndReported(t *testing.T) {
	leaf := testLeaf(t, "loop7-oom", 32<<20)
	g := newFake()
	s, tg := jailed(t, g, leaf.Path, func(release string) string {
		return fakeBin(t, release, "fake.test", `x=$(head -c 268435456 /dev/zero | tr '\0' a); echo ${#x}; exit 0`)
	})
	n, err := s.Fuzz(context.Background(), tg)
	if err != nil || n != 1 || len(g.reported) != 1 {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	data, _ := os.ReadFile(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzFake", "0crash"))
	if f := g.reported[0]; f.Check != loops.CheckFuzz || f.Detail != crashDetail(data) {
		t.Fatalf("finding %+v, want the input's digest", f)
	}
	if k, err := leaf.OOMKills(); err != nil || k == 0 {
		t.Fatalf("no OOM kill in the leaf: %d, %v", k, err)
	}
}

// LOOP-7, F3: a jailed target still reads its stored crash input, writes
// to its corpus as the engine does, and its failure reaches Report.
func TestAJailedTargetStillReportsItsCrash(t *testing.T) {
	needRoot(t)
	g := newFake()
	s, tg := jailed(t, g, "", func(release string) string {
		return fakeBin(t, release, "fake.test", `case "$1" in -test.run=^FuzzFake\$)
			cat testdata/fuzz/FuzzFake/0crash >/dev/null && touch testdata/fuzz/FuzzFake/w || exit 2
			echo "    --- FAIL: FuzzFake/0crash (0.00s)"; exit 1;; esac; exit 0`)
	})
	n, err := s.Fuzz(context.Background(), tg)
	data, _ := os.ReadFile(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzFake", "0crash"))
	if err != nil || n != 1 || len(g.reported) != 1 || g.reported[0].Detail != crashDetail(data) {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	if fi, err := os.Stat(filepath.Join(tg.Dir, "testdata", "fuzz", "FuzzFake", "w")); err != nil || fi.Sys().(*syscall.Stat_t).Uid != nobody {
		t.Fatalf("the child did not write its corpus as nobody: %v", err)
	}
}

// LOOP-7, F9: Own gives the state tree to the jail's user, so a crash
// input written as root before this update stays readable, but never
// follows a link out of it or takes a hard-linked file, and the release's
// seeds stay root's.
func TestOwnGivesTheStateToTheJailUser(t *testing.T) {
	needRoot(t)
	base := jailDir(t)
	release, state := filepath.Join(base, "release"), filepath.Join(base, "state")
	seeds := filepath.Join(release, "corpus", "fake", "FuzzFake")
	if err := os.MkdirAll(seeds, 0o755); err != nil {
		t.Fatal(err)
	}
	seed := cacheFile(t, seeds, "s1", 3, 0)
	if err := os.WriteFile(filepath.Join(release, "manifest.json"), []byte(`{"targets":[{"pkg":"fake","name":"FuzzFake","binary":"fake.test"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ts, err := Load(release, state)
	if err != nil {
		t.Fatal(err)
	}
	old := cacheFile(t, state, "targets/fake/testdata/fuzz/FuzzFake/0crash", 3, 0)
	outside := cacheFile(t, base, "outside", 3, 0)
	if err := os.Symlink(outside, filepath.Join(state, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(state, "hard")); err != nil {
		t.Fatal(err)
	}
	if err := (&Jail{UID: nobody, GID: nobody, State: state}).Own(); err != nil {
		t.Fatal(err)
	}
	uid := func(p string) uint32 {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Sys().(*syscall.Stat_t).Uid
	}
	for _, p := range []string{state, ts[0].Dir, filepath.Join(ts[0].Dir, "testdata", "fuzz", "FuzzFake", "s1"), old} {
		if uid(p) != nobody {
			t.Errorf("%s not given to the jail user", p)
		}
	}
	for _, p := range []string{outside, seed, release} {
		if uid(p) != 0 {
			t.Errorf("%s left root's hands", p)
		}
	}
}

// outsideDir is a root-owned directory outside every fuzz tree, as /etc
// is; the tests check root never writes, chowns or removes there.
func outsideDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	cacheFile(t, d, "keep", 7, 300*time.Hour)
	return d
}

func untouched(t *testing.T, d string) {
	t.Helper()
	es, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 || es[0].Name() != "keep" {
		t.Fatalf("root wrote through a planted link into %s: %v", d, es)
	}
	fi, err := os.Lstat(filepath.Join(d, "keep"))
	if err != nil {
		t.Fatalf("root removed through a planted link: %v", err)
	}
	if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != os.Getuid() {
		t.Fatalf("root chowned through a planted link: uid %d", st.Uid)
	}
}

// LOOP-7, ARC-2 (L3 1a on #588): the state tree belongs to the fuzz user,
// who can swap a corpus directory for a link; Load, which runs as root,
// writes no seed through it.
func TestLoadNeverWritesThroughAPlantedLink(t *testing.T) {
	release, state, outside := t.TempDir(), t.TempDir(), outsideDir(t)
	seeds := filepath.Join(release, "corpus", "fake", "FuzzFake")
	cacheFile(t, seeds, "s1", 3, 0)
	if err := os.WriteFile(filepath.Join(release, "manifest.json"), []byte(`{"targets":[{"pkg":"fake","name":"FuzzFake","binary":"fake.test"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	corpus := filepath.Join(state, "targets", "fake", "testdata", "fuzz")
	if err := os.MkdirAll(corpus, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(corpus, "FuzzFake")); err != nil {
		t.Fatal(err)
	}
	Load(release, state) // refusing is fine; writing outside is not
	untouched(t, outside)

	// The whole targets directory swapped for a link (Security B2).
	state2 := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(state2, "targets")); err != nil {
		t.Fatal(err)
	}
	Load(release, state2)
	untouched(t, outside)
}

// LOOP-1, ARC-2 (L3 1b on #588): a cache directory swapped for a link
// does not take the per-run scratch directory, or its chown to the fuzz
// user, out of the tree.
func TestScratchIsMadeWithoutFollowingALink(t *testing.T) {
	needRoot(t)
	// Reachable by the fuzz user, so the child can show where HOME went.
	outside := filepath.Join(jailDir(t), "etc")
	cacheFile(t, outside, "keep", 7, 300*time.Hour)
	if err := os.Chmod(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	s, tg := jailed(t, newFake(), "", func(release string) string {
		return fakeBin(t, release, "fake.test", `readlink -f "$HOME" > home`)
	})
	if err := os.Symlink(outside, s.cfg.CacheDir); err != nil {
		t.Fatal(err)
	}
	s.run(context.Background(), tg, "-test.run=^$")
	untouched(t, outside)
	if home, err := os.ReadFile(filepath.Join(tg.Dir, "home")); err == nil && strings.HasPrefix(string(home), outside) {
		t.Fatalf("the scratch directory was made through the link: HOME %s", home)
	}
}

// LOOP-1 (L3 1c on #588): the prune removes nothing reached through a
// link, even one swapped in for a package's cache directory.
func TestThePruneRemovesNothingThroughALink(t *testing.T) {
	release, cache, outside := t.TempDir(), t.TempDir(), outsideDir(t)
	tg := fakeTarget(t, release, "exit 0")
	if err := os.MkdirAll(filepath.Join(cache, "fuzz"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cache, "fuzz", "fake")); err != nil {
		t.Fatal(err)
	}
	s := newSource(t, newFake(), Config{Targets: []Target{tg}, CacheDir: cache, CacheCap: 1, CacheTotal: 1})
	s.Fuzz(context.Background(), tg)
	untouched(t, outside)
}

// LOOP-1, ARC-2 (L3 1 on #588): a child that leaves its process group
// (setsid) is killed with its run: nothing of the fuzz user outlives a
// run to race root's work in its tree, or to fill the disk.
func TestAChildThatLeavesItsGroupDiesWithItsRun(t *testing.T) {
	leaf := testLeaf(t, "loop7-setsid", 256<<20)
	s, tg := jailed(t, newFake(), leaf.Path, func(release string) string {
		return fakeBin(t, release, "fake.test", `setsid sh -c 'echo $$ > escaped; exec sleep 60' </dev/null >/dev/null 2>&1 &
			while [ ! -s escaped ]; do sleep 0.05; done; exit 0`)
	})
	if _, err := s.run(context.Background(), tg, "-test.run=^$"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(tg.Dir, "escaped"))
	if err != nil {
		t.Fatal(err)
	}
	pid := strings.TrimSpace(string(b))
	if st, err := os.ReadFile("/proc/" + pid + "/stat"); err == nil && !strings.Contains(string(st), ") Z ") {
		t.Fatalf("the escaped child %s outlived its run", pid)
	}
	if p, err := leaf.Populated(); err != nil || p {
		t.Fatalf("the leaf still holds a process after the run: %v %v", p, err)
	}
}

// LOOP-7, ARC-2: a jail's cache and every target's directory lie in its
// State, the only tree root works in for the fuzz user.
func TestAJailedPathOutsideItsStateIsRefused(t *testing.T) {
	release, state := t.TempDir(), t.TempDir()
	tg := fakeTarget(t, release, "exit 0")
	tg.Dir = filepath.Join(state, "targets", "fake")
	for name, c := range map[string]Config{
		"cache outside":  {CacheDir: t.TempDir(), Targets: []Target{tg}},
		"target outside": {CacheDir: filepath.Join(state, "cache"), Targets: []Target{fakeTarget(t, release, "exit 0")}},
		"no state":       {CacheDir: filepath.Join(state, "cache"), Targets: []Target{tg}, Jail: &Jail{UID: nobody, GID: nobody}},
	} {
		if c.Jail == nil {
			c.Jail = &Jail{UID: nobody, GID: nobody, State: state}
		}
		c.Inner, c.Report, c.Release = newFake(), newFake(), release
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// LOOP-7 (Security B3 on #588): on a fresh state the cache does not yet
// exist; root creates it for the run, and the jailed fuzz step can still
// write its -test.fuzzcachedir and its $TMPDIR.
func TestAJailedFuzzStepUsesItsCacheOnFirstBoot(t *testing.T) {
	needRoot(t)
	s, tg := jailed(t, newFake(), "", func(release string) string {
		return fakeBin(t, release, "fake.test", `c=
			for a; do case "$a" in -test.fuzzcachedir=*) c=${a#*=};; esac; done
			if [ -n "$c" ]; then mkdir -p "$c/FuzzFake" && touch "$c/FuzzFake/x" "$TMPDIR/y" || exit 3; fi
			exit 0`)
	})
	if _, err := os.Lstat(s.cfg.CacheDir); err == nil {
		t.Fatal("the cache exists before the first run")
	}
	if n, err := s.Fuzz(context.Background(), tg); n != 0 || err != nil {
		t.Fatalf("a first-boot fuzz step: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(filepath.Join(s.cfg.CacheDir, "fuzz", "fake", "FuzzFake", "x")); err != nil {
		t.Fatalf("the step wrote no cache: %v", err)
	}
}

// LOOP-7 (L3 delta on #588): a fuzz step that did not run says why. A
// failing Go test binary ends its output with a bare FAIL line, so the
// runner's error carries the reason above it, not that trailer.
func TestAFuzzStepThatDidNotRunSaysWhy(t *testing.T) {
	release := t.TempDir()
	tg := fakeTarget(t, release, stepBin(`printf -- '--- FAIL: FuzzFake\n    engine refused the cache directory\nFAIL\n'; exit 1`, "1"))
	s := newSource(t, newFake(), Config{Targets: []Target{tg}})
	_, err := s.Fuzz(context.Background(), tg)
	if err == nil || !strings.Contains(err.Error(), "engine refused the cache directory") {
		t.Fatalf("error %v, want the engine's reason", err)
	}
}

// P3-4b-3r-confine-r5: each of F16's defences fails a test when reverted.
// REQ: LOOP-7, LOOP-1

// machine skips unless the test runs as root in CI's machines job, which
// sets AGENTOS_CGROUP_PARENT.
func machine(t *testing.T) {
	t.Helper()
	needRoot(t)
	if os.Getenv("AGENTOS_CGROUP_PARENT") == "" {
		t.Skip("set AGENTOS_CGROUP_PARENT to run the machines job's root tests")
	}
}

// snapshot is every file under d with its mode, owner and contents.
func snapshot(t *testing.T, d string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(d, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		st := fi.Sys().(*syscall.Stat_t)
		v := fmt.Sprintf("%v %d:%d", fi.Mode(), st.Uid, st.Gid)
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		out[p] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(t *testing.T, before, after map[string]string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("files outside the state changed: before %v, after %v", before, after)
	}
	for p, v := range before {
		if after[p] != v {
			t.Fatalf("%s outside the state changed: %q, now %q", p, v, after[p])
		}
	}
}

// linkedOut is a jailed source whose target directory (state/targets/fake)
// is a link the fuzz user planted to a root-owned directory outside the
// state, holding a corpus file x and a file named as a release seed, s1.
// The child, built from body, can enter it; only root's work is checked.
func linkedOut(t *testing.T, g *fakeGuard, body string) (*Source, Target, string, map[string]string) {
	t.Helper()
	base := jailDir(t)
	release, state, outside := filepath.Join(base, "release"), filepath.Join(base, "state"), filepath.Join(base, "outside")
	corpus := filepath.Join(outside, "testdata", "fuzz", "FuzzFake")
	if err := os.MkdirAll(corpus, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{outside, filepath.Join(outside, "testdata"), filepath.Join(outside, "testdata", "fuzz"), corpus} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{"x": "go test fuzz v1\n[]byte(\"outside\")\n", "s1": "outside seed name"} {
		if err := os.WriteFile(filepath.Join(corpus, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seeds := filepath.Join(release, "corpus", "fake", "FuzzFake")
	if err := os.MkdirAll(seeds, 0o755); err != nil {
		t.Fatal(err)
	}
	cacheFile(t, seeds, "s1", 3, 0)
	cacheFile(t, seeds, "s2", 3, 0)
	if err := os.WriteFile(filepath.Join(release, "manifest.json"), []byte(`{"targets":[{"pkg":"fake","name":"FuzzFake","binary":"fake.test"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(state, "targets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(state, "targets", "fake")); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, outside)
	if _, err := Load(release, state); err == nil {
		t.Error("Load seeded through a link out of the state")
	}
	sameTree(t, before, snapshot(t, outside))
	j := &Jail{UID: nobody, GID: nobody, State: state}
	if err := j.Own(); err != nil {
		t.Fatal(err)
	}
	tg := Target{Pkg: "fake", Name: "FuzzFake", Binary: fakeBin(t, release, "fake.test", body), Dir: filepath.Join(state, "targets", "fake")}
	s := newSource(t, g, Config{Targets: []Target{tg}, CacheDir: filepath.Join(state, "cache"), Jail: j})
	return s, tg, outside, before
}

// LOOP-7, F16 (r5 point 1): root never reads, replaces or creates a file
// through a link out of the state: not in Load's seeding, not in a
// replay's read of a failing or passing input, not after a fuzz step. The
// round fails as the runner's error, never as a finding or a resolution.
func TestALinkOutOfTheStateIsNeverFollowed(t *testing.T) {
	machine(t)
	marks := jailDir(t)
	if err := os.Chmod(marks, 0o777); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"replay fails":  `case "$1" in -test.run=^FuzzFake\$) echo "    --- FAIL: FuzzFake/x (0.00s)"; exit 1;; esac; exit 0`,
		"replay passes": `case "$1" in -test.run=^FuzzFake\$) echo "    --- PASS: FuzzFake/x (0.00s)"; exit 0;; esac; exit 0`,
		"fuzz step": `m=` + marks + `/stepped
			case "$1" in
			-test.run=^FuzzFake\$) [ -e $m ] && { echo "    --- FAIL: FuzzFake/x (0.00s)"; exit 1; }; exit 0;;
			-test.run=^\$) : > $m; echo "Failing input written to testdata/fuzz/FuzzFake/x"; exit 1;;
			esac; exit 0`,
	} {
		t.Run(name, func(t *testing.T) {
			os.Remove(filepath.Join(marks, "stepped"))
			g := newFake()
			s, tg, outside, before := linkedOut(t, g, body)
			// An open finding a read of the outside x would resolve.
			x, err := os.ReadFile(filepath.Join(outside, "testdata", "fuzz", "FuzzFake", "x"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := g.Report(context.Background(), loops.Finding{Check: loops.CheckFuzz, Subject: tg.subject(), Severity: loops.High, Detail: crashDetail(x)}); err != nil {
				t.Fatal(err)
			}
			g.reported = nil
			n, err := s.Fuzz(context.Background(), tg)
			if err == nil || n != 0 {
				t.Errorf("n=%d err=%v, want the runner's error", n, err)
			}
			if len(g.reported) != 0 || len(g.resolved) != 0 {
				t.Errorf("a read through the link became a finding or a resolution: reported %+v resolved %v", g.reported, g.resolved)
			}
			sameTree(t, before, snapshot(t, outside))
		})
	}
}

// LOOP-7, F16 (r5 point 2): ownPath chowns neither the target of a link
// at rel nor anything reached through a link above it.
func TestOwnPathNeverChownsThroughALink(t *testing.T) {
	machine(t)
	for name, plant := range map[string]func(state, outside string) error{
		"link at rel": func(state, outside string) error {
			if err := os.Mkdir(filepath.Join(state, "cache"), 0o700); err != nil {
				return err
			}
			return os.Symlink(filepath.Join(outside, "keep"), filepath.Join(state, "cache", "run-1"))
		},
		"link above rel": func(state, outside string) error {
			if err := os.Mkdir(filepath.Join(outside, "run-1"), 0o700); err != nil {
				return err
			}
			return os.Symlink(outside, filepath.Join(state, "cache"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			state, outside := jailDir(t), outsideDir(t)
			if err := plant(state, outside); err != nil {
				t.Fatal(err)
			}
			before := snapshot(t, outside)
			r, err := os.OpenRoot(state)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			(&Jail{UID: nobody, GID: nobody, State: state}).ownPath(r, filepath.Join("cache", "run-1"))
			sameTree(t, before, snapshot(t, outside))
		})
	}
}

// LOOP-1, F16 (r5 point 2; L3 3 on #588): a package's cache directory
// swapped for a link after the prune's walk and before its removals
// takes no removal out of the state.
func TestThePruneRemovesNothingThroughALinkSwappedAfterItsWalk(t *testing.T) {
	state, outside := t.TempDir(), outsideDir(t)
	cache := filepath.Join(state, "cache")
	for _, d := range []string{cache, outside} {
		cacheFile(t, d, "fuzz/fake/FuzzFake/old", 400, 3*time.Hour)
		cacheFile(t, d, "fuzz/fake/FuzzFake/new", 400, time.Hour)
	}
	pkg := filepath.Join(cache, "fuzz", "fake")
	pruneWalked = func() {
		if err := os.Rename(pkg, pkg+".moved"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(filepath.Join(outside, "fuzz", "fake"), pkg); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { pruneWalked = nil })
	release := t.TempDir()
	tg := fakeTarget(t, release, "exit 0")
	tg.Dir = filepath.Join(state, "targets", "fake")
	s := newSource(t, newFake(), Config{Targets: []Target{tg}, CacheDir: cache, CacheCap: 1, CacheTotal: 1,
		Jail: &Jail{UID: nobody, GID: nobody, State: state}})
	before := snapshot(t, outside)
	s.prune("fake") // refusing is fine; removing outside is not
	sameTree(t, before, snapshot(t, outside))
}

// LOOP-7 (r5 point 3): a hang seen again on a newer build records that
// build when the child runs jailed in the leaf, as agentosd runs it.
func TestAJailedRepeatedHangRecordsTheNewerBuild(t *testing.T) {
	leaf := testLeaf(t, "loop7-hang", 256<<20)
	g := newFake()
	var release string
	s, tg := jailed(t, g, leaf.Path, func(r string) string {
		release = r
		return fakeBin(t, r, "fake.test", stepBin(progress(2, 2), "1"))
	})
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 || len(g.reported) != 1 || g.reported[0].Detail != loops.FuzzStallDetail {
		t.Fatalf("n=%d err=%v reported %+v", n, err, g.reported)
	}
	fakeBin(t, release, "fake.test", stepBin(progress(2, 2), "2"))
	if n, err := s.Fuzz(context.Background(), tg); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if st, err := s.readHangs(tg); err != nil || st[loops.FuzzStallDetail] != fileDigest(t, tg.Binary) {
		t.Fatalf("state %v %v", st, err)
	}
}

// LOOP-1 (r5 point 3, F16): a jailed child still starts in the leaf after
// it has been emptied twice in a row. A cgroup.kill in empty would kill
// every child started there afterwards (the regression F16 records).
func TestAJailedChildStartsAfterTheLeafIsEmptiedTwice(t *testing.T) {
	leaf := testLeaf(t, "loop7-twice", 256<<20)
	s, tg := jailed(t, newFake(), leaf.Path, helperBin(t))
	for i := 0; i < 2; i++ {
		if err := s.cfg.Jail.empty(); err != nil {
			t.Fatal(err)
		}
	}
	said := childSays(t, s, tg)
	if rel := strings.TrimPrefix(leaf.Path, "/sys/fs/cgroup"); said["cgroup"] != "0::"+rel {
		t.Fatalf("child in %q, want 0::%s", said["cgroup"], rel)
	}
}
