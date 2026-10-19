package main

// REQ: RES-2, ARC-2, DEP-1

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/cgroup"
	"github.com/ghbmrk/agentos/broker/infer"
	"github.com/ghbmrk/agentos/broker/infer/supervise"
)

// syncBuf is a log both the test and the supervisor's goroutine write.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// serviceUID is a non-root uid, not the test's, with a non-root primary
// group, for the service.
func serviceUID(t *testing.T) int {
	t.Helper()
	for _, id := range []int{65534, 1000, 1} {
		u, err := user.LookupId(strconv.Itoa(id))
		if err != nil || u.Gid == "0" || id == os.Getuid() {
			continue
		}
		return id
	}
	t.Skip("no non-root user with a non-root group on this host")
	return -1
}

// unavailableAt asserts a client of sock gets unavailable, never data.
func unavailableAt(t *testing.T, sock string) {
	t.Helper()
	c := infer.Client{Path: sock, Timeout: 500 * time.Millisecond}
	if _, err := c.Hello(context.Background()); infer.CauseOf(err) != infer.Unavailable {
		t.Fatalf("hello on %s: %v, want unavailable", sock, err)
	}
	if vs, _, err := c.Embed(context.Background(), []string{"synthetic"}); infer.CauseOf(err) != infer.Unavailable || vs != nil {
		t.Fatalf("embed on %s: %v %v, want unavailable and no vectors", sock, vs, err)
	}
}

// INF-4, DEP-1: with the service disabled, unconfigured or crash-looping,
// the broker's start goes on at once (startInference never waits and never
// exits), and the service's clients get unavailable. main calls it on the
// owner's path with nothing after it depending on its result.
func TestAgentosdServesControlWithoutInference(t *testing.T) {
	quick := func(t *testing.T, f func() *supervise.Supervisor) *supervise.Supervisor {
		t.Helper()
		start := time.Now()
		sv := f()
		if d := time.Since(start); d > time.Second {
			t.Fatalf("startInference took %s: the broker's start waited on it", d)
		}
		return sv
	}

	t.Run("disabled", func(t *testing.T) {
		sock := filepath.Join(shortDir(t), "infer", "infer.sock")
		called := false
		leaf := func() (*cgroup.Group, error) { called = true; return nil, errors.New("unused") }
		var log syncBuf
		sv := quick(t, func() *supervise.Supervisor {
			return startInference(context.Background(), inferFlags{Socket: sock, UID: 65534, Bin: "/nonexistent"}, leaf, &log)
		})
		if sv != nil || called {
			t.Fatalf("supervisor %v, leaf opened %v: -infer=false started something", sv, called)
		}
		if _, err := os.Stat(filepath.Dir(sock)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("socket directory: %v, want absent", err)
		}
		unavailableAt(t, sock)
	})

	t.Run("not startable", func(t *testing.T) {
		uid := serviceUID(t)
		noLeaf := func() (*cgroup.Group, error) { return nil, errors.New("synthetic: no delegated group") }
		for name, f := range map[string]inferFlags{
			"root uid":   {On: true, UID: 0},
			"broker uid": {On: true, UID: os.Getuid()},
			"unset uid":  {On: true, UID: -1},
			"no leaf":    {On: true, UID: uid},
			"relative":   {On: true, UID: uid, Bin: "agentos-infer"},
		} {
			t.Run(name, func(t *testing.T) {
				dir := shortDir(t)
				f.Socket = filepath.Join(dir, "infer", "infer.sock")
				if f.Bin == "" {
					f.Bin = "/nonexistent/agentos-infer"
				}
				leaf := noLeaf
				if name == "relative" {
					leaf = func() (*cgroup.Group, error) { return &cgroup.Group{Path: dir}, nil }
				}
				var log syncBuf
				sv := quick(t, func() *supervise.Supervisor { return startInference(context.Background(), f, leaf, &log) })
				if sv != nil {
					t.Fatal("started a service it should have refused")
				}
				if !strings.Contains(log.String(), "local inference not started: ") {
					t.Fatalf("log %q gives no reason", log.String())
				}
				unavailableAt(t, f.Socket)
			})
		}
	})

	t.Run("crash-looping", func(t *testing.T) {
		uid := serviceUID(t)
		dir := shortDir(t)
		sock := filepath.Join(dir, "infer", "infer.sock")
		// Not a cgroup: every start fails, as a service that dies at once does.
		leaf := func() (*cgroup.Group, error) { return &cgroup.Group{Path: filepath.Join(dir, "leaf")}, nil }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var log syncBuf
		sv := quick(t, func() *supervise.Supervisor {
			return startInference(ctx, inferFlags{On: true, Socket: sock, UID: uid, Bin: "/nonexistent/agentos-infer"}, leaf, &log)
		})
		if sv == nil {
			t.Fatalf("not started: %s", log.String())
		}
		deadline := time.Now().Add(5 * time.Second)
		for sv.State().Restarts < 1 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if st := sv.State(); st.State != supervise.Unavailable && st.State != supervise.Starting || st.Restarts < 1 {
			t.Fatalf("state %+v, want unavailable with a restart counted", st)
		}
		unavailableAt(t, sock)
		cancel()
		select {
		case <-sv.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("the supervisor outlived the broker's context")
		}
	})
}

// INF-1: the leaf is the inference component beside the machine pool, and
// it must carry the budget; anything else is no leaf.
func TestInferenceLeafIsTheBudgetedComponent(t *testing.T) {
	root := shortDir(t)
	machines := &cgroup.Group{Path: filepath.Join(root, "machines")}
	open := func() (*cgroup.Group, error) { return machines, nil }
	if _, err := inferenceLeaf(open, 0)(); err == nil {
		t.Fatal("a 0 MB budget gave a leaf")
	}
	if _, err := inferenceLeaf(func() (*cgroup.Group, error) { return nil, errors.New("synthetic") }, 64)(); err == nil {
		t.Fatal("no machine group, yet a leaf")
	}
	if _, err := inferenceLeaf(open, 64)(); err == nil {
		t.Fatal("no inference group, yet a leaf")
	}
	leafDir := filepath.Join(root, "inference")
	if err := os.Mkdir(leafDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"max\n", "1\n"} {
		os.WriteFile(filepath.Join(leafDir, "memory.max"), []byte(v), 0o644)
		if _, err := inferenceLeaf(open, 64)(); err == nil {
			t.Fatalf("memory.max %q accepted as the 64 MB budget", v)
		}
	}
	os.WriteFile(filepath.Join(leafDir, "memory.max"), []byte("67108864\n"), 0o644)
	g, err := inferenceLeaf(open, 64)()
	if err != nil || g.Path != leafDir {
		t.Fatalf("leaf %v, %v; want %s", g, err, leafDir)
	}
}

// INF-2, removal row: the service is off unless asked for, at the
// brief's socket path, and main starts it through startInference alone.
func TestInferenceIsOffByDefault(t *testing.T) {
	var f inferFlags
	fs := flag.NewFlagSet("agentosd", flag.ContinueOnError)
	f.register(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	want := inferFlags{Socket: "/run/agentos/infer/infer.sock", UID: -1, Bin: "/usr/lib/agentos/agentos-infer"}
	if f != want {
		t.Fatalf("defaults %+v, want %+v", f, want)
	}
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"inf.register(flag.CommandLine)",
		"\tstartInference(ctx, inf, inferenceLeaf(boxMachines, mem.Budget.InferenceMB), log.Writer())\n",
	} {
		if strings.Count(string(src), s) != 1 {
			t.Fatalf("main.go does not hold %q once", s)
		}
	}
	if strings.Contains(string(src), "supervise.") {
		t.Fatal("main.go reaches the supervisor other than through startInference")
	}
}
