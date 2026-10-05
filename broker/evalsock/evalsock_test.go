package evalsock

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/replay"
)

// REQ: CHG-1, LOOP-5, ARC-2

// runner is a fake replay: it records what each run saw through the
// server's Active and Task.
type runner struct {
	s       *Server
	mu      sync.Mutex
	tasks   []string
	actives []change.Tree
	err     error
	inside  atomic.Int32
	overlap atomic.Bool
	hold    time.Duration
}

func (r *runner) Run(_ context.Context, t change.Tree, p change.Probe) ([]byte, error) {
	if r.inside.Add(1) > 1 {
		r.overlap.Store(true)
	}
	defer r.inside.Add(-1)
	time.Sleep(r.hold)
	task, _ := r.s.Task(p.ID)
	_, other := r.s.Task(p.ID + "x")
	active := change.Tree{}
	for _, ns := range []string{"config", "routing", "context", "skills"} {
		for k, v := range r.s.Active(ns) {
			active[k] = v
		}
	}
	r.mu.Lock()
	r.tasks = append(r.tasks, task)
	r.actives = append(r.actives, active)
	r.mu.Unlock()
	if other {
		return nil, errors.New("another probe had a task")
	}
	if r.err != nil {
		return nil, r.err
	}
	return []byte(fmt.Sprintf("%s|%s|%s", p.ID, p.Input, t["skills/a.md"])), nil
}

func serve(t *testing.T, r *runner, uid int) string {
	t.Helper()
	s := &Server{}
	r.s = s
	s.Runner = r
	// Unix socket paths are short; t.TempDir can exceed the limit.
	dir, err := os.MkdirTemp("", "evalsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "eval.sock")
	ln, err := Listen(path, uid)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Serve(ctx, ln, s); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return path
}

var active = change.Tree{
	"config/guest.json":   []byte("cfg"),
	"routing/rule.json":   []byte("rule"),
	"context/owner.md":    []byte("owner's private notes"),
	"skills/old.md":       []byte("old skill"),
	"guest-image/digest":  []byte("sha"),
	"host-image/digest":   []byte("sha2"),
	"procedures/pay.md":   []byte("steps"),
	"suites/never-sent":   []byte("x"),
	"grants/never-either": []byte("y"),
}

// The pipeline's evaluator runs in the learning process; agentosd replays.
// The run sees the probe's task and the compared namespaces of the active
// tree, and nothing else of the active tree crosses the socket.
func TestCHG1EvaluationCrossesTheSocket(t *testing.T) {
	r := &runner{}
	c := NewClient(ClientConfig{
		Socket:    serve(t, r, os.Getuid()),
		ProbeTask: func(id string) (string, bool) { return "task-of-" + id, true },
		Active: func(ns string) change.Tree {
			out := change.Tree{}
			for p, b := range active {
				if strings.HasPrefix(p, ns+"/") {
					out[p] = b
				}
			}
			return out
		},
	})
	out, err := c.Run(context.Background(), change.Tree{"skills/a.md": []byte("new skill")}, change.Probe{ID: "p1", Input: []byte("book a table")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "p1|book a table|new skill" {
		t.Fatalf("output %q", out)
	}
	if r.tasks[0] != "task-of-p1" {
		t.Fatalf("task %q", r.tasks[0])
	}
	got := r.actives[0]
	if len(got) != 2 || string(got["config/guest.json"]) != "cfg" || string(got["routing/rule.json"]) != "rule" {
		t.Fatalf("active seen by the run: %v", got)
	}
}

// ActiveNamespaces covers every namespace replay compares to the active
// tree, plus routing, which an offline replay compares too.
func TestLOOP5ActiveNamespacesCoverReplay(t *testing.T) {
	for _, ns := range append(append([]string(nil), replay.Untested...), "routing") {
		if !contains(ActiveNamespaces, ns) {
			t.Errorf("replay compares %s, which the socket does not carry", ns)
		}
	}
}

// A tree agentosd cannot evaluate is "not evaluated" on the pipeline's
// side, never a pass; any other failure is a plain failure.
func TestCHG1NotEvaluatedSurvivesTheSocket(t *testing.T) {
	r := &runner{err: fmt.Errorf("%w: config", replay.ErrNotEvaluated)}
	c := NewClient(ClientConfig{Socket: serve(t, r, os.Getuid())})
	if _, err := c.Run(context.Background(), change.Tree{}, change.Probe{ID: "p"}); !errors.Is(err, change.ErrNotEvaluated) {
		t.Fatalf("not evaluated: %v", err)
	}
	r2 := &runner{err: replay.ErrUnrecorded}
	c2 := NewClient(ClientConfig{Socket: serve(t, r2, os.Getuid())})
	_, err := c2.Run(context.Background(), change.Tree{}, change.Probe{ID: "p"})
	if err == nil || errors.Is(err, change.ErrNotEvaluated) {
		t.Fatalf("failed run: %v", err)
	}
}

// A security fixture has no task: the run sees none, so every effect it
// asks for fails closed.
func TestLOOP5FixtureHasNoTask(t *testing.T) {
	r := &runner{}
	c := NewClient(ClientConfig{Socket: serve(t, r, os.Getuid()), ProbeTask: func(string) (string, bool) { return "", false }})
	if _, err := c.Run(context.Background(), change.Tree{}, change.Probe{ID: "fx"}); err != nil {
		t.Fatal(err)
	}
	if r.tasks[0] != "" {
		t.Fatalf("fixture task %q", r.tasks[0])
	}
}

// One replay machine at a time: concurrent requests never overlap, so each
// run's Active and Task are its own.
func TestLOOP5RunsAreSerialized(t *testing.T) {
	r := &runner{hold: 20 * time.Millisecond}
	c := NewClient(ClientConfig{Socket: serve(t, r, os.Getuid()), ProbeTask: func(id string) (string, bool) { return "t-" + id, true }})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := c.Run(context.Background(), change.Tree{}, change.Probe{ID: fmt.Sprint("p", i)}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if r.overlap.Load() {
		t.Fatal("runs overlapped")
	}
}

// ARC-2: only the learning process's uid reaches the socket.
func TestARC2OnlyThePeerUIDIsServed(t *testing.T) {
	r := &runner{}
	c := NewClient(ClientConfig{Socket: serve(t, r, os.Getuid()+1), Timeout: 2 * time.Second})
	if _, err := c.Run(context.Background(), change.Tree{}, change.Probe{ID: "p"}); err == nil {
		t.Fatal("a connection from another uid was served")
	}
	if len(r.tasks) != 0 {
		t.Fatal("the runner ran")
	}
}

// The server decodes strictly: unknown fields, a missing probe, or an
// active tree outside the compared namespaces are refused before any run.
func TestCHG1StrictRequests(t *testing.T) {
	r := &runner{}
	s := &Server{Runner: r}
	r.s = s
	for _, body := range []string{
		`{"tree":{},"probe":{"id":"p"},"active":{},"extra":1}`,
		`{"tree":{},"probe":{},"active":{}}`,
		`{"tree":{},"probe":{"id":"p"},"active":{"context/owner.md":"eA=="}}`,
		`not json`,
	} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("POST", "/run", strings.NewReader(body)))
		if w.Code != 400 {
			t.Errorf("%s: status %d", body, w.Code)
		}
	}
	if len(r.tasks) != 0 {
		t.Fatal("a refused request ran")
	}
}
