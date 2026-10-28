package proc

// REQ: CLK-2, KRN-7, KRN-8, STO-2

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// fakeClerk answers every call with do's result.
type fakeClerk struct {
	do      func() kernel.Result
	probe   string
	covered string // what Probe gives with its outcome
}

func (f fakeClerk) Do(kernel.Request, kernel.View) kernel.Result { return f.do() }

func (f fakeClerk) Probe(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: f.probe, Covered: f.covered}
}

// serveFake serves c on a fresh socket for the test's uid.
func serveFake(t *testing.T, c kernel.Clerk) string {
	t.Helper()
	sock := filepath.Join(shortDir(t), "fake.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeClerk(ln, c, anchors)
	return sock
}

// The kernel logs only what a clerk may answer: an outcome from the closed
// list (anything else is unknown, to be probed) and a short, valid detail.
func TestKernelBoundsWhatAClerkAnswers(t *testing.T) {
	for _, c := range []struct {
		res          kernel.Result
		probe        string
		want, wantPr string
		detail       string
	}{
		{kernel.Result{Outcome: "ok", Detail: "sent"}, "done", "ok", "done", "sent"},
		{kernel.Result{Outcome: "done", Detail: "x"}, "ok", "unknown", "unknown", "x"},
		{kernel.Result{Outcome: "failed", Detail: strings.Repeat("d", maxDetail+1)}, "notdone", "failed", "notdone", "malformed"},
		{kernel.Result{Outcome: "failed", Detail: "sent\nok"}, "", "failed", "unknown", "malformed"},
	} {
		sock := serveFake(t, fakeClerk{do: func() kernel.Result { return c.res }, probe: c.probe})
		r := remote{Remote: Remote{Socket: sock, UID: os.Getuid()}}
		v := kernel.NewState(anchors)
		got := r.Do(kernel.Request{}, v)
		if got.Outcome != c.want || got.Detail != c.detail {
			t.Errorf("clerk answered %+v: kernel took %+v, want %s %q", c.res, got, c.want, c.detail)
		}
		if p := r.Probe(kernel.Request{}, v).Outcome; p != c.wantPr {
			t.Errorf("clerk probed %q: kernel took %q, want %q", c.probe, p, c.wantPr)
		}
	}
	// No clerk listening: nothing was sent, so the step is sent again later,
	// and a probe made no check.
	r := remote{Remote: Remote{Socket: filepath.Join(shortDir(t), "none.sock"), UID: os.Getuid()}}
	if got := r.Do(kernel.Request{}, kernel.NewState(nil)); got.Outcome != kernel.OUnsent || got.Detail != DUnreachable {
		t.Fatalf("no clerk: %+v, want unsent %s", got, DUnreachable)
	}
	if got := r.Probe(kernel.Request{}, kernel.NewState(nil)).Outcome; got != kernel.OUnreached {
		t.Fatalf("no clerk, probed: %q, want %s", got, kernel.OUnreached)
	}
}

// A view that leaves out the ledger of a scope the request's chain charges
// would read as unspent; the clerk's process refuses the call before the
// clerk sees it.
func TestClerkRefusesAViewWithoutTheLedger(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	sock := serveFake(t, fakeClerk{do: func() kernel.Result { mu.Lock(); calls++; mu.Unlock(); return kernel.Result{Outcome: "ok"} }})
	b := newBox(t, filepath.Join(t.TempDir(), "unused.sock"))
	id := b.submit("dave")
	var req kernel.Request
	b.h.With(func(k *kernel.Kernel) error { req = kernel.Request{Plan: k.State().Plans[id].Plan}; return nil })
	full := snapshot{Dispatch: &kernel.Dispatch{Seq: 99}, Grants: map[key.ID]int64{}, Ledger: map[key.ID][]key.Use{}}
	ver, err := kernel.VerifyPlan(req.Plan, anchors)
	if err != nil {
		t.Fatal(err)
	}
	scopes := ver.Scopes()
	if len(scopes) < 2 {
		t.Fatalf("chain has %d scopes", len(scopes))
	}
	for _, id := range scopes {
		full.Ledger[id] = nil
	}
	send := func(s snapshot) answer {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		json.NewEncoder(c).Encode(call{opDo, req, s})
		var a answer
		json.NewDecoder(c).Decode(&a)
		return a
	}
	if a := send(full); a.Outcome != "ok" {
		t.Fatalf("full view: %+v, want the clerk to be called", a)
	}
	part := full
	part.Ledger = map[key.ID][]key.Use{}
	for _, id := range scopes[1:] {
		part.Ledger[id] = nil
	}
	if a := send(part); a.Outcome != "failed" || a.Detail != DView {
		t.Fatalf("view missing the root's ledger: %+v, want failed %s", a, DView)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("clerk called %d times, want once", calls)
	}
}

// The log file is the kernel process's alone while it is open: a second
// kernel process cannot open it and fork the log.
func TestLogFileIsLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); !errors.Is(err, ErrLogInUse) {
		t.Fatalf("second open: %v, want %v", err, ErrLogInUse)
	}
	s.Close()
	s, err = OpenFileStore(path)
	if err != nil {
		t.Fatalf("open after close: %v", err)
	}
	s.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Fatal("a log file open to other uids was opened")
	}
}

// The file store keeps what it appended across a reopen and cuts a tail.
func TestFileStoreAppendTruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	s, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"abc", "def"} {
		if err := s.Append([]byte(b)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Truncate(4); err != nil {
		t.Fatal(err)
	}
	if err := s.Truncate(9); err == nil {
		t.Fatal("truncate past the end")
	}
	s.Close()
	s, _ = OpenFileStore(path)
	defer s.Close()
	if b, _ := s.ReadAll(); string(b) != "abcd" {
		t.Fatalf("read %q, want abcd", b)
	}
}

// The view carries the kernel's one-off line for the chain's root, and a root
// it does not name has line 0, so the clerk asks for a second passkey on any
// spend rather than allow one (D-146, kernel.OneOff).
func TestViewCarriesTheOneOffLine(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "unused.sock"))
	id := b.submit("erin")
	b.h.With(func(k *kernel.Kernel) error {
		r := kernel.Request{Plan: k.State().Plans[id].Plan}
		root := b.key.Root
		rid := key.Key{Root: root}.Tip()
		want := k.State().OneOffLine(rid, b.now)
		if want <= 0 {
			t.Fatalf("kernel's line %d: the test needs a live clerk key under the root", want)
		}
		s := view(k.State(), anchors, nil, r, b.now)
		if got := s.OneOffLine(rid, 0); got != want {
			t.Fatalf("view's line %d, want the kernel's %d", got, want)
		}
		if got := s.OneOffLine(key.ID{1}, b.now); got != 0 {
			t.Fatalf("line for a root the view does not name: %d, want 0", got)
		}
		return nil
	})
}

// The view carries the chain's task as the kernel's log has it, and the
// clerk judges its timeout and approval itself (KRN-5, CLK-3).
func TestViewCarriesTheChainsTask(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "unused.sock"))
	served, err := key.Derive(b.key, holderPriv, holderPub, key.LimitTask("t1"))
	if err != nil {
		t.Fatal(err)
	}
	a := kernel.TaskApproval{Site: "shop.example", First: "https://shop.example/"}
	a.By = key.Approve(key.Ed25519Signer(ownerPriv), kernel.TaskHash("t1", 0, a.Site, a.First))
	ps := kernel.PlanStep{Verb: key.Post, Clerk: "web", Args: map[string]string{"to": "erin", "msg": "hello"}, Content: "text", Labels: []string{"public"}}
	in := kernel.SignPlan(kernel.Plan{ID: "in", Key: served, Steps: []kernel.PlanStep{ps}}, holderPriv)
	out := kernel.SignPlan(kernel.Plan{ID: "out", Key: b.key, Steps: []kernel.PlanStep{ps}}, holderPriv)
	b.h.With(func(k *kernel.Kernel) error {
		if err := k.OpenTask(b.now, "t1"); err != nil {
			t.Fatal(err)
		}
		if err := k.ApproveTask(b.now, "t1", a); err != nil {
			t.Fatal(err)
		}
		s := view(k.State(), anchors, nil, kernel.Request{Plan: in}, b.now)
		ver, err := kernel.VerifyPlan(in, kernel.PlanOwners(&s, anchors, in.Key))
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := kernel.TaskApproved(&s, anchors, ver, a.Site, b.now); !ok || got.Site != a.Site || got.At != b.now {
			t.Fatalf("the view's task approval: %+v %v", got, ok)
		}
		if _, ok := s.Task("t1", b.now+kernel.TaskTimeout); ok {
			t.Fatal("the view's task past its timeout on the clerk's clock")
		}
		if _, ok := s.Task("t2", b.now); ok {
			t.Fatal("the view answered for a task the chain does not serve")
		}
		if s := view(k.State(), anchors, nil, kernel.Request{Plan: out}, b.now); s.Served != nil {
			t.Fatalf("a chain with no task carried one: %+v", s.Served)
		}
		if err := k.EndTask(b.now, "t1"); err != nil {
			t.Fatal(err)
		}
		if s := view(k.State(), anchors, nil, kernel.Request{Plan: in}, b.now); s.Served != nil {
			t.Fatal("the view carried an ended task")
		}
		return nil
	})
}

// hung is a clerk whose Do waits until released.
type hung struct {
	in, release chan struct{}
}

func (h hung) Do(kernel.Request, kernel.View) kernel.Result {
	h.in <- struct{}{}
	<-h.release
	return kernel.Result{Outcome: "ok"}
}

func (hung) Probe(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: "notdone"}
}

// STOP, and every other owner call, returns while a clerk call hangs: Tick
// makes clerk calls outside the kernel's lock (KRN-7, OWN-18). The answer is
// logged once the clerk returns.
func TestStopReturnsWhileAClerkCallHangs(t *testing.T) {
	sock := filepath.Join(shortDir(t), "hung.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	c := hung{make(chan struct{}), make(chan struct{})}
	go ServeClerk(ln, c, anchors)
	t.Cleanup(func() { ln.Close() })
	b := newBox(t, sock)
	id := b.submit("dave")
	ticked := make(chan error, 1)
	go func() { ticked <- b.h.Tick(b.now) }()
	<-c.in
	stopped := make(chan error, 1)
	go func() { stopped <- b.h.With(func(k *kernel.Kernel) error { return k.Stop(b.now) }) }()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("STOP waited on a hung clerk call")
	}
	close(c.release)
	if err := <-ticked; err != nil {
		t.Fatal(err)
	}
	if st := b.step(id); st.Phase != kernel.PDone {
		t.Fatalf("the hung call's answer was not logged: %+v", st)
	}
}

// first is a clerk whose first call hangs until released; it counts the
// calls that reach it.
type first struct {
	in, release chan struct{}
	mu          sync.Mutex
	n           int
}

func (f *first) Do(kernel.Request, kernel.View) kernel.Result {
	f.mu.Lock()
	f.n++
	n := f.n
	f.mu.Unlock()
	if n == 1 {
		f.in <- struct{}{}
		<-f.release
	}
	return kernel.Result{Outcome: "ok"}
}

func (*first) Probe(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: "notdone"}
}

// A STOP logged while one clerk call hangs stops every call after it in the
// same Tick: the kernel checks each dispatch again, under the lock, just
// before it is sent, and the stopped one is cancelled unsent (KRN-7).
func TestAStopWhileACallHangsSendsNothingAfterIt(t *testing.T) {
	sock := filepath.Join(shortDir(t), "first.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	c := &first{in: make(chan struct{}), release: make(chan struct{})}
	go ServeClerk(ln, c, anchors)
	t.Cleanup(func() { ln.Close() })
	b := newBox(t, sock)
	a, z := b.submit("dave"), b.submit("erin")
	ticked := make(chan error, 1)
	go func() { ticked <- b.h.Tick(b.now) }()
	<-c.in
	if err := b.h.With(func(k *kernel.Kernel) error { return k.Stop(b.now) }); err != nil {
		t.Fatal(err)
	}
	close(c.release)
	if err := <-ticked; err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n != 1 || b.step(a).Phase != kernel.PDone || b.step(z).Phase != kernel.PCancelled {
		t.Fatalf("after STOP: %d calls reached the clerk, steps %s and %s", c.n, b.step(a).Phase, b.step(z).Phase)
	}
}

// A view shares nothing with the kernel's state: Tick sends it outside the
// lock while revokes and pauses change that state (KRN-7). Run under -race.
func TestTickRacesNoOwnerChange(t *testing.T) {
	sock := filepath.Join(shortDir(t), "race.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	go ServeClerk(ln, fakeClerk{do: func() kernel.Result { return kernel.Result{Outcome: "ok"} }}, anchors)
	t.Cleanup(func() { ln.Close() })
	b := newBox(t, sock)
	for i := 0; i < 20; i++ {
		b.submit(fmt.Sprintf("r%d", i))
	}
	done := make(chan error, 1)
	go func() { done <- b.h.Tick(b.now) }()
	for i := 0; ; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return
		default:
		}
		id := key.ID{byte(i), byte(i >> 8), 1}
		if err := b.h.With(func(k *kernel.Kernel) error { return k.Revoke(b.now, id) }); err != nil {
			t.Fatal(err)
		}
	}
}

// A covered submit's STATUS line crosses the clerk's socket into the log
// (CLK-3, #2705).
func TestACoveredLineCrossesTheSocket(t *testing.T) {
	line := "Sent on shop.example: Place order, 12:00 UTC"
	for name, f := range map[string]fakeClerk{
		"answered": {do: func() kernel.Result { return kernel.Result{Outcome: "ok", Covered: line} }},
		"probed":   {do: func() kernel.Result { return kernel.Result{Outcome: "unknown"} }, probe: "done", covered: line},
	} {
		b := newBox(t, serveFake(t, f))
		id := b.submit("dave")
		b.tick(b.now)
		b.tick(b.now + kernel.ProbeEvery)
		b.h.With(func(k *kernel.Kernel) error {
			if c := k.State().Covered(b.now + kernel.ProbeEvery); len(c) != 1 || c[0].Plan != id || c[0].Line != line {
				t.Fatalf("%s: covered %+v", name, c)
			}
			return nil
		})
	}
}
