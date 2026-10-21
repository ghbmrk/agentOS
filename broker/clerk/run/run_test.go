package run

// REQ: CLK-1, CLK-2, KRN-8, STO-2, STO-3

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// box is the test process as the kernel's process, with one clerk at
// sock.
type box struct {
	t      *testing.T
	h      *Kernel
	cfg    KernelConfig
	key    key.Key // the clerk key the holder signs plans under
	now    int64
	plans  int
	remote Remote
}

func newBox(t *testing.T, sock string) *box {
	t.Helper()
	return newBoxFor(t, sock, "web", key.Post)
}

// newBoxFor is a box whose clerk name, at sock, the owner granted verbs.
func newBoxFor(t *testing.T, sock, name string, verbs ...key.Verb) *box {
	t.Helper()
	b := &box{t: t, now: time.Now().UnixMilli(), remote: Remote{Socket: sock, UID: os.Getuid(), Timeout: 20 * time.Second}}
	b.cfg = KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: headPub, Sign: headPriv, Anchors: anchors,
		Clerks: map[string]Remote{name: b.remote},
	}
	b.open()
	t.Cleanup(func() { b.h.Close() })
	root := key.Issue(ownerPriv, key.Root{Clerk: name, Verbs: verbs, Serial: "r1"})
	ck, err := key.ClerkKey(root, ownerPriv, holderPub, b.now, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	b.key = ck
	// New power: the owner's passkey and the second hardware key co-sign it (D-146).
	cos := []key.Cosign{key.Approve(ownerPriv, kernel.BatchHash(root, ck)), key.Approve(sparePriv, kernel.BatchHash(root, ck))}
	if err := b.h.With(func(k *kernel.Kernel) error { return k.Issue(b.now-kernel.GrantHold, cos, root, ck) }); err != nil {
		t.Fatal(err)
	}
	return b
}

// open starts the kernel's process over the box's log, as a restart does.
func (b *box) open() {
	b.t.Helper()
	h, err := OpenKernel(b.cfg, b.now)
	if err != nil {
		b.t.Fatal(err)
	}
	b.h = h
}

// submit has the holder sign a one-step plan posting to to, and submits it.
func (b *box) submit(to string) string {
	b.t.Helper()
	return b.submitStep(kernel.PlanStep{Verb: key.Post, Clerk: "web", Args: map[string]string{"to": to, "msg": "hello"}, Content: "text", Labels: []string{"public"}})
}

// submitStep has the holder sign a plan of the one step ps, and submits it.
func (b *box) submitStep(ps kernel.PlanStep) string {
	b.t.Helper()
	b.plans++
	id := fmt.Sprintf("p%d", b.plans)
	p := kernel.SignPlan(kernel.Plan{ID: id, Key: b.key, Steps: []kernel.PlanStep{ps}}, holderPriv)
	if err := b.h.With(func(k *kernel.Kernel) error { return k.Submit(b.now, p) }); err != nil {
		b.t.Fatal(err)
	}
	return id
}

func (b *box) tick(at int64) {
	b.t.Helper()
	if err := b.h.Tick(at); err != nil {
		b.t.Fatal(err)
	}
}

// step is the state of plan id's one step.
func (b *box) step(id string) kernel.StepState {
	var st kernel.StepState
	b.h.With(func(k *kernel.Kernel) error {
		if p := k.State().Plans[id]; p != nil {
			st = p.Steps[0]
		}
		return nil
	})
	return st
}

// A step goes from the kernel's process to the clerk's process, which sends
// it to the provider with its own secret, and its result comes back to the
// log. A request the log does not have in flight is refused at the clerk's
// process, across the socket, and the provider sees nothing (CLK-2).
func TestCallRunsOnlyAStepTheLogHasInFlight(t *testing.T) {
	w := newWorld(t)
	b := newBox(t, w.sock)
	id := b.submit("alice")
	b.tick(b.now)
	if st := b.step(id); st.Phase != kernel.PDone {
		t.Fatalf("step %+v, want done", st)
	}
	if h := w.hits(t); len(h) != 1 || h[0] != "alice auth-ok" {
		t.Fatalf("provider saw %q, want one post to alice with the clerk's secret", h)
	}

	// The same signed request again, now that the log has it done: the
	// kernel's view says it is not in flight, and the clerk refuses it.
	var res kernel.Result
	b.h.With(func(k *kernel.Kernel) error {
		p := k.State().Plans[id].Plan
		res = remote{b.remote, b.cfg.Anchors}.Do(kernel.Request{Plan: p, Index: 0}, k.State())
		return nil
	})
	if res.Outcome != "failed" || res.Detail != clerk.RDispatch {
		t.Fatalf("replayed request: %+v, want failed %s", res, clerk.RDispatch)
	}
	// A plan the log never saw, signed by the holder, is refused the same way.
	ps := kernel.PlanStep{Verb: key.Post, Clerk: "web", Args: map[string]string{"to": "mallory", "msg": "x"}, Content: "text", Labels: []string{"public"}}
	forged := kernel.SignPlan(kernel.Plan{ID: "never", Key: b.key, Steps: []kernel.PlanStep{ps}}, holderPriv)
	b.h.With(func(k *kernel.Kernel) error {
		res = remote{b.remote, b.cfg.Anchors}.Do(kernel.Request{Plan: forged, Index: 0}, k.State())
		return nil
	})
	if res.Outcome != "failed" || res.Detail != clerk.RDispatch {
		t.Fatalf("unlogged plan: %+v, want failed %s", res, clerk.RDispatch)
	}
	if h := w.hits(t); len(h) != 1 {
		t.Fatalf("provider saw %q after refused requests, want the one post", h)
	}
}

// A clerk process killed while its request is at the provider comes back with
// no memory of it. The kernel logs the step unknown, probes it through the new
// clerk process, and parks it after MaxChecks without sending it again; a
// restart of the kernel's process on the way does not resend it either
// (KRN-8).
func TestKilledClerkDoesNotResend(t *testing.T) {
	w := newWorld(t)
	b := newBox(t, w.sock)
	id := b.submit("hang")
	done := make(chan struct{})
	go func() { defer close(done); b.h.Tick(b.now) }()
	waitFor(t, "the post to reach the provider", func() bool { return len(w.hits(t)) == 1 })
	w.kill(t)
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the kernel did not notice the clerk's death")
	}
	if st := b.step(id); st.Phase != kernel.PUnknown || st.Detail != DLost {
		t.Fatalf("step %+v, want unknown %s", st, DLost)
	}
	w.startClerk(t)
	at := b.now
	for i := 0; i < kernel.MaxChecks; i++ {
		at += kernel.ProbeEvery
		if i == kernel.MaxChecks/2 {
			b.h.Close()
			b.open()
		}
		b.tick(at)
	}
	if st := b.step(id); st.Phase != kernel.PParked {
		t.Fatalf("step %+v, want parked after %d checks", st, kernel.MaxChecks)
	}
	if h := w.hits(t); len(h) != 1 {
		t.Fatalf("provider saw %q, want the one send: a killed clerk must not resend", h)
	}
}

// The secret lives only in the clerk's process: after a step that used it,
// no byte of it is in the kernel's process memory or in the log (CLK-1). The
// provider's record shows the secret was really sent.
func TestNoSecretInKernelProcess(t *testing.T) {
	w := newWorld(t)
	b := newBox(t, w.sock)
	b.submit("bob")
	b.tick(b.now)
	if h := w.hits(t); len(h) != 1 || h[0] != "bob auth-ok" {
		t.Fatalf("provider saw %q, want the post with the clerk's secret", h)
	}
	hash := w.secretHash(t)
	raw, err := os.ReadFile(b.cfg.Log)
	if err != nil {
		t.Fatal(err)
	}
	var plain strings.Builder
	b.h.With(func(k *kernel.Kernel) error {
		for _, e := range k.Log().Entries() {
			j, _ := json.Marshal(e)
			plain.Write(j)
		}
		return nil
	})
	for what, s := range map[string]string{"log file": string(raw), "log entries": plain.String()} {
		if found, _ := findSecret(strings.NewReader(s), hash); found {
			t.Fatalf("the secret is in the %s", what)
		}
	}
	found, scanned, err := scanMemory(hash)
	if err != nil {
		t.Fatal(err)
	}
	if scanned == 0 {
		t.Fatal("scanned no memory")
	}
	if found {
		t.Fatal("the secret is in the kernel process's memory")
	}
	// The scan finds a secret that is there.
	here := []byte("canary-" + hex.EncodeToString(hash[:16]))
	h := sha256.Sum256(here)
	if found, _, _ := scanMemory(h[:]); !found {
		t.Fatal("the scan missed a secret held in this process")
	}
	runtime.KeepAlive(here)
}

// scanMemory searches every readable mapping of this process for the secret.
func scanMemory(hash []byte) (found bool, scanned int64, err error) {
	maps, err := os.Open("/proc/self/maps")
	if err != nil {
		return false, 0, err
	}
	defer maps.Close()
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return false, 0, err
	}
	defer mem.Close()
	const chunk, overlap = 1 << 20, 64
	buf := make([]byte, chunk+overlap)
	for s := bufio.NewScanner(maps); s.Scan(); {
		f := strings.Fields(s.Text())
		if len(f) < 2 || f[1][0] != 'r' || strings.HasSuffix(s.Text(), "[vvar]") {
			continue
		}
		lo, hi, _ := strings.Cut(f[0], "-")
		start, err1 := strconv.ParseUint(lo, 16, 64)
		end, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		for off := start; off < end; off += chunk {
			n := min(uint64(chunk+overlap), end-off)
			got, _ := mem.ReadAt(buf[:n], int64(off))
			if got <= 0 {
				break
			}
			scanned += int64(got)
			if ok, _ := findSecret(strings.NewReader(string(buf[:got])), hash); ok {
				return true, scanned, nil
			}
		}
	}
	return false, scanned, nil
}

// Each side admits only the other's uid. A kernel that finds another uid on
// the clerk's socket sends nothing, so the step is sent again later; a clerk socket that
// admits another uid answers the kernel nothing, so the step is unknown and
// the provider sees nothing.
func TestPeersAreCheckedByUID(t *testing.T) {
	w := newWorld(t)
	b := newBox(t, w.sock)
	b.cfg.Clerks["web"] = Remote{Socket: w.sock, UID: os.Getuid() + 1}
	b.h.Close()
	b.open()
	id := b.submit("carol")
	b.tick(b.now)
	if st := b.step(id); st.Phase != kernel.PUnsent || st.Detail != DUnreachable {
		t.Fatalf("step %+v, want unsent %s", st, DUnreachable)
	}

	// A clerk socket that admits some other uid, not the kernel's.
	sock := filepath.Join(shortDir(t), "other.sock")
	ln, err := ListenClerk(sock, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	calls := 0
	go ServeClerk(ln, fakeClerk{do: func() kernel.Result { calls++; return kernel.Result{Outcome: "ok"} }}, nil)
	var res kernel.Result
	b.h.With(func(k *kernel.Kernel) error {
		res = remote{Remote{Socket: sock, UID: os.Getuid(), Timeout: 2 * time.Second}, nil}.Do(kernel.Request{Plan: k.State().Plans[id].Plan}, k.State())
		return nil
	})
	if res.Outcome != "unknown" || calls != 0 {
		t.Fatalf("got %+v with %d calls, want unknown and no call", res, calls)
	}
	if h := w.hits(t); len(h) != 0 {
		t.Fatalf("provider saw %q, want nothing", h)
	}
}

// fakeClerk answers every call with do's result.
type fakeClerk struct {
	do    func() kernel.Result
	probe string
}

func (f fakeClerk) Do(kernel.Request, kernel.View) kernel.Result { return f.do() }
func (f fakeClerk) Probe(kernel.Request, kernel.View) string     { return f.probe }

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
		r := remote{Remote{Socket: sock, UID: os.Getuid()}, nil}
		v := kernel.NewState(anchors)
		got := r.Do(kernel.Request{}, v)
		if got.Outcome != c.want || got.Detail != c.detail {
			t.Errorf("clerk answered %+v: kernel took %+v, want %s %q", c.res, got, c.want, c.detail)
		}
		if p := r.Probe(kernel.Request{}, v); p != c.wantPr {
			t.Errorf("clerk probed %q: kernel took %q, want %q", c.probe, p, c.wantPr)
		}
	}
	// No clerk listening: nothing was sent, so the step is sent again later,
	// and a probe made no check.
	r := remote{Remote{Socket: filepath.Join(shortDir(t), "none.sock"), UID: os.Getuid()}, nil}
	if got := r.Do(kernel.Request{}, kernel.NewState(nil)); got.Outcome != kernel.OUnsent || got.Detail != DUnreachable {
		t.Fatalf("no clerk: %+v, want unsent %s", got, DUnreachable)
	}
	if got := r.Probe(kernel.Request{}, kernel.NewState(nil)); got != kernel.OUnreached {
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
		s := view(k.State(), anchors, r, b.now)
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
	a.By = key.Approve(ownerPriv, kernel.TaskHash("t1", a.Site, a.First))
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
		s := view(k.State(), anchors, kernel.Request{Plan: in}, b.now)
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
		if s := view(k.State(), anchors, kernel.Request{Plan: out}, b.now); s.Served != nil {
			t.Fatalf("a chain with no task carried one: %+v", s.Served)
		}
		if err := k.EndTask(b.now, "t1"); err != nil {
			t.Fatal(err)
		}
		if s := view(k.State(), anchors, kernel.Request{Plan: in}, b.now); s.Served != nil {
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
func (hung) Probe(kernel.Request, kernel.View) string { return "notdone" }

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
func (*first) Probe(kernel.Request, kernel.View) string { return "notdone" }

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
