package run

// REQ: CLK-1, CLK-7, LOG-7, KRN-7

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// serveSide serves side of b's kernel on a fresh socket that admits uid, and
// returns a Conn to it.
func serveSide(t *testing.T, b *box, side Side, uid int) Conn {
	t.Helper()
	sock := filepath.Join(shortDir(t), side.name+".sock")
	ln, err := ListenKernel(sock, uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeKernel(ln, b.h, side, func() int64 { return time.Now().UnixMilli() })
	return Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}
}

// entries is how many entries b's log holds.
func (b *box) entries() int {
	n := 0
	b.h.With(func(k *kernel.Kernel) error { n = len(k.Log().Entries()); return nil })
	return n
}

// The owner seam crosses the owner socket as the frozen interface lists it
// (docs/LANES.md): each action lands in the log as the direct call does, a
// refusal keeps its code, and each read answers as State() does.
func TestOwnerSocketServesTheSeam(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	o := Owner{serveSide(t, b, OwnerSide, os.Getuid())}

	p := kernel.SignPlan(kernel.Plan{ID: "o1", Key: b.key, Steps: []kernel.PlanStep{{Verb: key.Post, Clerk: "web",
		Args: map[string]string{"to": "alice", "msg": "hi"}, Content: "text", Labels: []string{"public"}}}}, holderPriv)
	if err := o.Submit(p); err != nil {
		t.Fatal(err)
	}
	if err := o.Submit(p); !errors.Is(err, kernel.ErrDuplicatePlan) {
		t.Fatalf("a second submit: %v, want %v", err, kernel.ErrDuplicatePlan)
	}
	var rf *key.Refusal
	if err := o.Extend(b.key, "o1"); !errors.As(err, &rf) || rf.Code != kernel.CNotHeld {
		t.Fatalf("extend of an unheld plan: %v, want refusal %s", err, kernel.CNotHeld)
	}
	if err := o.Retry("o1", 0); !errors.Is(err, kernel.ErrNotParked) {
		t.Fatalf("retry of an unparked step: %v", err)
	}
	ver, err := kernel.VerifyPlan(p, anchors)
	if err != nil {
		t.Fatal(err)
	}
	id := ver.ID()
	for _, a := range []func() error{
		func() error { return o.Pause(id) }, func() error { return o.Stop() }, func() error { return o.Reserve("codex-5h", 200) },
	} {
		if err := a(); err != nil {
			t.Fatal(err)
		}
	}
	b.h.With(func(k *kernel.Kernel) error {
		s := k.State()
		if s.Plans["o1"] == nil || !s.Changes.Paused[id] || !s.Changes.Stopped || s.Pools["codex-5h"].Reserve != 200 {
			t.Fatalf("the log after the owner's calls: plan %v, paused %v, stopped %v, pools %v",
				s.Plans["o1"] != nil, s.Changes.Paused[id], s.Changes.Stopped, s.Pools)
		}
		return nil
	})
	// What a lost answer leaves the owner side to read back.
	if c, err := o.Changes(); err != nil || !c.Paused[id] || !c.Stopped {
		t.Fatalf("changes over the socket: %+v, %v", c, err)
	}
	if status, phases, ok, err := o.Plan("o1"); err != nil || !ok || status != kernel.SActive || len(phases) != 1 {
		t.Fatalf("plan over the socket: %q %v %v %v", status, phases, ok, err)
	}
	if _, _, ok, err := o.Plan("none"); ok || err != nil {
		t.Fatalf("a plan never submitted reads as found (%v)", err)
	}
	if from, ok, err := o.Granted(ver.Root()); err != nil || !ok || from == 0 {
		t.Fatalf("the root's grant over the socket: %d %v %v", from, ok, err)
	}
	for _, a := range []func() error{func() error { return o.Unpause(id) }, func() error { return o.Resume() }, func() error { return o.Cancel("o1") }} {
		if err := a(); err != nil {
			t.Fatal(err)
		}
	}

	var (
		status []kernel.Unsettled
		lines  int
		held   map[string]kernel.SpendHold
		pools  map[string]kernel.Pool
	)
	b.h.With(func(k *kernel.Kernel) error {
		s := k.State()
		status, lines, held, pools = s.Status(), s.LineChanges(), s.SpendHeld, s.Pools
		if s.Changes.Paused[id] || s.Changes.Stopped || s.Plans["o1"].Status != kernel.SCancelled {
			t.Fatal("unpause, resume or cancel did not land")
		}
		return nil
	})
	gs, err := o.Status()
	same(t, "status", gs, status, err)
	gl, err := o.LineChanges()
	same(t, "line changes", gl, lines, err)
	gh, err := o.SpendHeld()
	same(t, "spend held", len(gh), len(held), err)
	gp, err := o.Pools()
	same(t, "pools", gp, pools, err)
	if _, ok, err := o.Task("none"); ok || err != nil {
		t.Fatalf("a task never opened reads live (%v)", err)
	}
}

func same(t *testing.T, what string, got, want any, err error) {
	t.Helper()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("%s over the socket: %+v (%v), the log says %+v", what, got, err, want)
	}
}

// Each socket serves its side's calls and no other: the model clerk cannot
// STOP, issue or read the owner's state, and the owner side cannot meter. A
// call outside the table logs nothing (CLK-7).
func TestEachSocketServesOnlyItsSide(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	owner := serveSide(t, b, OwnerSide, os.Getuid())
	meter := serveSide(t, b, MeterSide, os.Getuid())
	for name := range OwnerSide.ops {
		if _, ok := MeterSide.ops[name]; ok {
			t.Fatalf("both sides serve %s", name)
		}
	}
	before := b.entries()
	for _, op := range []string{"stop", "issue", "resume", "status", "submit"} {
		if err := meter.call(op, nil, nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("%s on the meter socket: %v, want refused", op, err)
		}
	}
	for _, op := range []string{"meter", "hold", "readpool", "admitspend"} {
		if err := owner.call(op, spendArgs{Plan: "p1", Amount: 1}, nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("%s on the owner socket: %v, want refused", op, err)
		}
	}
	if n := b.entries(); n != before {
		t.Fatalf("refused calls logged %d entries", n-before)
	}
}

// A kernel socket admits only its side's uid, and a caller sends nothing to
// a socket another uid holds (CLK-1).
func TestKernelSocketsCheckPeerUID(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	before := b.entries()
	other := Owner{serveSide(t, b, OwnerSide, os.Getuid()+1)}
	if err := other.Stop(); err == nil {
		t.Fatal("a socket for another uid took the caller's STOP")
	}
	mine := serveSide(t, b, OwnerSide, os.Getuid())
	mine.UID = os.Getuid() + 1
	if err := (Owner{mine}).Stop(); err == nil {
		t.Fatal("a caller sent STOP to a socket another uid holds")
	}
	if n := b.entries(); n != before {
		t.Fatalf("calls refused by uid logged %d entries", n-before)
	}
}

// fakeProvider answers every model call with 400 bytes, or err, and counts
// them.
type fakeProvider struct {
	calls int
	err   error
}

func (f *fakeProvider) Call(route, prompt string, maxOut int64) (string, model.Usage, error) {
	f.calls++
	return strings.Repeat("x", 400), model.Usage{}, f.err
}

// The model clerk runs apart from the kernel and meters through the meter
// socket: a call is admitted against the plan's cap, its use lands in the
// log on the kernel's clock whatever the clerk's says, and a call past the
// cap is refused with the cap's code, which holds the plan, without reaching
// the provider (LOG-7, #2572).
func TestModelClerkMetersThroughTheKernelSocket(t *testing.T) {
	b := newBoxFor(t, filepath.Join(shortDir(t), "web.sock"), "model", key.Read)
	root := key.Issue(ownerPriv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m"})
	ky, err := key.ClerkKey(root, ownerPriv, holderPub, b.now, 1<<40, key.LimitSpendTask(100))
	if err != nil {
		t.Fatal(err)
	}
	cos := []key.Cosign{key.Approve(ownerPriv, kernel.BatchHash(root, ky)), key.Approve(sparePriv, kernel.BatchHash(root, ky))}
	p := kernel.SignPlan(kernel.Plan{ID: "t", Key: ky, Steps: []kernel.PlanStep{{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}}}, holderPriv)
	if err := b.h.With(func(k *kernel.Kernel) error {
		if err := k.Issue(b.now-kernel.GrantHold, cos, root, ky); err != nil {
			return err
		}
		return k.Submit(b.now, p)
	}); err != nil {
		t.Fatal(err)
	}

	pr := &fakeProvider{}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1_000_000, OutPerM: 1_000_000}}, Provider: pr,
		Ledger: Meter{serveSide(t, b, MeterSide, os.Getuid())}}
	sock := filepath.Join(shortDir(t), "model.sock")
	ln, err := ListenModel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeModel(ln, c, func() int64 { return 0 }) // a clerk clock far behind
	m := Model{Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}}

	start := time.Now().UnixMilli()
	if reply, err := m.Call("t", "api", "hi", 50); err != nil || len(reply) != 400 {
		t.Fatalf("a call within the cap: %d bytes, %v", len(reply), err)
	}
	var used kernel.Entry
	b.h.With(func(k *kernel.Kernel) error {
		for _, e := range k.Log().Entries() {
			if e.Type == kernel.TModelUsed {
				used = e
			}
		}
		return nil
	})
	if used.Type == "" || used.At < start || !strings.Contains(string(used.Body), `"api"`) {
		t.Fatalf("the metered use: %+v, want a model.used entry at the kernel's time (>= %d)", used, start)
	}

	_, err = m.Call("t", "api", "hi", 1000)
	var rf *key.Refusal
	if !errors.As(err, &rf) || rf.Code != key.RSpendTask {
		t.Fatalf("a call past the cap: %v, want refusal %s", err, key.RSpendTask)
	}
	if pr.calls != 1 {
		t.Fatalf("the provider saw %d calls, want 1", pr.calls)
	}
	b.h.With(func(k *kernel.Kernel) error {
		if _, ok := k.State().SpendHeld["t"]; !ok {
			t.Fatal("the plan past its cap is not held")
		}
		return nil
	})
}

// A meter socket that cannot be reached admits nothing: the clerk refuses
// the call as the broken log does, and the provider is never called.
func TestModelClerkWithoutTheKernelCallsNothing(t *testing.T) {
	pr := &fakeProvider{}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1, OutPerM: 1}}, Provider: pr,
		Ledger: Meter{Conn{Socket: filepath.Join(shortDir(t), "none.sock"), UID: os.Getuid()}}}
	_, err := c.Call(0, "t", "api", "hi", 10)
	var rf *key.Refusal
	if !errors.As(err, &rf) || rf.Code != kernel.CBroken || pr.calls != 0 {
		t.Fatalf("no kernel: %v with %d provider calls, want refusal %s and none", err, pr.calls, kernel.CBroken)
	}
}

// A call whose answer is cut off is ErrLost, never a success or a refusal
// the caller might act on.
func TestAKernelCallCutOffIsLost(t *testing.T) {
	sock := filepath.Join(shortDir(t), "cut.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Read(make([]byte, 1))
			c.Close()
		}
	}()
	err = Owner{Conn{Socket: sock, UID: os.Getuid(), Timeout: 5 * time.Second}}.Stop()
	if !errors.Is(err, ErrLost) {
		t.Fatalf("a cut-off STOP: %v, want %v", err, ErrLost)
	}
	err = Owner{Conn{Socket: filepath.Join(shortDir(t), "none.sock"), UID: os.Getuid()}}.Stop()
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("a STOP to no socket: %v, want %v", err, ErrUnreachable)
	}
}

// A provider's own error, which can carry its URL or a key, never leaves the
// model clerk's process: the planner sees ErrModelCall, while a refusal
// still crosses with its code (CLK-1, #2717 Security 1).
func TestAProviderErrorStaysInTheModelClerk(t *testing.T) {
	const canary = "CANARY-SECRET-2717"
	pr := &fakeProvider{err: errors.New("Post https://api.example.test/v1?key=" + canary + ": 401")}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1, OutPerM: 1}}, Provider: pr, Ledger: admitAll{}}
	sock := filepath.Join(shortDir(t), "model.sock")
	ln, err := ListenModel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeModel(ln, c, func() int64 { return 0 })
	m := Model{Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}}
	_, err = m.Call("t", "api", "hi", 10)
	if !errors.Is(err, ErrModelCall) || strings.Contains(err.Error(), canary) || pr.calls != 1 {
		t.Fatalf("a failed provider call: %v (%d calls), want %v without the canary", err, pr.calls, ErrModelCall)
	}
}

// admitAll is a ledger that admits and records everything.
type admitAll struct{}

func (admitAll) AdmitSpend(_ int64, plan string, _ int64) (kernel.Admitted, *key.Refusal) {
	return kernel.Admitted{Plan: plan}, nil
}
func (admitAll) Meter(int64, kernel.Admitted, string, int64, string) error { return nil }
func (admitAll) Hold(int64, string, *key.Refusal) error                    { return nil }
func (admitAll) AdmitPool(int64, string) *key.Refusal                      { return nil }
func (admitAll) ReadPool(int64, string, int64, int64) error                { return nil }

// failingOnce is a listener whose first accept fails as a process out of
// descriptors does.
type failingOnce struct {
	net.Listener
	failed bool
}

func (l *failingOnce) Accept() (net.Conn, error) {
	if !l.failed {
		l.failed = true
		return nil, &net.OpError{Op: "accept", Net: "unix", Err: syscall.EMFILE}
	}
	return l.Listener.Accept()
}

// An accept that fails, as when a flood has used up the process's
// descriptors, does not end the socket: the owner's STOP lands after it
// (KRN-7, #2717 Security 2).
func TestAKernelSocketOutlivesAFailedAccept(t *testing.T) {
	b := newBox(t, filepath.Join(shortDir(t), "web.sock"))
	sock := filepath.Join(shortDir(t), "owner.sock")
	ln, err := ListenKernel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go ServeKernel(&failingOnce{Listener: ln}, b.h, OwnerSide, func() int64 { return time.Now().UnixMilli() })
	if err := (Owner{Conn{Socket: sock, UID: os.Getuid(), Timeout: 10 * time.Second}}).Stop(); err != nil {
		t.Fatalf("STOP after a failed accept: %v", err)
	}
}

// A socket serves at most maxConns calls at once; the rest wait in the
// backlog and are served as slots free, so a side that floods its socket
// holds a bounded number of the process's descriptors.
func TestASocketServesABoundedNumberAtOnce(t *testing.T) {
	sock := filepath.Join(shortDir(t), "cap.sock")
	ln, err := ListenKernel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	now, peak := 0, 0
	release := make(chan struct{})
	go serveConns(ln, maxConns, func(c net.Conn) {
		defer c.Close()
		mu.Lock()
		now++
		peak = max(peak, now)
		mu.Unlock()
		<-release
		mu.Lock()
		now--
		mu.Unlock()
	})
	var conns []net.Conn
	for range maxConns + 8 {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	got := peak
	mu.Unlock()
	close(release)
	for _, c := range conns {
		c.Close()
	}
	if got != maxConns {
		t.Fatalf("%d calls served at once, want %d", got, maxConns)
	}
}

// No error crosses a socket as success: a typed-nil refusal or an error with
// no text still reads as an error (#2717 Security 3).
func TestNoErrorCrossesAsSuccess(t *testing.T) {
	for _, bad := range []error{(*key.Refusal)(nil), &key.Refusal{}, errors.New("")} {
		sock := filepath.Join(shortDir(t), "e.sock")
		ln, err := ListenKernel(sock, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		go serveConns(ln, 1, func(c net.Conn) {
			serveOne(c, func(string, json.RawMessage) (json.RawMessage, error) { return nil, bad })
		})
		if err := (Conn{Socket: sock, UID: os.Getuid(), Timeout: 5 * time.Second}).call("x", nil, nil); err == nil {
			t.Fatalf("%#v crossed as success", bad)
		}
		ln.Close()
	}
}

// twin is a call made the same way on two kernels with the same log: direct
// on one, and through the caller's typed client and its side's socket on the
// other.
type twin struct {
	name string
	op   string // the table row the call reaches
	sock func(Owner, Meter) (any, error)
	call func(*kernel.Kernel) (any, error) // the direct call
	read func(any) bool                    // for a read: whether its result is not empty
}

// Every call on both tables does through its client and socket what the
// direct call does (docs/LANES.md): the same answer, the same entries in the
// log, and, for a read, the same result, each read made on a state where it
// is not empty, and each action on a state where it succeeds.
func TestEverySocketCallIsTheDirectCall(t *testing.T) {
	var clk atomic.Int64
	clk.Store(time.Now().UnixMilli())
	at := clk.Load()
	// A clerk that never answers, so a step is unknown and, after
	// MaxChecks probes, parked for RETRY.
	clerkSock := serveFake(t, fakeClerk{do: func() kernel.Result { return kernel.Result{Outcome: "unknown"} }, probe: "unknown"})
	direct := newBoxAt(t, clerkSock, "web", at, key.Post)
	sock := newBoxAt(t, clerkSock, "web", at, key.Post)
	conns := map[string]Conn{}
	for _, side := range []Side{OwnerSide, MeterSide} {
		path := filepath.Join(shortDir(t), side.name+".sock")
		ln, err := ListenKernel(path, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go ServeKernel(ln, sock.h, side, clk.Load)
		conns[side.name] = Conn{Socket: path, UID: os.Getuid(), Timeout: 10 * time.Second}
	}
	o, m := Owner{conns["owner"]}, Meter{conns["meter"]}

	// A plan under a key capped at 100 a task, for the metering calls, and
	// a second root whose capped key can release it once held.
	issue := func(serial string, cv ...key.Caveat) (key.Key, key.Key, []key.Cosign) {
		root := key.Issue(ownerPriv, key.Root{Clerk: "web", Verbs: []key.Verb{key.Post}, Serial: serial})
		ck, err := key.ClerkKey(root, ownerPriv, holderPub, at, 1<<40, cv...)
		if err != nil {
			t.Fatal(err)
		}
		return root, ck, []key.Cosign{key.Approve(ownerPriv, kernel.BatchHash(root, ck)), key.Approve(sparePriv, kernel.BatchHash(root, ck))}
	}
	root, capped, cos := issue("m", key.LimitSpendTask(100))
	eroot, ext, ecos := issue("e", key.LimitSpendTask(500))
	other := key.Issue(ownerPriv, key.Root{Clerk: "web", Verbs: []key.Verb{key.Post}, Serial: "x"})
	ocos := []key.Cosign{key.Approve(ownerPriv, kernel.BatchHash(other)), key.Approve(sparePriv, kernel.BatchHash(other))}
	step := kernel.PlanStep{Verb: key.Post, Clerk: "web", Args: map[string]string{"to": "alice", "msg": "hi"}, Content: "text", Labels: []string{"public"}}
	pm := kernel.SignPlan(kernel.Plan{ID: "m", Key: capped, Steps: []kernel.PlanStep{step}}, holderPriv)
	p1 := kernel.SignPlan(kernel.Plan{ID: "p1", Key: direct.key, Steps: []kernel.PlanStep{step}}, holderPriv)
	ver, err := kernel.VerifyPlan(p1, anchors)
	if err != nil {
		t.Fatal(err)
	}
	phone, phonePriv := gen(8)
	spend := &key.Refusal{Code: key.RSpendTask, Detail: "used up"}
	approval := kernel.TaskApproval{Site: "shop.test", First: "r", By: key.Approve(phonePriv, kernel.TaskHash("t1", 0, "shop.test", "r"))}
	for _, b := range []*box{direct, sock} {
		if err := b.h.With(func(k *kernel.Kernel) error {
			if err := k.Issue(at-kernel.GrantHold, cos, root, capped); err != nil {
				return err
			}
			if err := k.Issue(at-kernel.GrantHold, ecos, eroot, ext); err != nil {
				return err
			}
			return k.OpenTask(at, "t1")
		}); err != nil {
			t.Fatal(err)
		}
	}
	// park runs both kernels on until plan p1's step is parked.
	park := func() {
		for range 4 * kernel.MaxChecks {
			now := clk.Add(kernel.ProbeEvery)
			direct.tick(now)
			sock.tick(now)
		}
		if st := direct.step("p1"); st.Phase != kernel.PParked {
			t.Fatalf("p1 is %s, want parked", st.Phase)
		}
	}
	nonEmpty := func(v any) bool { b, _ := json.Marshal(v); return len(b) > 4 }
	now := func() int64 { return clk.Load() }
	plan := func(k *kernel.Kernel, id string) planRead {
		p := k.State().Plans[id]
		r := planRead{Status: p.Status}
		for _, st := range p.Steps {
			r.Phases = append(r.Phases, st.Phase)
		}
		return r
	}

	var admitted kernel.Admitted // the socket's admission, settled by both kernels' meter
	cases := []twin{
		{name: "submit", op: "submit", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Submit(p1) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Submit(now(), p1) }},
		{name: "issue", op: "issue", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Issue(ocos, other) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Issue(now(), ocos, other) }},
		{name: "submit capped", op: "submit", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Submit(pm) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Submit(now(), pm) }},
		{name: "enroll", op: "enroll", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Enroll(key.Enroll(ownerPriv, phone)) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Enroll(now(), key.Enroll(ownerPriv, phone)) }},
		{name: "approvetask", op: "approvetask", sock: func(o Owner, _ Meter) (any, error) { return nil, o.ApproveTask("t1", approval) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.ApproveTask(now(), "t1", approval) }},
		{name: "task", op: "task", read: func(v any) bool { return len(v.(kernel.Task).Approvals) > 0 },
			sock: func(o Owner, _ Meter) (any, error) {
				tk, ok, err := o.Task("t1")
				if !ok {
					return nil, err
				}
				return tk, err
			},
			call: func(k *kernel.Kernel) (any, error) {
				tk, ok := k.State().Task("t1", now())
				if !ok {
					return nil, nil
				}
				return tk, nil
			}},
		{name: "setline", op: "setline", sock: func(o Owner, _ Meter) (any, error) { return nil, o.SetLine(100) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.SetLine(now(), 100) }},
		{name: "reserve", op: "reserve", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Reserve("full", kernel.PoolFull) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Reserve(now(), "full", kernel.PoolFull) }},
		{name: "admit", op: "admitspend", read: func(v any) bool { return v.(kernel.Admitted).Seq > 0 },
			sock: func(_ Owner, m Meter) (any, error) {
				a, r := m.AdmitSpend(0, "m", 37)
				admitted = a
				return a, refusal(r)
			},
			call: func(k *kernel.Kernel) (any, error) { a, r := k.AdmitSpend(now(), "m", 37); return a, refusal(r) }},
		{name: "meter", op: "meter", sock: func(_ Owner, m Meter) (any, error) { return nil, m.Meter(0, admitted, "api", 37, "provider") }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Meter(now(), admitted, "api", 37, "provider") }},
		{name: "meter again", op: "meter", sock: func(_ Owner, m Meter) (any, error) { return nil, m.Meter(0, admitted, "api", 37, "provider") }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Meter(now(), admitted, "api", 37, "provider") }},
		{name: "admitspend", op: "admitspend", sock: func(_ Owner, m Meter) (any, error) { a, r := m.AdmitSpend(0, "m", 1000); return a, refusal(r) }, call: func(k *kernel.Kernel) (any, error) { a, r := k.AdmitSpend(now(), "m", 1000); return a, refusal(r) }},
		{name: "admitpool", op: "admitpool", sock: func(_ Owner, m Meter) (any, error) { return nil, refusal(m.AdmitPool(0, "full")) }, call: func(k *kernel.Kernel) (any, error) { return nil, refusal(k.AdmitPool(now(), "full")) }},
		{name: "readpool", op: "readpool", sock: func(_ Owner, m Meter) (any, error) { return nil, m.ReadPool(0, "codex", 300, at+1000) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.ReadPool(now(), "codex", 300, at+1000) }},
		{name: "hold", op: "hold", sock: func(_ Owner, m Meter) (any, error) { return nil, m.Hold(0, "m", spend) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Hold(now(), "m", spend) }},
		{name: "spendheld", op: "spendheld", read: nonEmpty, sock: func(o Owner, _ Meter) (any, error) { return o.SpendHeld() }, call: func(k *kernel.Kernel) (any, error) { return k.State().SpendHeld, nil }},
		{name: "extend", op: "extend", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Extend(ext, "m") }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Extend(now(), ext, "m") }},
		{name: "pause", op: "pause", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Pause(ver.ID()) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Pause(now(), ver.ID()) }},
		{name: "unpause", op: "unpause", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Unpause(ver.ID()) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Unpause(now(), ver.ID()) }},
		{name: "stop", op: "stop", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Stop() }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Stop(now()) }},
		{name: "changes", op: "changes", read: nonEmpty, sock: func(o Owner, _ Meter) (any, error) { return o.Changes() }, call: func(k *kernel.Kernel) (any, error) { return *k.State().ChangesView(), nil }},
		{name: "resume", op: "resume", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Resume() }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Resume(now()) }},
		{name: "status", op: "status", read: nonEmpty, sock: func(o Owner, _ Meter) (any, error) { return o.Status() }, call: func(k *kernel.Kernel) (any, error) { return k.State().Status(), nil }},
		{name: "retry", op: "retry", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Retry("p1", 0) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Retry(now(), "p1", 0) }},
		{name: "linechanges", op: "linechanges", read: func(v any) bool { return v.(int) > 0 }, sock: func(o Owner, _ Meter) (any, error) { return o.LineChanges() }, call: func(k *kernel.Kernel) (any, error) { return k.State().LineChanges(), nil }},
		{name: "pools", op: "pools", read: nonEmpty, sock: func(o Owner, _ Meter) (any, error) { return o.Pools() }, call: func(k *kernel.Kernel) (any, error) { return k.State().Pools, nil }},
		{name: "enrollments", op: "enrollments", read: func(v any) bool { return len(v.(enrolled).Enrolled) > 0 },
			sock: func(o Owner, _ Meter) (any, error) {
				es, un, err := o.Enrollments()
				return enrolled{es, un}, err
			},
			call: func(k *kernel.Kernel) (any, error) {
				es, un := k.State().Enrollments()
				return enrolled{es, un}, nil
			}},
		{name: "plan", op: "plan", read: func(v any) bool { return v.(planRead).Status != "" },
			sock: func(o Owner, _ Meter) (any, error) {
				status, phases, _, err := o.Plan("p1")
				return planRead{status, phases}, err
			},
			call: func(k *kernel.Kernel) (any, error) { return plan(k, "p1"), nil }},
		{name: "granted", op: "granted", read: func(v any) bool { return v.(grantRead).OK },
			sock: func(o Owner, _ Meter) (any, error) {
				from, ok, err := o.Granted(ver.Root())
				return grantRead{from, ok}, err
			},
			call: func(k *kernel.Kernel) (any, error) {
				from, ok := k.State().Granted(ver.Root())
				return grantRead{from, ok}, nil
			}},
		{name: "undo", op: "undo", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Undo("p1", 0) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Undo(now(), "p1", 0) }},
		{name: "unenroll", op: "unenroll", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Unenroll(phone) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Unenroll(now(), phone) }},
		{name: "revoke", op: "revoke", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Revoke(ver.ID()) }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Revoke(now(), ver.ID()) }},
		{name: "cancel", op: "cancel", sock: func(o Owner, _ Meter) (any, error) { return nil, o.Cancel("p1") }, call: func(k *kernel.Kernel) (any, error) { return nil, k.Cancel(now(), "p1") }},
	}
	// Refused on both kernels by design: the admission past the cap and the
	// pool at its reserve. Every other action succeeds.
	refused := map[string]bool{"admitspend": true, "admitpool": true, "meter again": true}
	served := map[string]bool{}
	for _, c := range cases {
		if c.name == "status" {
			park()
		}
		served[c.op] = true
		before := sock.entries()
		var want any
		var wantErr error
		direct.h.With(func(k *kernel.Kernel) error { want, wantErr = c.call(k); return nil })
		got, gotErr := c.sock(o, m)
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || (wantErr != nil) != refused[c.name] {
			t.Fatalf("%s: the socket answers %v, the direct call %v", c.name, gotErr, wantErr)
		}
		if c.read != nil {
			wb, _ := json.Marshal(want)
			gb, _ := json.Marshal(got)
			if string(wb) != string(gb) || want == nil || !c.read(want) {
				t.Fatalf("%s: the socket reads %s, the direct read %s (want a read that is not empty)", c.name, gb, wb)
			}
		}
		if got, want := logged(sock, before), logged(direct, before); got != want {
			t.Fatalf("%s: the socket logged %s, the direct call %s", c.name, got, want)
		}
	}
	for _, side := range []Side{OwnerSide, MeterSide} {
		for op := range side.ops {
			if !served[op] {
				t.Errorf("no case for %s", op)
			}
		}
	}
}

// logged is the type and body of each entry b's log holds from index from.
func logged(b *box, from int) string {
	var out []string
	b.h.With(func(k *kernel.Kernel) error {
		for _, e := range k.Log().Entries()[from:] {
			out = append(out, e.Type+" "+string(e.Body))
		}
		return nil
	})
	return strings.Join(out, "\n")
}
