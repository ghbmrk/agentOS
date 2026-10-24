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
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// box is the test process as the kernel's process, with one clerk at
// sock.
type box struct {
	t      *testing.T
	h      *proc.Kernel
	cfg    proc.KernelConfig
	key    key.Key // the clerk key the holder signs plans under
	now    int64
	plans  int
	remote proc.Remote
}

func newBox(t *testing.T, sock string) *box {
	t.Helper()
	return newBoxFor(t, sock, "web", key.Post)
}

// newBoxFor is a box whose clerk name, at sock, the owner granted verbs.
func newBoxFor(t *testing.T, sock, name string, verbs ...key.Verb) *box {
	t.Helper()
	return newBoxAt(t, sock, name, time.Now().UnixMilli(), verbs...)
}

// newBoxAt is newBoxFor with its clock at now, so two boxes made at one now
// hold the same keys.
func newBoxAt(t *testing.T, sock, name string, now int64, verbs ...key.Verb) *box {
	t.Helper()
	b := &box{t: t, now: now, remote: proc.Remote{Socket: sock, UID: os.Getuid(), Timeout: 20 * time.Second}}
	b.cfg = proc.KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: headPub, Sign: headPriv, Anchors: anchors,
		Clerks: map[string]proc.Remote{name: b.remote},
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
	h, err := proc.OpenKernel(b.cfg, b.now)
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
		res = b.remote.Clerk(b.cfg.Anchors).Do(kernel.Request{Plan: p, Index: 0}, k.State())
		return nil
	})
	if res.Outcome != "failed" || res.Detail != clerk.RDispatch {
		t.Fatalf("replayed request: %+v, want failed %s", res, clerk.RDispatch)
	}
	// A plan the log never saw, signed by the holder, is refused the same way.
	ps := kernel.PlanStep{Verb: key.Post, Clerk: "web", Args: map[string]string{"to": "mallory", "msg": "x"}, Content: "text", Labels: []string{"public"}}
	forged := kernel.SignPlan(kernel.Plan{ID: "never", Key: b.key, Steps: []kernel.PlanStep{ps}}, holderPriv)
	b.h.With(func(k *kernel.Kernel) error {
		res = b.remote.Clerk(b.cfg.Anchors).Do(kernel.Request{Plan: forged, Index: 0}, k.State())
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
	if st := b.step(id); st.Phase != kernel.PUnknown || st.Detail != proc.DLost {
		t.Fatalf("step %+v, want unknown %s", st, proc.DLost)
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
	b.cfg.Clerks["web"] = proc.Remote{Socket: w.sock, UID: os.Getuid() + 1}
	b.h.Close()
	b.open()
	id := b.submit("carol")
	b.tick(b.now)
	if st := b.step(id); st.Phase != kernel.PUnsent || st.Detail != proc.DUnreachable {
		t.Fatalf("step %+v, want unsent %s", st, proc.DUnreachable)
	}

	// A clerk socket that admits some other uid, not the kernel's.
	sock := filepath.Join(shortDir(t), "other.sock")
	ln, err := proc.ListenClerk(sock, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	calls := 0
	go proc.ServeClerk(ln, fakeClerk{do: func() kernel.Result { calls++; return kernel.Result{Outcome: "ok"} }}, nil)
	var res kernel.Result
	b.h.With(func(k *kernel.Kernel) error {
		res = proc.Remote{Socket: sock, UID: os.Getuid(), Timeout: 2 * time.Second}.Clerk(nil).Do(kernel.Request{Plan: k.State().Plans[id].Plan}, k.State())
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
func (f fakeClerk) Probe(kernel.Request, kernel.View) kernel.Result {
	return kernel.Result{Outcome: f.probe}
}

// The clerks' own errors cross a socket as themselves, though the wire's
// package cannot name them: clerk/run adds them at init (#2892).
func TestClerkErrorsCrossASocketAsThemselves(t *testing.T) {
	for _, want := range []error{ErrModelCall, ErrNoMailAccount, ErrMailAddress, ErrMailServer, ErrMailUser,
		ErrWeakMailPassword, ErrBadGrant, ErrNoReconnect, fmt.Errorf("stage: %w", ErrBadGrant)} {
		sock := filepath.Join(shortDir(t), "e.sock")
		ln, err := proc.ListenKernel(sock, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		go proc.ServeConns(ln, 1, func(c net.Conn) {
			proc.ServeOne(c, func(string, json.RawMessage) (json.RawMessage, error) { return nil, want })
		})
		got := proc.Conn{Socket: sock, UID: os.Getuid(), Timeout: 5 * time.Second}.Call("x", nil, nil)
		ln.Close()
		if got == nil || got.Error() != want.Error() || !errors.Is(got, errors.Unwrap(want)) && got != want {
			t.Fatalf("%v crossed as %#v", want, got)
		}
	}
}
