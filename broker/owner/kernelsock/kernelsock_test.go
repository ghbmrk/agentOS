//go:build linux

package kernelsock

// REQ: CLK-1, KRN-7, KEY-4, REC-3

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// testOwnerUID stands in for agentos-owner: a uid no test process runs as.
const testOwnerUID = 65534

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: agentosd calls the kernel as the owner side's uid")
	}
}

// runDir stands in for /run/agentos-kernel (0711), in a directory the
// owner side's uid can search: t.TempDir's parent is root's alone.
func runDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kernel")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	return dir
}

// setupKernel serves a real setup-only kernel's OwnerSide, as the kernel's
// process does, to the owner side's uid alone; this process stands in for
// the kernel's uid.
func setupKernel(t *testing.T) Owner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := proc.OpenKernel(proc.KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: pub, Sign: priv,
	}, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	path := filepath.Join(runDir(t), "owner.sock")
	ln, err := proc.ListenKernel(path, testOwnerUID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go proc.ServeKernel(ln, h, proc.OwnerSide, func() int64 { return time.Now().UnixMilli() })
	return Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}
}

// The kernel's own owner socket answers this client as the owner side: a
// setup-only kernel says setup is open, and its refusal of another call
// comes back in its own words. A call made as root, the broker's own uid,
// is refused (MIG-4-run-start-a).
func TestSpeaksTheKernelsWire(t *testing.T) {
	needRoot(t)
	o := setupKernel(t)
	ctx := context.Background()
	open, err := o.SetupOpen(ctx)
	if err != nil || !open {
		t.Fatalf("setup open %v, %v", open, err)
	}
	var r Refused
	if err := o.call(ctx, "stop", nil, nil); !errors.As(err, &r) || r.Text != proc.ErrSetupOnly.Error() {
		t.Fatalf("stop before setup: %v", err)
	}
	root := o
	root.As = 0
	if _, err := root.SetupOpen(ctx); err == nil {
		t.Fatal("the kernel's owner socket answered the broker's own uid")
	}
}

// A socket no kernel serves, or one served under another uid than the
// kernel's, is never sent the call.
func TestOnlyTheKernelsUIDIsCalled(t *testing.T) {
	needRoot(t)
	o := setupKernel(t)
	o.UID = testOwnerUID + 1
	if _, err := o.SetupOpen(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("a socket under another uid: %v", err)
	}
	o.Socket = filepath.Join(runDir(t), "none.sock")
	if _, err := o.SetupOpen(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("no kernel: %v", err)
	}
}

// Only the calling thread takes the owner side's uid, as its effective uid
// alone, and takes root back before the runtime has it again: after many
// calls, every thread of the broker is root, so no other goroutine ever
// runs as the owner side (MIG-4-run-start-a).
func TestNoThreadKeepsTheOwnerSidesUID(t *testing.T) {
	needRoot(t)
	o := setupKernel(t)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := o.SetupOpen(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if os.Geteuid() != 0 {
		t.Fatal("the process's own euid changed")
	}
	if left := threadsNotRoot(t); len(left) != 0 {
		t.Fatalf("threads still under another uid: %v", left)
	}
}

// threadsNotRoot lists this process's threads whose real, effective or
// saved uid is not 0.
func threadsNotRoot(t *testing.T) []string {
	t.Helper()
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, task := range tasks {
		f, err := os.Open(filepath.Join("/proc/self/task", task.Name(), "status"))
		if err != nil {
			continue // the thread ended
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if fs := strings.Fields(sc.Text()); len(fs) >= 4 && fs[0] == "Uid:" && (fs[1] != "0" || fs[2] != "0" || fs[3] != "0") {
				out = append(out, task.Name()+" "+sc.Text())
			}
		}
		f.Close()
	}
	return out
}

// A uid this process cannot take fails the call before anything is sent.
func TestAnOwnerUIDThatCannotBeTakenSendsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can take any uid")
	}
	called := false
	err := asUID(os.Geteuid()+1, func() error { called = true; return nil })
	if !errors.Is(err, errNoSeat) || called {
		t.Fatalf("a call ran without the owner side's uid: %v", err)
	}
}

// runningKernel serves a real OwnerSide of a kernel that has the owner's
// two hardware keys, as setupKernel does.
func runningKernel(t *testing.T) Owner {
	t.Helper()
	var anchors []key.PublicKey
	for range 2 {
		a, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		anchors = append(anchors, key.Ed25519(a))
	}
	return kernelWith(t, anchors)
}

// kernelWith is runningKernel with the given anchors.
func kernelWith(t *testing.T, anchors []key.PublicKey) Owner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	h, err := proc.OpenKernel(proc.KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: pub, Sign: priv, Anchors: anchors,
	}, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	path := filepath.Join(runDir(t), "owner.sock")
	ln, err := proc.ListenKernel(path, testOwnerUID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go proc.ServeKernel(ln, h, proc.OwnerSide, func() int64 { return time.Now().UnixMilli() })
	return Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}
}

// STOP and RESUME are logged on a running kernel, and its stop is read
// back (#2783); a RESUME naming an earlier STOP than the last is refused
// (#3078); a setup-only kernel refuses all three in its own words.
func TestStopAndResumeReachTheKernel(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	o := runningKernel(t)
	var stale uint64
	for i, want := range []bool{false, true, true, true, false} {
		_, stops, _ := o.Stopped(ctx)
		switch i {
		case 1:
			if err := o.Stop(ctx); err != nil {
				t.Fatal(err)
			}
		case 2:
			stale = stops // a RESUME sent now and abandoned
			if err := o.Stop(ctx); err != nil {
				t.Fatal(err)
			}
		case 3:
			if err := o.Resume(ctx, stale); !errors.As(err, new(Refused)) {
				t.Fatalf("a RESUME sent before the last STOP: %v", err)
			}
		case 4:
			if err := o.Resume(ctx, stops); err != nil {
				t.Fatal(err)
			}
		}
		if got, _, err := o.Stopped(ctx); err != nil || got != want {
			t.Fatalf("step %d: stopped %v, %v; want %v", i, got, err, want)
		}
	}
	s := setupKernel(t)
	var r Refused
	if _, _, err := s.Stopped(ctx); !errors.As(err, &r) {
		t.Fatalf("a setup-only kernel's stop read: %v", err)
	}
	if err := s.Resume(ctx, 0); !errors.As(err, &r) {
		t.Fatalf("a setup-only kernel's RESUME: %v", err)
	}
}

// cannedKernel answers every call on a socket of this process's uid with
// one fixed line.
func cannedKernel(t *testing.T, answer string) Owner {
	t.Helper()
	path := filepath.Join(runDir(t), "owner.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadBytes('\n')
			c.Write([]byte(answer + "\n"))
			c.Close()
		}
	}()
	return Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}
}

// A kernel's refusal (a key.Refusal) comes back as Refused with its code
// and detail, never as success; a result that does not decode is lost,
// never read as a default (#3072 L3 release 1).
func TestARefusalAndAnUndecodableAnswer(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	o := cannedKernel(t, `{"refusal":{"code":"stopped","detail":"stop is in force"}}`)
	var r Refused
	if err := o.Stop(ctx); !errors.As(err, &r) || r.Text != "stopped: stop is in force" {
		t.Fatalf("a refusal: %v", err)
	}
	if _, _, err := o.Stopped(ctx); !errors.As(err, &r) {
		t.Fatalf("a refused read: %v", err)
	}
	o = cannedKernel(t, `{"result":"stopped"}`)
	if got, _, err := o.Stopped(ctx); !errors.Is(err, ErrLost) || got {
		t.Fatalf("an undecodable result: %v, %v", got, err)
	}
	o = cannedKernel(t, `{"result":`)
	if err := o.Stop(ctx); !errors.Is(err, ErrLost) {
		t.Fatalf("a cut answer: %v", err)
	}
}

// STATUS's unsettled steps and RETRY reach a running kernel (#2783 b): it
// has none, and refuses a RETRY of a step it does not hold parked in its
// own words. A setup-only kernel holds no step, and refuses the RETRY.
func TestStatusAndRetryReachTheKernel(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	o := runningKernel(t)
	if s, err := o.Status(ctx); err != nil || len(s) != 0 {
		t.Fatalf("status: %+v, %v", s, err)
	}
	var r Refused
	if err := o.Retry(ctx, "p1", 0); !errors.As(err, &r) || r.Text != kernel.ErrNotParked.Error() {
		t.Fatalf("a RETRY of no parked step: %v", err)
	}
	s := setupKernel(t)
	if st, err := s.Status(ctx); err != nil || len(st) != 0 {
		t.Fatalf("a setup-only kernel's status: %+v, %v", st, err)
	}
	if err := s.Retry(ctx, "p1", 0); !errors.As(err, &r) {
		t.Fatalf("a setup-only kernel's RETRY: %v", err)
	}
}

// capturingKernel answers every call with an empty result and sends each
// call's line on the channel it returns.
func capturingKernel(t *testing.T) (string, <-chan string) {
	t.Helper()
	path := filepath.Join(runDir(t), "owner.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	lines := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l, _ := bufio.NewReader(c).ReadString('\n')
			lines <- l
			c.Write([]byte("{\"result\":null}\n"))
			c.Close()
		}
	}()
	return path, lines
}

// RETRY sends the bytes kernel/proc's own client sends, so the kernel reads
// the plan and step the owner approved, not another (#2783 b).
func TestRetrySendsTheKernelsOwnCall(t *testing.T) {
	needRoot(t)
	path, lines := capturingKernel(t)
	if err := (proc.Owner{Conn: proc.Conn{Socket: path, UID: os.Getuid(), Timeout: 5 * time.Second}}).Retry("plan:7", 2); err != nil {
		t.Fatal(err)
	}
	want := <-lines
	if err := (Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}).Retry(context.Background(), "plan:7", 2); err != nil {
		t.Fatal(err)
	}
	if got := <-lines; got != want {
		t.Fatalf("RETRY sends %q; kernel/proc sends %q", got, want)
	}
}

// Status reads every field it names from the kernel's own frame
// (kernel.Unsettled as the status read encodes it).
func TestStatusReadsTheKernelsFrame(t *testing.T) {
	needRoot(t)
	u := []kernel.Unsettled{{Plan: "p9", Index: 3, Verb: "pay", Clerk: "bank", Phase: kernel.PParked, Checks: 6,
		Detail: "no answer", Retry: true, SentAt: 1760364120000, Amount: 1200, Money: true, Recipient: "acct-4417", PlanStatus: kernel.SActive}}
	b, err := json.Marshal(map[string]any{"result": u})
	if err != nil {
		t.Fatal(err)
	}
	got, err := cannedKernel(t, string(b)).Status(context.Background())
	want := []Step{{Plan: "p9", Index: 3, Verb: "pay", Clerk: "bank", Phase: PhaseParked, Detail: "no answer", Retry: true,
		SentAt: 1760364120000, Amount: 1200, Money: true, Recipient: "acct-4417", PlanStatus: PlanActive}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("status reads %+v, %v; want %+v", got, err, want)
	}
	for k, v := range map[string]string{PhaseUnknown: kernel.PUnknown, PhaseParked: kernel.PParked, PhaseUnsent: kernel.PUnsent, PlanActive: kernel.SActive} {
		if k != v {
			t.Errorf("%q is %q in the kernel", k, v)
		}
	}
}

// A guest's plan reaches a running kernel, which logs it and decides it at
// once; Plan reads it back. A plan under a key the log never granted is
// rejected, not dropped (PLN-4), and an unknown plan reads as absent.
func TestSubmitAndPlanReachTheKernel(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	o := runningKernel(t)
	_, holder, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := kernel.SignPlan(kernel.Plan{ID: "m1/r1", Steps: []kernel.PlanStep{{Verb: "organize", Clerk: "mail",
		Args: map[string]string{"target": "t", "label": "l"}}}}, holder)
	if err := o.Submit(ctx, p); err != nil {
		t.Fatal(err)
	}
	if st, _, ok, err := o.Plan(ctx, "m1/r1"); err != nil || !ok || st != kernel.SRejected {
		t.Fatalf("plan read %q %v %v", st, ok, err)
	}
	if st, _, ok, err := o.Plan(ctx, "m1/none"); err != nil || ok {
		t.Fatalf("an unknown plan reads %q %v %v", st, ok, err)
	}
}

// Submit and Plan send the bytes kernel/proc's own client sends.
func TestSubmitAndPlanSendTheKernelsOwnCalls(t *testing.T) {
	needRoot(t)
	path, lines := capturingKernel(t)
	pc := proc.Owner{Conn: proc.Conn{Socket: path, UID: os.Getuid(), Timeout: 5 * time.Second}}
	o := Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}
	p := kernel.Plan{ID: "m1/r1", Steps: []kernel.PlanStep{{Verb: "organize", Clerk: "mail", Args: map[string]string{"target": "t"}}}, Sig: []byte{1}}
	if err := pc.Submit(p); err != nil {
		t.Fatal(err)
	}
	want := <-lines
	if err := o.Submit(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if got := <-lines; got != want {
		t.Fatalf("submit sends %q; kernel/proc sends %q", got, want)
	}
	pc.Plan("m1/r1")
	want = <-lines
	o.Plan(context.Background(), "m1/r1")
	if got := <-lines; got != want {
		t.Fatalf("plan sends %q; kernel/proc sends %q", got, want)
	}
}

// anchorSigners are two software hardware keys, Ed25519 as setup takes
// them today.
func anchorSigners(t *testing.T) []key.Ed25519Signer {
	t.Helper()
	var out []key.Ed25519Signer
	for range 2 {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, key.Ed25519Signer(priv))
	}
	return out
}

func publics(ss []key.Ed25519Signer) []key.PublicKey {
	var out []key.PublicKey
	for _, s := range ss {
		out = append(out, s.Public())
	}
	return out
}

// phoneKey is a phone passkey's ES256 public key on rp.
func phoneKey(t *testing.T, rp string) key.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := key.ES256(rp, point)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// An anchor-signed ES256 enrollment sent on the written-out wire is listed
// by the real OwnerSide, then listed as cut off after Unenroll; the anchors
// read back in setup order (#2779a).
func TestEnrollAndUnenrollReachTheKernel(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	as := anchorSigners(t)
	o := kernelWith(t, publics(as))
	if got, err := o.Anchors(ctx); err != nil || !reflect.DeepEqual(got, publics(as)) {
		t.Fatalf("anchors %v, %v", got, err)
	}
	phone := phoneKey(t, "agentos.internal")
	e := key.Enroll(as[1], phone)
	if err := o.Enroll(ctx, e); err != nil {
		t.Fatal(err)
	}
	es, un, err := o.Enrollments(ctx)
	if err != nil || len(es) != 1 || es[0].Passkey != phone || es[0].By != as[1].Public() || len(un) != 0 {
		t.Fatalf("enrolled %+v, cut off %v, %v", es, un, err)
	}
	if err := o.Unenroll(ctx, key.Unenrollment{Passkey: phone, By: phone}); !errors.As(err, new(Refused)) || errors.Is(err, ErrAnchor) {
		t.Fatalf("a cut-off no hardware key signed: %v", err) // #3209
	}
	if err := o.Unenroll(ctx, key.Unenroll(as[0], phone)); err != nil {
		t.Fatal(err)
	}
	if es, un, err = o.Enrollments(ctx); err != nil || len(es) != 1 || len(un) != 1 || un[0] != phone {
		t.Fatalf("after cut off: %+v, %v, %v", es, un, err)
	}
	// An enrollment no anchor signed is the kernel's refusal, not a typed one.
	other := phoneKey(t, "agentos.internal")
	bad := key.Enroll(as[0], other)
	bad.Sig[0] ^= 1
	if err := o.Enroll(ctx, bad); !errors.As(err, new(Refused)) || errors.Is(err, ErrAnchor) {
		t.Fatalf("a bad enrollment: %v", err)
	}
}

// Cutting off an anchor comes back as ErrAnchor, never a generic refusal,
// and changes nothing (#2740 item 2).
func TestUnenrollingAnAnchorIsErrAnchor(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	as := anchorSigners(t)
	o := kernelWith(t, publics(as))
	if err := o.Unenroll(ctx, key.Unenroll(as[0], as[0].Public())); !errors.Is(err, ErrAnchor) {
		t.Fatalf("cut off an anchor: %v", err)
	}
	es, un, err := o.Enrollments(ctx)
	if err != nil || len(es) != 0 || len(un) != 0 {
		t.Fatalf("the log changed: %v %v %v", es, un, err)
	}
	if got, err := o.Anchors(ctx); err != nil || len(got) != 2 {
		t.Fatalf("anchors %v, %v", got, err)
	}
}

// A setup-only kernel refuses every passkey call as ErrSetupOnly, matched
// by kernel/proc's own words.
func TestASetupOnlyKernelRefusesPasskeyOps(t *testing.T) {
	if setupOnlyText != proc.ErrSetupOnly.Error() {
		t.Fatalf("setupOnlyText drifted from kernel/proc: %q", proc.ErrSetupOnly.Error())
	}
	needRoot(t)
	ctx := context.Background()
	o := setupKernel(t)
	as := anchorSigners(t)
	phone := phoneKey(t, "agentos.internal")
	_, _, err1 := o.Enrollments(ctx)
	_, err2 := o.Anchors(ctx)
	for i, err := range []error{o.Enroll(ctx, key.Enroll(as[0], phone)), o.Unenroll(ctx, key.Unenroll(as[0], phone)), err1, err2} {
		if !errors.Is(err, ErrSetupOnly) {
			t.Errorf("call %d: %v", i, err)
		}
	}
}
