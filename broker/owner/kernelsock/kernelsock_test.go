//go:build linux

package kernelsock

// REQ: CLK-1, KRN-7, KEY-4, REC-3, PLN-4

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
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

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
	"github.com/ghbmrk/agentos/broker/pageca"
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
	if err := o.Retry(ctx, "p1", 0, 1); !errors.As(err, &r) || r.Text != kernel.ErrNotParked.Error() {
		t.Fatalf("a RETRY of no parked step: %v", err)
	}
	s := setupKernel(t)
	if st, err := s.Status(ctx); err != nil || len(st) != 0 {
		t.Fatalf("a setup-only kernel's status: %+v, %v", st, err)
	}
	if err := s.Retry(ctx, "p1", 0, 1); !errors.As(err, &r) {
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
	if err := (proc.Owner{Conn: proc.Conn{Socket: path, UID: os.Getuid(), Timeout: 5 * time.Second}}).Retry("plan:7", 2, 3); err != nil {
		t.Fatal(err)
	}
	want := <-lines
	if err := (Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}).Retry(context.Background(), "plan:7", 2, 3); err != nil {
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
		Detail: "no answer", Retry: true, SentAt: 1760364120000, Attempt: 2, Amount: 1200, Money: true, Recipient: "acct-4417", PlanStatus: kernel.SActive}}
	b, err := json.Marshal(map[string]any{"result": u})
	if err != nil {
		t.Fatal(err)
	}
	got, err := cannedKernel(t, string(b)).Status(context.Background())
	want := []Step{{Plan: "p9", Index: 3, Verb: "pay", Clerk: "bank", Phase: PhaseParked, Detail: "no answer", Retry: true,
		SentAt: 1760364120000, Attempt: 2, Amount: 1200, Money: true, Recipient: "acct-4417", PlanStatus: PlanActive}}
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
// rejected, not dropped, and its read names the failing check (PLN-4); an
// unknown plan reads as absent.
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
	// The read names the failing check (PLN-4): the plan's key is no chain.
	if v, err := o.Plan(ctx, "m1/r1"); err != nil || v.Status != kernel.SRejected || v.Reject != kernel.CKey {
		t.Fatalf("plan read %+v %v", v, err)
	}
	if v, err := o.Plan(ctx, "m1/none"); err != nil || v.Status != "" {
		t.Fatalf("an unknown plan reads %+v %v", v, err)
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

// Backups cross the owner socket in the kernel's frames: a destination
// added on a hardware key's signature, a backup taken and verified by the
// kernel, the kept backups read back, and a removal (MIG-4-recovery-e3).
func TestBackupsReachTheKernel(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	as := anchorSigners(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rcp, err := backup.RecipientFor(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	h, err := proc.OpenKernel(proc.KernelConfig{
		Log: filepath.Join(data, "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: pub, Sign: priv, Anchors: publics(as),
		KeyDir: filepath.Join(data, "keys"), BackupDir: filepath.Join(data, "backups"), Recipient: append(rcp.X, rcp.EK...),
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
	o := Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}

	tg := kernel.BackupTarget{Name: "drive", Kind: kernel.KindDir, Locator: t.TempDir()}
	if err := o.BackupTarget(ctx, tg, key.Approve(as[1], kernel.BackupTargetHash(1, tg))); !errors.As(err, new(Refused)) || !errors.Is(err, ErrTargetSig) {
		t.Fatalf("a signature over another add: %v", err)
	}
	// Unsigned, the kernel checks the place first (MIG-4-recovery-e4b's
	// Begin): a good one is ErrTargetSig, one it cannot reach is not.
	if err := o.BackupTarget(ctx, tg, key.Cosign{}); !errors.Is(err, ErrTargetSig) {
		t.Fatalf("unsigned: %v", err)
	}
	gone := kernel.BackupTarget{Name: "gone", Kind: kernel.KindDir, Locator: filepath.Join(t.TempDir(), "absent")}
	if err := o.BackupTarget(ctx, gone, key.Cosign{}); !errors.As(err, new(Refused)) || errors.Is(err, ErrTargetSig) {
		t.Fatalf("unsigned, a place it cannot reach: %v", err)
	}
	if !bytes.Equal(TargetMsg(0, tg), key.CosignMsg(kernel.BackupTargetHash(0, tg))) {
		t.Fatal("TargetMsg is not the add's cosign message")
	}
	if err := o.BackupTarget(ctx, tg, key.Approve(as[1], kernel.BackupTargetHash(0, tg))); err != nil {
		t.Fatal(err)
	}
	taken, err := o.Backup(ctx)
	if err != nil || len(taken) != 1 || taken[0].Backup == nil || !taken[0].Backup.Verified || taken[0].Backup.Recipient != rcp.ID() {
		t.Fatalf("backup: %+v %v", taken, err)
	}
	v, err := o.Backups(ctx)
	if err != nil || v.Recipient != rcp.ID() || len(v.Targets) != 1 || !v.Targets[0].Rewritable || len(v.Backups) != 1 || *taken[0].Backup != v.Backups[0] {
		t.Fatalf("backups: %+v %v", v, err)
	}
	if err := o.BackupTarget(ctx, tg, key.Approve(as[1], kernel.BackupTargetHash(1, tg))); !errors.Is(err, ErrTargetExists) {
		t.Fatalf("a name used before: %v", err)
	}
	if err := o.Untarget(ctx, "drive"); err != nil {
		t.Fatal(err)
	}
	if err := o.Untarget(ctx, "drive"); !errors.Is(err, ErrNoTarget) {
		t.Fatalf("removed twice: %v", err)
	}
	if v, err = o.Backups(ctx); err != nil || !v.Targets[0].Removed || len(v.Backups) != 1 {
		t.Fatalf("after the removal: %+v %v", v, err)
	}
}

// REQ: CH-9
// MIG-4-recovery-f1: the page's serving key reaches the kernel, which
// signs it with the authority only it holds; a kernel with none answers
// ErrNoAuthority before setup and ErrPageRestore once claimed, here as
// this package's own errors, so the texts stay the kernel's.
func TestCertifyReachesTheKernel(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	a, err := pageca.New(pageca.DefaultName, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), nil)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pageca.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(pageCA []byte, anchors []key.PublicKey) Owner {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		h, err := proc.OpenKernel(proc.KernelConfig{
			Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: pub, Sign: priv,
			Anchors: anchors, PageCA: pageCA,
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
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&sk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, auth, err := serve(ca, nil).Certify(ctx, der)
	if err != nil || !bytes.Equal(auth, a.Certificate()) {
		t.Fatalf("certify: %v", err)
	}
	if c, err := x509.ParseCertificate(leaf); err != nil || len(c.DNSNames) != 1 || c.DNSNames[0] != pageca.DefaultName {
		t.Fatalf("the leaf: %v", err)
	}
	if _, _, err := serve(nil, nil).Certify(ctx, der); !errors.Is(err, ErrNoAuthority) {
		t.Fatalf("no authority: %v", err)
	}
	if _, _, err := serve(nil, publics(anchorSigners(t))).Certify(ctx, der); !errors.Is(err, ErrPageRestore) {
		t.Fatalf("claimed with no authority: %v", err)
	}
	if noAuthorityText != proc.ErrNoAuthority.Error() || pageRestoreText != proc.ErrPageRestore.Error() {
		t.Fatal("the refusals' texts are not the kernel's")
	}
}

// REQ: REC-4, BAK-1
// MIG-4-recovery-r1 (#3391): a hardware key's tap over RotateMsg gets an
// approval the store's head key signed, and the same approval switches
// the kernel to the new recipient; a phone passkey's tap is ErrRotateSig,
// a spent approval ErrApprovalStale and an expired one ErrApprovalExpired,
// here as this package's own errors, so the texts stay the kernel's.
func TestRecoveryRotateReachesTheKernel(t *testing.T) {
	needRoot(t)
	if approvalStaleText != proc.ErrApprovalStale.Error() || approvalExpiredText != handoff.ErrApprovalExpired.Error() {
		t.Fatal("the rotation refusals' texts are not the kernel's")
	}
	ctx := context.Background()
	as := anchorSigners(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rcp := func(b byte) backup.Recipient {
		r, err := backup.RecipientFor(bytes.Repeat([]byte{b}, 32))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r1, r2 := rcp(9), rcp(10)
	data := t.TempDir()
	h, err := proc.OpenKernel(proc.KernelConfig{
		Log: filepath.Join(data, "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: pub, Sign: priv, Anchors: publics(as),
		KeyDir: filepath.Join(data, "keys"), BackupDir: filepath.Join(data, "backups"), Recipient: append(r1.X, r1.EK...),
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
	o := Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}

	if !bytes.Equal(RotateMsg(r1.ID(), r2.ID()), key.CosignMsg(kernel.RecoveryRotateHash(r1.ID(), r2.ID()))) {
		t.Fatal("RotateMsg is not the rotation's cosign message")
	}
	sign := func(s key.Ed25519Signer, old, next string) key.Cosign {
		return key.Cosign{By: s.Public(), Sig: s.Sign(RotateMsg(old, next))}
	}
	phone := anchorSigners(t)[0] // a key the kernel holds as no anchor
	if _, err := o.RecoveryRotate(ctx, r2.ID(), sign(phone, r1.ID(), r2.ID())); !errors.As(err, new(Refused)) || !errors.Is(err, ErrRotateSig) {
		t.Fatalf("a key that is no anchor: %v", err)
	}
	a, err := o.RecoveryRotate(ctx, r2.ID(), sign(as[0], r1.ID(), r2.ID()))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := handoff.VerifyApproval(pub, a, time.Now().UnixMilli()); err != nil || got.Old != r1.ID() || got.Next != r2.ID() {
		t.Fatalf("approval %+v, %v", got, err)
	}
	expired, err := handoff.SignApproval(priv, handoff.Approval{Route: handoff.RouteCard, Old: r1.ID(), Next: r2.ID(), Expires: 1})
	if err != nil {
		t.Fatal(err)
	}
	wire := append(bytes.Clone(r2.X), r2.EK...)
	if err := o.SwitchRecipient(ctx, wire, expired); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("an expired approval: %v", err)
	}
	if err := o.SwitchRecipient(ctx, wire, a); err != nil {
		t.Fatal(err)
	}
	if v, err := o.Backups(ctx); err != nil || v.Recipient != r2.ID() {
		t.Fatalf("after the switch: %+v %v", v, err)
	}
	r3 := rcp(11)
	spent, err := handoff.SignApproval(priv, handoff.Approval{Route: handoff.RouteCard, Old: r1.ID(), Next: r3.ID(), Expires: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	if err := o.SwitchRecipient(ctx, append(bytes.Clone(r3.X), r3.EK...), spent); !errors.Is(err, ErrApprovalStale) {
		t.Fatalf("an approval from before the switch: %v", err)
	}
}

// REQ: HW-15
// EDGE-link-core-c2b: the page step's enrolment and the owner's cut reach
// the real OwnerSide on the written-out wire: the candidate the link port
// logged is enrolled on a hardware key's signature and is live, a key the
// link never logged is the kernel's refusal, and a revoke cuts it.
// Revert mutants: a call or argument name changed here (the kernel answers
// "no call" or ErrArgs).
func TestEdgeEnrollAndRevokeReachTheKernel(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	as := anchorSigners(t)
	head, headPriv, _ := ed25519.GenerateKey(nil)
	h, err := proc.OpenKernel(proc.KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: head, Sign: headPriv, Anchors: publics(as),
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
	o := Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}

	edge, edgePriv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	nonce := make([]byte, kernel.HelloNonce)
	sig := func(k ed25519.PublicKey) (c key.Cosign) {
		h.With(func(kk *kernel.Kernel) error {
			c = key.Approve(as[0], kernel.EdgeEnrollHash(kk.State().EdgeChanges(), kk.Box(), k, kk.EdgeReplaces(k)))
			return nil
		})
		return c
	}
	live := func() (k ed25519.PublicKey) {
		h.With(func(kk *kernel.Kernel) error { k = kk.LiveEdge(); return nil })
		return k
	}
	if err := h.With(func(k *kernel.Kernel) error {
		return k.EdgeCandidate(time.Now().UnixMilli(), edge, nonce, ed25519.Sign(edgePriv, kernel.HelloMsg(nonce)))
	}); err != nil {
		t.Fatal(err)
	}
	var r Refused
	if err := o.EdgeEnroll(ctx, other, sig(other)); !errors.As(err, &r) || r.Text != kernel.ErrEdgeCandidate.Error() {
		t.Fatalf("enrolling a key the link never logged: %v", err)
	}
	if err := o.EdgeEnroll(ctx, edge, sig(edge)); err != nil || !live().Equal(edge) {
		t.Fatalf("enrolling the candidate: %v, live %x", err, live())
	}
	if err := o.EdgeRevoke(ctx, edge); err != nil || live() != nil {
		t.Fatalf("revoking it: %v, live %x", err, live())
	}
	if err := o.EdgeRevoke(ctx, edge); !errors.As(err, &r) || r.Text != kernel.ErrEdgeRevoked.Error() {
		t.Fatalf("revoking it again: %v", err)
	}
}

// REQ: REC-4
// MIG-4-recovery-r3: after a lost-card restart, the page reads the new
// recovery key from the real OwnerSide on the written-out wire until it
// confirms the card; then the kernel holds none, which reads as
// ErrNoRecoveryCard, and confirming again changes nothing.
// Revert mutants: a call name changed here (the kernel answers "no call");
// noRecoveryCardText changed (the text check fails).
func TestRecoveryCardReachesTheKernel(t *testing.T) {
	needRoot(t)
	if noRecoveryCardText != proc.ErrNoRecoveryCard.Error() {
		t.Fatal("the no-card refusal's text is not the kernel's")
	}
	ctx := context.Background()
	as := anchorSigners(t)
	head, headPriv, _ := ed25519.GenerateKey(nil)
	h, err := proc.OpenKernel(proc.KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: head, Sign: headPriv, Anchors: publics(as),
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
	o := Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}

	if _, err := o.RecoveryCard(ctx); !errors.Is(err, ErrNoRecoveryCard) {
		t.Fatalf("no card made at this boot: %v", err)
	}
	rec := bytes.Repeat([]byte{0x42}, handoff.RecoveryLen)
	h.HoldRecoveryCard(bytes.Clone(rec))
	if got, err := o.RecoveryCard(ctx); err != nil || !bytes.Equal(got, rec) {
		t.Fatalf("the card: %x, %v", got, err)
	}
	for range 2 {
		if err := o.RecoveryCardDone(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := o.RecoveryCard(ctx); !errors.Is(err, ErrNoRecoveryCard) {
		t.Fatalf("after the confirm: %v", err)
	}
}

// REQ: LOG-4
// KRN-forget b: erase by name over the real OwnerSide on the written-out
// wire. Named answers IDs, Recall counts, Erase confirms and records the
// reader, and the kernel's content refusals come back as its own errors.
func TestEraseByNameReachesTheKernel(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	h, err := proc.OpenKernel(proc.KernelConfig{
		Log: filepath.Join(data, "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: pub, Sign: priv,
		Anchors: publics(anchorSigners(t)), KeyDir: filepath.Join(data, "keys"),
		ContentDir: filepath.Join(data, "content"), Stores: []string{"mail"},
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
	o := Owner{Socket: path, UID: os.Getuid(), As: testOwnerUID}

	var alice string
	if err := h.With(func(k *kernel.Kernel) error {
		if alice, err = k.OpenSubject(1000); err != nil {
			return err
		}
		if _, err := k.Seal(1000, alice, "mail", kernel.ClassLabel, []byte("Alice Smith")); err != nil {
			return err
		}
		item, err := k.Seal(1000, alice, "mail", "message", []byte("CANARY-lunch"))
		if err != nil {
			return err
		}
		_, err = k.ReadFor(2000, item, "agent.1")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	found, unread, err := o.Named(ctx, "alice  smith")
	if err != nil || len(found) != 1 || found[0] != alice || unread != nil {
		t.Fatalf("named: %v %v %v", found, unread, err)
	}
	if _, _, err := o.Named(ctx, "  "); !errors.Is(err, kernel.ErrLabel) {
		t.Fatalf("a blank name: %v", err)
	}
	if r, ok, err := o.Recall(ctx, alice); err != nil || !ok || len(r.Items) != 2 {
		t.Fatalf("recall: %+v %v %v", r, ok, err)
	}
	if _, ok, err := o.Recall(ctx, strings.Repeat("0", 32)); err != nil || ok {
		t.Fatalf("recall of no subject: %v %v", ok, err)
	}
	c, err := o.Erase(ctx, alice)
	if err != nil || c.Subject != alice || len(c.Unconfirmed) != 0 {
		t.Fatalf("erase: %+v %v", c, err)
	}
	if _, err := o.Erase(ctx, alice); !errors.Is(err, kernel.ErrErased) || !errors.As(err, new(Refused)) {
		t.Fatalf("a second erase: %v", err)
	}
	if _, err := o.Erase(ctx, strings.Repeat("0", 32)); !errors.Is(err, kernel.ErrSubject) {
		t.Fatalf("an erase of no subject: %v", err)
	}
	if u, err := o.Unerased(ctx); err != nil || u != nil {
		t.Fatalf("unerased: %+v %v", u, err)
	}
	rs, err := o.ErasedReads(ctx)
	if err != nil || len(rs) != 1 || rs[0] != (kernel.ErasedRead{Subject: alice, Lineage: "agent.1", First: 2000}) {
		t.Fatalf("erased reads: %+v %v", rs, err)
	}
	// A kernel with no subject-key table has no content to look in.
	if _, _, err := runningKernel(t).Named(ctx, "Alice"); !errors.Is(err, kernel.ErrContentClosed) {
		t.Fatalf("named before content opens: %v", err)
	}
}
