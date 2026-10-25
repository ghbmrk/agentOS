//go:build linux

package kernelsock

// REQ: CLK-1, KRN-7

import (
	"bufio"
	"context"
	"crypto/ed25519"
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
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var anchors []ed25519.PublicKey
	for range 2 {
		a, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		anchors = append(anchors, a)
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
// back (#2783); a setup-only kernel refuses all three in its own words.
func TestStopAndResumeReachTheKernel(t *testing.T) {
	needRoot(t)
	ctx := context.Background()
	o := runningKernel(t)
	for i, want := range []bool{false, true, false} {
		switch i {
		case 1:
			if err := o.Stop(ctx); err != nil {
				t.Fatal(err)
			}
		case 2:
			if err := o.Resume(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := o.Stopped(ctx); err != nil || got != want {
			t.Fatalf("step %d: stopped %v, %v; want %v", i, got, err, want)
		}
	}
	s := setupKernel(t)
	var r Refused
	if _, err := s.Stopped(ctx); !errors.As(err, &r) {
		t.Fatalf("a setup-only kernel's stop read: %v", err)
	}
	if err := s.Resume(ctx); !errors.As(err, &r) {
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
	if _, err := o.Stopped(ctx); !errors.As(err, &r) {
		t.Fatalf("a refused read: %v", err)
	}
	o = cannedKernel(t, `{"result":"stopped"}`)
	if got, err := o.Stopped(ctx); !errors.Is(err, ErrLost) || got {
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
		Detail: "no answer", Retry: true, Amount: 1200, Money: true, Recipient: "acct-4417", PlanStatus: kernel.SActive}}
	b, err := json.Marshal(map[string]any{"result": u})
	if err != nil {
		t.Fatal(err)
	}
	got, err := cannedKernel(t, string(b)).Status(context.Background())
	want := []Step{{Plan: "p9", Index: 3, Verb: "pay", Clerk: "bank", Phase: PhaseParked, Detail: "no answer", Retry: true,
		Amount: 1200, Money: true, Recipient: "acct-4417", PlanStatus: PlanActive}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("status reads %+v, %v; want %+v", got, err, want)
	}
	for k, v := range map[string]string{PhaseUnknown: kernel.PUnknown, PhaseParked: kernel.PParked, PhaseUnsent: kernel.PUnsent, PlanActive: kernel.SActive} {
		if k != v {
			t.Errorf("%q is %q in the kernel", k, v)
		}
	}
}
