package proc

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: STO-2

// STO-2a-b: a log written under another key is refused, never trimmed to a
// fresh box. kernel.Open alone would trim a one-entry log as a torn frame.
func TestCheckLogKeyReadsTheKernelsFrames(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log")
	if err := checkLogKey(logPath, [32]byte{7}); err != nil {
		t.Fatalf("no log yet: %v", err)
	}
	cfg := KernelConfig{Log: logPath, Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: headPub, Sign: headPriv, Anchors: anchors}
	h, err := OpenKernel(cfg, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.With(func(k *kernel.Kernel) error { return k.Stop(1000) }); err != nil {
		t.Fatal(err)
	}
	h.Close()
	if err := checkLogKey(logPath, [32]byte{7}); err != nil {
		t.Fatalf("right key: %v", err)
	}
	if err := checkLogKey(logPath, [32]byte{8}); !errors.Is(err, ErrLogKey) {
		t.Fatalf("wrong key: got %v, want ErrLogKey", err)
	}
	// The case the check exists for: kernel.Open reads the one entry under
	// another key as a torn frame and opens empty, when no anchor kept the
	// head.
	cfg.Key, cfg.Anchor = [32]byte{8}, &kernel.MemAnchor{}
	h, err = OpenKernel(cfg, 1000)
	if err != nil {
		t.Fatalf("kernel.Open no longer trims a final frame it cannot open (%v); checkLogKey may be redundant", err)
	}
	h.Close()
	// A crash inside the first append leaves a torn frame, which is a fresh
	// box: kernel.Open trims it.
	torn := filepath.Join(dir, "torn")
	if err := os.WriteFile(torn, []byte{0, 0, 1, 0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkLogKey(torn, [32]byte{7}); err != nil {
		t.Fatalf("torn first frame: %v", err)
	}
}

// mainBox is a box whose kernel process runs in this test (RunKernel),
// started again over the same log and anchor as each boot's unlock step
// would start it.
type mainBox struct {
	t   *testing.T
	dir string
	cfg MainConfig
}

func newMainBox(t *testing.T) *mainBox {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the kernel never runs as root; CI runs these as a plain user")
	}
	dir := shortDir(t)
	return &mainBox{t: t, dir: dir, cfg: MainConfig{
		Log: filepath.Join(dir, "log"), OwnerSock: filepath.Join(dir, "o.sock"), OwnerUID: os.Getuid(),
		MeterSock: filepath.Join(dir, "m.sock"), MeterUID: os.Getuid(),
		KeyDir: filepath.Join(dir, "keys"), ContentDir: filepath.Join(dir, "content"), BackupDir: filepath.Join(dir, "backups"), Up: filepath.Join(dir, "up"),
	}}
}

// boot runs the kernel process on keys until the returned stop is called.
// The keys are the store's: the head and log keys, no anchors (so the
// kernel starts setup-only until setup logs them), and the slot and first
// edge key the test gives.
func (m *mainBox) boot(slot string, first ed25519.PublicKey) (Owner, func()) {
	t := m.t
	t.Helper()
	os.Remove(m.cfg.Up)
	keys := handoff.KernelKeys{Log: [32]byte{7}, Head: headPriv, Slot: slot, FirstEdge: first}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunKernel(ctx, m.cfg, keys, anchor(t, m.cfg.Log)) }()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(m.cfg.Up); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("the kernel did not come up: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the kernel did not come up in time")
		}
	}
	return Owner{Conn{Socket: m.cfg.OwnerSock, UID: os.Getuid(), Timeout: 10 * time.Second}}, func() {
		t.Helper()
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("the kernel stopped: %v", err)
		}
	}
}

// read opens the log the kernel process left and returns its entries'
// types and the edge it trusts.
func (m *mainBox) read() ([]string, ed25519.PublicKey) {
	t := m.t
	t.Helper()
	h, err := OpenKernel(KernelConfig{Log: m.cfg.Log, Anchor: anchor(t, m.cfg.Log), Key: [32]byte{7}, Pub: headPub, Sign: headPriv}, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	var types []string
	var live ed25519.PublicKey
	h.With(func(k *kernel.Kernel) error {
		for _, e := range k.Log().Entries() {
			types = append(types, e.Type)
		}
		live = k.LiveEdge()
		return nil
	})
	return types, live
}

// bootFails runs the kernel process as boot does and wants it to stop
// with an error before it comes up.
func (m *mainBox) bootFails(slot string, first ed25519.PublicKey) error {
	t := m.t
	t.Helper()
	os.Remove(m.cfg.Up)
	keys := handoff.KernelKeys{Log: [32]byte{7}, Head: headPriv, Slot: slot, FirstEdge: first}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunKernel(ctx, m.cfg, keys, anchor(t, m.cfg.Log))
	if _, up := os.Stat(m.cfg.Up); err == nil || up == nil {
		t.Fatalf("a start by slot %q came up (%v)", slot, err)
	}
	return err
}

// cutSlot is the slot the log's last edge.cut names, or "" with none.
func (m *mainBox) cutSlot() string {
	t := m.t
	t.Helper()
	h, err := OpenKernel(KernelConfig{Log: m.cfg.Log, Anchor: anchor(t, m.cfg.Log), Key: [32]byte{7}, Pub: headPub, Sign: headPriv}, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	var slot string
	h.With(func(k *kernel.Kernel) error {
		for _, e := range k.Log().Entries() {
			if e.Type == kernel.TEdgeCut {
				var b struct{ Slot string }
				if err := json.Unmarshal(e.Body, &b); err != nil {
					t.Fatal(err)
				}
				slot = b.Slot
			}
		}
		return nil
	})
	return slot
}

func setupAnchors() kernel.FirstAnchors {
	return kernel.SignSetup(headPub, key.Ed25519Signer(ownerPriv), key.Ed25519Signer(sparePriv))
}

// REQ: HW-15
// EDGE-link-core-b: the first edge key the store hands is logged by the
// owner's setup step, right after the anchors (sequence 2), and is the
// live edge from then on, across a restart. A box with none logs none.
// Revert mutant: the setup call back to `k.Setup(now, f)` (no edge logged).
func TestSetupLogsTheFirstEdge(t *testing.T) {
	edge, _ := gen(8)
	m := newMainBox(t)
	o, stop := m.boot(handoff.SlotTPM, edge)
	if err := o.Setup(setupAnchors()); err != nil {
		t.Fatal(err)
	}
	stop()
	types, live := m.read()
	if len(types) < 2 || types[0] != kernel.TAnchorsSet || types[1] != kernel.TEdgeEnrolled || !live.Equal(edge) {
		t.Fatalf("setup with a first edge logged %v, live %x", types, live)
	}
	_, stop = m.boot(handoff.SlotTPM, edge)
	stop()
	if _, live := m.read(); !live.Equal(edge) {
		t.Fatalf("after a restart the live edge is %x", live)
	}

	n := newMainBox(t)
	o, stop = n.boot(handoff.SlotTPM, nil)
	if err := o.Setup(setupAnchors()); err != nil {
		t.Fatal(err)
	}
	stop()
	if types, live := n.read(); len(types) < 1 || types[0] != kernel.TAnchorsSet || slicesContain(types, kernel.TEdgeEnrolled) || live != nil {
		t.Fatalf("setup with no first edge logged %v, live %x", types, live)
	}
}

// REQ: HW-15, REC-2
// EDGE-link-core-b: a start whose store was not opened by this PC's tpm
// slot (§12.2) logs edge.cut naming the slot, and the edge stays cut on
// the next start by the tpm slot. A pending first key handed at such a
// start is not logged at setup either.
// The cut names the slot that opened the store, and a cut the kernel
// refuses (a slot out of shape) starts no kernel (b2, #3364).
// Revert mutants: `moved` always false (the passphrase start cuts nothing),
// or true only for SlotPassphrase (the recovery start cuts nothing);
// `first = nil` dropped (the moved box's setup logs the first key);
// `EdgeCut(clock(), "x")` for `keys.Slot` (the cut names another slot);
// EdgeCut's error ignored (the bad slot's start comes up).
func TestUnknownHostCutsTheEdge(t *testing.T) {
	edge, _ := gen(8)
	m := newMainBox(t)
	o, stop := m.boot(handoff.SlotTPM, edge)
	if err := o.Setup(setupAnchors()); err != nil {
		t.Fatal(err)
	}
	stop()
	_, stop = m.boot(handoff.SlotPassphrase, edge)
	stop()
	types, live := m.read()
	if types[len(types)-1] != kernel.TEdgeCut || live != nil {
		t.Fatalf("a passphrase start left the edge live: %v, %x", types, live)
	}
	if got := m.cutSlot(); got != handoff.SlotPassphrase {
		t.Fatalf("the cut names slot %q, want %q", got, handoff.SlotPassphrase)
	}
	_, stop = m.boot(handoff.SlotTPM, edge)
	stop()
	if again, live := m.read(); live != nil || len(again) != len(types) {
		t.Fatalf("a tpm start after the cut trusts %x (log %v)", live, again)
	}
	// Nothing live: a second moved start logs nothing more.
	_, stop = m.boot(handoff.SlotRecovery, edge)
	stop()
	if again, _ := m.read(); len(again) != len(types) {
		t.Fatalf("a second cut was logged: %v", again)
	}

	// Any slot but the tpm one cuts: the recovery slot too.
	r := newMainBox(t)
	o, stop = r.boot(handoff.SlotTPM, edge)
	if err := o.Setup(setupAnchors()); err != nil {
		t.Fatal(err)
	}
	stop()
	_, stop = r.boot(handoff.SlotRecovery, edge)
	stop()
	if types, live := r.read(); types[len(types)-1] != kernel.TEdgeCut || live != nil {
		t.Fatalf("a recovery start left the edge live: %v, %x", types, live)
	}
	if got := r.cutSlot(); got != handoff.SlotRecovery {
		t.Fatalf("the cut names slot %q, want %q", got, handoff.SlotRecovery)
	}

	// A cut the kernel refuses starts no kernel, and the edge stays live.
	f := newMainBox(t)
	o, stop = f.boot(handoff.SlotTPM, edge)
	if err := o.Setup(setupAnchors()); err != nil {
		t.Fatal(err)
	}
	stop()
	if err := f.bootFails("no slot", edge); !errors.Is(err, kernel.ErrEdgeSlot) {
		t.Fatalf("a start by a slot out of shape: %v", err)
	}
	if types, live := f.read(); slicesContain(types, kernel.TEdgeCut) || !live.Equal(edge) {
		t.Fatalf("a refused cut logged %v, live %x", types, live)
	}

	n := newMainBox(t)
	o, stop = n.boot(handoff.SlotPassphrase, edge)
	if err := o.Setup(setupAnchors()); err != nil {
		t.Fatal(err)
	}
	stop()
	if types, live := n.read(); slicesContain(types, kernel.TEdgeEnrolled) || live != nil {
		t.Fatalf("a moved box's setup logged its first edge: %v", types)
	}
}

func slicesContain(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// REQ: HW-15, HW-16
// EDGE-link-core-c2b: given -link-sock, the kernel process serves LinkSide
// there before it marks itself up, and only setup opens it, as the owner
// side's calls; a store with no link key refuses to sign. Without it no
// link socket exists. Revert mutant: RunKernel's LinkSock append dropped
// (the link's call is unreachable).
func TestTheKernelServesTheLinkSocket(t *testing.T) {
	m := newMainBox(t)
	m.cfg.LinkSock, m.cfg.LinkUID = filepath.Join(m.dir, "l.sock"), os.Getuid()
	o, stop := m.boot(handoff.SlotTPM, nil)
	defer stop()
	link := Conn{Socket: m.cfg.LinkSock, UID: os.Getuid(), Timeout: 10 * time.Second}
	if err := link.Call("linkkey", nil, nil); !errors.Is(err, ErrSetupOnly) {
		t.Fatalf("linkkey before setup: %v, want ErrSetupOnly", err)
	}
	if err := o.Setup(setupAnchors()); err != nil {
		t.Fatal(err)
	}
	if err := link.Call("linksign", signArgs{cvInput(32)}, nil); !errors.Is(err, ErrNoLinkKey) {
		t.Fatalf("linksign with no link key: %v, want ErrNoLinkKey", err)
	}

	n := newMainBox(t)
	_, stop2 := n.boot(handoff.SlotTPM, nil)
	defer stop2()
	if _, err := os.Stat(filepath.Join(n.dir, "l.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a kernel with no -link-sock made one: %v", err)
	}
}

// REQ: CH-4, CLK-1
// MIG-4-exit-c2 (potency 1 on #3974): the kernel process pins the checker's
// key exactly when it hands the checker's unit its clerk key. Started so, it
// takes a code approval as one to check (refused here only because it names
// no held step); started with no checker clerk, it has no key to check one
// by. Revert mutant: `Checker: checker` dropped from RunKernel's config (the
// first start then answers kernel.ErrNoChecker).
func TestRunKernelPinsTheCheckerItHandsAKey(t *testing.T) {
	var root [32]byte
	for i := range root {
		root[i] = byte(0x60 + i)
	}
	ck, err := clerkkey.Derive(&root, handoff.CheckerName)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := ck.Signer()
	if err != nil {
		t.Fatal(err)
	}
	step := kernel.CodeStep{Plan: "none", Index: 0}
	approval := kernel.SignCode(sign, []kernel.CodeStep{step})
	run := func(withChecker bool) error {
		t.Helper()
		m := newMainBox(t)
		if withChecker {
			m.cfg.ClerkKeys = map[string]KeyClerk{handoff.CheckerName: {
				Socket: filepath.Join(m.dir, "kc.sock"), Cgroup: "/agentos.slice/agentos-checker.service"}}
		}
		os.Remove(m.cfg.Up)
		keys := handoff.KernelKeys{Log: [32]byte{7}, Head: headPriv, Slot: handoff.SlotTPM, ClerkRoot: root}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- RunKernel(ctx, m.cfg, keys, anchor(t, m.cfg.Log)) }()
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			if _, err := os.Stat(m.cfg.Up); err == nil {
				break
			}
			select {
			case err := <-done:
				t.Fatalf("the kernel did not come up: %v", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("the kernel did not come up in time")
			}
		}
		o := Owner{Conn{Socket: m.cfg.OwnerSock, UID: os.Getuid(), Timeout: 10 * time.Second}}
		if err := o.Setup(setupAnchors()); err != nil {
			t.Fatal(err)
		}
		err := o.ApproveCode(approval)
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("the kernel stopped: %v", err)
		}
		return err
	}
	if err := run(true); !errors.Is(err, kernel.ErrCodeApproval) {
		t.Fatalf("a kernel that hands the checker its key: %v, want the approval checked (ErrCodeApproval)", err)
	}
	if err := run(false); !errors.Is(err, kernel.ErrNoChecker) {
		t.Fatalf("a kernel with no checker clerk: %v, want ErrNoChecker", err)
	}
}
