package proc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
		KeyDir: filepath.Join(dir, "keys"), BackupDir: filepath.Join(dir, "backups"), Up: filepath.Join(dir, "up"),
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
// Revert mutants: `moved` always false (the passphrase start cuts nothing),
// or true only for SlotPassphrase (the recovery start cuts nothing);
// `first = nil` dropped (the moved box's setup logs the first key).
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
