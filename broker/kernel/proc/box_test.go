package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The box rig, as broker/clerk/run's tests have it: those test the clerks'
// processes against this package's kernel process, and these test the
// kernel process alone.

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
	return newBoxAt(t, sock, name, time.Now().UnixMilli(), verbs...)
}

// newBoxAt is newBoxFor with its clock at now, so two boxes made at one now
// hold the same keys.
func newBoxAt(t *testing.T, sock, name string, now int64, verbs ...key.Verb) *box {
	t.Helper()
	b := &box{t: t, now: now, remote: Remote{Socket: sock, UID: os.Getuid(), Timeout: 20 * time.Second}}
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
