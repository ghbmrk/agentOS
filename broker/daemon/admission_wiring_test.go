package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
)

// REQ: RES-1, RES-2

type recordPreempt struct{ ids []string }

func (r *recordPreempt) Preempt(id string) error { r.ids = append(r.ids, id); return nil }

// The daemon's admission uses the configured preempter (the VM manager in
// agentosd) and pressure source.
func TestRES1RES2DaemonAdmissionUsesPreempterAndPressure(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pre := &recordPreempt{}
	psi := 0.0
	d, err := Run(ctx, Config{
		JournalPath: filepath.Join(dir, "journal.log"),
		SocketDir:   filepath.Join(dir, "run"),
		OwnerNumber: owner,
		Admission:   admission.Config{CapacityMB: 2000, HeadroomMB: 200},
		Preempter:   pre,
		Pressure:    func() float64 { return psi },
		MaxPressure: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	adm := d.Admission()
	if _, err := adm.Admit(admission.Request{ID: "exp", Class: admission.Experiment, MemMB: 1500}); err != nil {
		t.Fatal(err)
	}
	if _, err := adm.Admit(admission.Request{ID: "call", Class: admission.Foreground, MemMB: 1000}); err != nil {
		t.Fatal(err)
	}
	if len(pre.ids) != 1 || pre.ids[0] != "exp" {
		t.Fatalf("preempted %v, want [exp]", pre.ids)
	}
	adm.Release("call")
	psi = 25
	if _, err := adm.Admit(admission.Request{ID: "w", Class: admission.Accepted, MemMB: 10}); !errors.Is(err, admission.ErrPressure) {
		t.Fatalf("accepted work under pressure: %v", err)
	}
	if _, err := adm.Admit(admission.Request{ID: "f", Class: admission.Foreground, MemMB: 10}); err != nil {
		t.Fatalf("foreground under pressure: %v", err)
	}
	cancel()
	d.Wait()
}

// Without a machine manager, preemption is refused rather than pretended.
func TestRES1NoManagerRefusesPreemption(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := Run(ctx, Config{
		JournalPath: filepath.Join(dir, "journal.log"),
		SocketDir:   filepath.Join(dir, "run"),
		OwnerNumber: owner,
		Admission:   admission.Config{CapacityMB: 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	adm := d.Admission()
	adm.Admit(admission.Request{ID: "exp", Class: admission.Experiment, MemMB: 100})
	if _, err := adm.Admit(admission.Request{ID: "call", Class: admission.Foreground, MemMB: 50}); err == nil {
		t.Fatal("preemption reported success with nothing to stop the machine")
	}
	cancel()
	d.Wait()
}
