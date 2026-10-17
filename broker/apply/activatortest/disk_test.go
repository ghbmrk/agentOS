package activatortest

// REQ: UPD-1, UPD-1a

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/apply"
	"github.com/ghbmrk/agentos/broker/update"
)

// ref is the reference activator over a Disk: the Install order A12(3)
// and (4) ask for. The mutants below each break one step of it.
type ref struct {
	d *Disk
	// Mutations, each one A12 defect.
	writeFirst bool // writes the slot before retiring its entries
	noSync     bool // retires the entries without SyncESP before the slot writes
	byDefault  bool // takes the slot not holding the default as inactive
}

func (r *ref) slots() (booted, inactive string, err error) {
	booted, err = r.d.BootedSlot()
	if err != nil {
		return "", "", err
	}
	slots, err := r.d.Slots()
	if err != nil {
		return "", "", err
	}
	if r.byDefault {
		es, def, err := r.d.Entries()
		if err != nil {
			return "", "", err
		}
		booted = es[def].Slot
	}
	for _, s := range slots {
		if s != booted {
			return booted, s, nil
		}
	}
	return "", "", errors.New("ref: one slot")
}

// retire takes every entry on slot s out of the boot menu, making an entry
// on booted the default first.
func (r *ref) retire(booted, s string) error {
	es, def, err := r.d.Entries()
	if err != nil {
		return err
	}
	if es[def].Slot == s {
		id, ok := bootedEntry(es, booted)
		if !ok {
			return errors.New("ref: no entry on the booted slot")
		}
		if err := r.d.SetDefault(id); err != nil {
			return err
		}
	}
	for id, e := range es {
		if e.Slot == s {
			if err := r.d.RemoveEntry(id); err != nil {
				return err
			}
		}
	}
	if r.noSync {
		return nil
	}
	return r.d.SyncESP()
}

func bootedEntry(es map[string]Entry, booted string) (string, bool) {
	for id, e := range es {
		if e.Slot == booted && e.Tries == Blessed {
			return id, true
		}
	}
	return "", false
}

func (r *ref) write(s, img string) error {
	if err := r.d.TruncateSlot(s); err != nil {
		return err
	}
	for i := 0; i < len(img); i += 16 {
		if err := r.d.WriteSlot(s, []byte(img[i:min(i+16, len(img))])); err != nil {
			return err
		}
	}
	return r.d.SyncSlot(s)
}

func (r *ref) Install(_ context.Context, v *update.Verified) error {
	m, err := v.Manifest()
	if err != nil {
		return err
	}
	booted, s, err := r.slots()
	if err != nil {
		return err
	}
	if r.writeFirst {
		if err := r.write(s, m.UsrRootHash); err != nil {
			return err
		}
	}
	if err := r.retire(booted, s); err != nil {
		return err
	}
	if !r.writeFirst {
		if err := r.write(s, m.UsrRootHash); err != nil {
			return err
		}
	}
	got, err := r.d.ReadSlot(s)
	if err != nil {
		return err
	}
	if got != m.UsrRootHash {
		return fmt.Errorf("ref: slot %s does not verify", s)
	}
	id := fmt.Sprintf("agentos-%d", m.Version)
	for _, step := range []func() error{
		func() error { return r.d.WriteEntry(id, Entry{Slot: s, UsrHash: m.UsrRootHash, Tries: 3}) },
		r.d.SyncESP,
		func() error { return r.d.SetDefault(id) },
		r.d.SyncESP,
	} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func (r *ref) Abandon(context.Context) error {
	booted, s, err := r.slots()
	if err != nil {
		return err
	}
	es, def, err := r.d.Entries()
	if err != nil {
		return err
	}
	if es[def].Slot == s {
		id, ok := bootedEntry(es, booted)
		if !ok {
			return errors.New("ref: no entry on the booted slot")
		}
		if err := r.d.SetDefault(id); err != nil {
			return err
		}
	}
	for id, e := range es {
		if e.Slot == s && e.Tries != Blessed {
			if err := r.d.RemoveEntry(id); err != nil {
				return err
			}
		}
	}
	return r.d.SyncESP()
}

func (r *ref) Restart(context.Context) error { return nil }

func (r *ref) Booted(context.Context) (apply.Boot, error) {
	booted, err := r.d.BootedSlot()
	if err != nil {
		return apply.Boot{}, err
	}
	usr, err := r.d.ReadSlot(booted)
	if err != nil {
		return apply.Boot{}, err
	}
	es, _, err := r.d.Entries()
	if err != nil {
		return apply.Boot{}, err
	}
	id, blessed := bootedEntry(es, booted)
	return apply.Boot{ID: id, UsrRootHash: usr, Blessed: blessed}, nil
}

// TestReferenceActivatorPasses: the reference order passes the check at
// every cut, so the check asks for nothing an activator cannot do.
func TestReferenceActivatorPasses(t *testing.T) {
	Check(t, func(d *Disk) apply.Activator { return &ref{d: d} })
}

// TestCheckCatchesA12Defects: each mutant breaks one A12 condition, and
// the check names it. A check that passed them would be a false pass.
func TestCheckCatchesA12Defects(t *testing.T) {
	for _, c := range []struct {
		name string
		mut  func(*ref)
		want string
	}{
		// A12(4): the slot is written while N's blessed entry still
		// points at it, so a cut leaves a blessed default on a torn slot.
		{"slot written before its entry leaves the menu", func(r *ref) { r.writeFirst = true }, "blessed entry"},
		// A12(4) durably: the retirement is written but not synced, so
		// the synced ESP still boots N on a torn slot.
		{"entry retired without SyncESP", func(r *ref) { r.noSync = true }, "synced ESP"},
		// A12(3): the slot not holding the default is the booted one.
		{"inactive slot taken from the default", func(r *ref) { r.byDefault = true }, "booted slot a was written"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := Violations(t, func(d *Disk) apply.Activator {
				r := &ref{d: d}
				c.mut(r)
				return r
			})
			if !anyContains(v, c.want) {
				t.Errorf("violations %q: none names %q", v, c.want)
			}
		})
	}
}

// TestCheckCatchesNilAfterCut: an Install that swallows the cut fails.
func TestCheckCatchesNilAfterCut(t *testing.T) {
	v := Violations(t, func(d *Disk) apply.Activator { return swallow{&ref{d: d}} })
	if !anyContains(v, "returned nil after the cut") {
		t.Errorf("violations %q", v)
	}
}

type swallow struct{ *ref }

func (s swallow) Install(ctx context.Context, v *update.Verified) error {
	if err := s.ref.Install(ctx, v); !errors.Is(err, ErrCut) {
		return err
	}
	return nil
}

// TestCheckCatchesNoFinish: an Install that never stops writing fails
// rather than hanging the sweep.
func TestCheckCatchesNoFinish(t *testing.T) {
	v := Violations(t, func(d *Disk) apply.Activator { return forever{&ref{d: d}} })
	if !anyContains(v, "did not finish") {
		t.Errorf("violations %q", v)
	}
}

type forever struct{ *ref }

func (f forever) Install(context.Context, *update.Verified) error {
	for {
		if err := f.d.WriteSlot("b", []byte("x")); err != nil {
			return err
		}
	}
}

// TestCutStopsEveryWrite: after the cut no call changes the disk, so a
// partway state is exactly what the steps before it wrote.
func TestCutStopsEveryWrite(t *testing.T) {
	d := Scenario()
	d.cutAt = 1
	if err := d.SetDefault("agentos-1"); !errors.Is(err, ErrCut) {
		t.Fatalf("SetDefault after cut: %v", err)
	}
	for name, f := range map[string]func() error{
		"WriteEntry":   func() error { return d.WriteEntry("x", Entry{}) },
		"RemoveEntry":  func() error { return d.RemoveEntry("agentos-2") },
		"SyncESP":      d.SyncESP,
		"TruncateSlot": func() error { return d.TruncateSlot("b") },
		"WriteSlot":    func() error { return d.WriteSlot("b", []byte("x")) },
		"SyncSlot":     func() error { return d.SyncSlot("b") },
	} {
		if err := f(); !errors.Is(err, ErrCut) {
			t.Errorf("%s after cut: %v", name, err)
		}
	}
	es, def, _ := d.Entries()
	if def != "agentos-2" || len(es) != 2 || d.slots["b"].data != "0000000000000000000000000000000000000000000000000000000000000002" {
		t.Errorf("disk changed after the cut: %v %q", es, def)
	}
}

func anyContains(v []string, s string) bool {
	for _, x := range v {
		if strings.Contains(x, s) {
			return true
		}
	}
	return false
}
