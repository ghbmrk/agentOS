package activatortest

// REQ: UPD-1, UPD-1a

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/apply"
	"github.com/ghbmrk/agentos/broker/apply/bootab"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

// ref is the reference activator over a Disk: the Install order A12(3)
// and (4) ask for. The mutants below each break one step of it.
type ref struct {
	d   *Disk
	src update.Source
	// Mutations, each one A12 or #2094 defect.
	writeFirst bool // writes the slot before retiring its entries
	noSync     bool // retires the entries without SyncESP before the slot writes
	byDefault  bool // takes the slot not holding the default as inactive
	blessFirst bool // makes N+1 the EFI default blessed, then counts it
	blessEntry bool // writes N+1's entry blessed, then counts it
	hashBytes  bool // writes the root-hash string as the image, unverified
	short      bool // writes the image less its last byte, unverified
	noVerity   bool // never writes the verity partition, unverified
	noUUIDs    bool // never sets the partition UUIDs
	keepPin    bool // leaves LoaderEntryDefault in place
	exactPin   bool // pins loader.conf's default to N+1's counted entry
	entryFirst bool // writes N+1's counted entry before the slot
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

// finish leaves the menu order to pick the next boot: loader.conf's
// default removed and synced, then LoaderEntryDefault deleted.
func (r *ref) finish(id string) error {
	if r.exactPin {
		if err := r.d.SetDefault(id); err != nil {
			return err
		}
	} else if err := r.d.SetDefault(""); err != nil {
		return err
	}
	if err := r.d.SyncESP(); err != nil {
		return err
	}
	if r.keepPin {
		return nil
	}
	efi, err := r.d.EFIDefault()
	if err != nil || efi == "" {
		return err
	}
	return r.d.SetEFIDefault("")
}

// retire takes the entries on slot s out of the boot menu (all of them, or
// only counted ones), leaving the booted slot's blessed entry.
func (r *ref) retire(booted, s string, all bool) error {
	es, _, err := r.d.Entries()
	if err != nil {
		return err
	}
	if _, ok := bootedEntry(es, booted); !ok {
		return errors.New("ref: no entry on the booted slot")
	}
	for id, e := range es {
		if e.Slot == s && (all || e.Tries != Blessed) {
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

func (r *ref) write(s, p string, img []byte) error {
	if err := r.d.TruncatePart(s, p); err != nil {
		return err
	}
	for i := 0; i < len(img); i += 16 {
		if err := r.d.WritePart(s, p, img[i:min(i+16, len(img))]); err != nil {
			return err
		}
	}
	return r.d.SyncPart(s, p)
}

// fetch reads the release's two partition images through v.Fetch.
func (r *ref) fetch(v *update.Verified) (data, verity []byte, err error) {
	dir, err := os.MkdirTemp("", "ref-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)
	var out [2][]byte
	for i, f := range []string{bootab.DataFile, bootab.VerityFile} {
		dst := filepath.Join(dir, fmt.Sprint(i))
		if err := v.Fetch(r.src, f, dst); err != nil {
			return nil, nil, err
		}
		if out[i], err = os.ReadFile(dst); err != nil {
			return nil, nil, err
		}
	}
	return out[0], out[1], nil
}

func (r *ref) writeSlot(s string, m update.Manifest, data, verity []byte) error {
	switch {
	case r.hashBytes:
		data = []byte(m.UsrRootHash)
	case r.short:
		data = data[:len(data)-1]
	}
	if err := r.write(s, bootab.PartUsr, data); err != nil {
		return err
	}
	if r.noVerity {
		return nil
	}
	return r.write(s, bootab.PartVerity, verity)
}

func (r *ref) Install(_ context.Context, v *update.Verified) error {
	m, err := v.Manifest()
	if err != nil {
		return err
	}
	data, verity, err := r.fetch(v)
	if err != nil {
		return err
	}
	booted, s, err := r.slots()
	if err != nil {
		return err
	}
	if r.writeFirst {
		if err := r.writeSlot(s, m, data, verity); err != nil {
			return err
		}
	}
	if err := r.retire(booted, s, true); err != nil {
		return err
	}
	if r.entryFirst {
		if err := r.d.WriteEntry(bootab.EntryID(m.Version), Entry{Slot: s, UsrHash: m.UsrRootHash, Tries: 3}); err != nil {
			return err
		}
	}
	if !r.writeFirst {
		if err := r.writeSlot(s, m, data, verity); err != nil {
			return err
		}
	}
	if !r.hashBytes && !r.short && !r.noVerity {
		if err := r.d.VerifySlot(s, m.UsrRootHash); err != nil {
			return err
		}
	}
	du, vu, err := bootab.PartitionUUIDs(m.UsrRootHash)
	if err != nil {
		return err
	}
	if !r.noUUIDs {
		if err := r.d.SetSlotUUIDs(s, du, vu); err != nil {
			return err
		}
	}
	if err := r.d.SetSlotLabel(s, bootab.Label(m.Version)); err != nil {
		return err
	}
	id := bootab.EntryID(m.Version)
	if r.blessEntry {
		if err := r.d.WriteEntry(id, Entry{Slot: s, UsrHash: m.UsrRootHash, Tries: Blessed}); err != nil {
			return err
		}
		if err := r.d.SyncESP(); err != nil {
			return err
		}
	}
	if r.blessFirst {
		if err := r.d.WriteEntry(id, Entry{Slot: s, UsrHash: m.UsrRootHash, Tries: Blessed}); err != nil {
			return err
		}
		if err := r.d.SyncESP(); err != nil {
			return err
		}
		if err := r.d.SetEFIDefault(id); err != nil {
			return err
		}
	}
	if err := r.d.WriteEntry(id, Entry{Slot: s, UsrHash: m.UsrRootHash, Tries: 3}); err != nil {
		return err
	}
	if err := r.d.SyncESP(); err != nil {
		return err
	}
	return r.finish(id)
}

func (r *ref) Abandon(context.Context) error {
	booted, s, err := r.slots()
	if err != nil {
		return err
	}
	return r.retire(booted, s, false)
}

func (r *ref) Restart(context.Context) error { return nil }

func (r *ref) Booted(context.Context) (apply.Boot, error) {
	id, err := r.d.BootID()
	if err != nil {
		return apply.Boot{}, err
	}
	booted, err := r.d.BootedSlot()
	if err != nil {
		return apply.Boot{}, err
	}
	es, _, err := r.d.Entries()
	if err != nil {
		return apply.Boot{}, err
	}
	eid, blessed := bootedEntry(es, booted)
	return apply.Boot{ID: id, UsrRootHash: es[eid].UsrHash, Blessed: blessed}, nil
}

func newRef(mut func(*ref)) func(*Disk, update.Source) apply.Activator {
	return func(d *Disk, src update.Source) apply.Activator {
		r := &ref{d: d, src: src}
		if mut != nil {
			mut(r)
		}
		return r
	}
}

// TestReferenceActivatorPasses: the reference order passes the check at
// every cut, so the check asks for nothing an activator cannot do.
func TestReferenceActivatorPasses(t *testing.T) {
	Check(t, newRef(nil))
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
		// A12(4): a whole N+1 is the default with no try counter, so a
		// bad N+1 boots with no fallback.
		{"N+1 made the default blessed", func(r *ref) { r.blessFirst = true }, "nor a whole, counted N+1"},
		// The same for an N+1 entry that is not the default: a manual
		// pick from the menu boots it with no fallback.
		{"N+1 entry written blessed", func(r *ref) { r.blessEntry = true }, "N+1's entry \"agentos_3.conf\" has no try counter"},
		// A4: a counted entry for a slot not yet written and verified,
		// so a manual pick boots a torn /usr (L3 point 4 on #3964).
		{"N+1 entry written before the slot", func(r *ref) { r.entryFirst = true }, "which is not whole for it"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if v := Violations(t, newRef(c.mut)); !anyContains(v, c.want) {
				t.Errorf("violations %q: none names %q", v, c.want)
			}
		})
	}
}

// TestWholenessIsTheImageDigest (#2094 point 1, point 3): a slot is whole
// only when both partitions hash to the release's images and carry the
// UUIDs its usrhash= finds. An activator that writes the root-hash string,
// a short image, no verity data or no UUIDs fails, even though its entry
// names the right hash.
func TestWholenessIsTheImageDigest(t *testing.T) {
	for _, c := range []struct {
		name string
		mut  func(*ref)
	}{
		{"root-hash string as the image", func(r *ref) { r.hashBytes = true }},
		{"image short by one byte", func(r *ref) { r.short = true }},
		{"verity partition never written", func(r *ref) { r.noVerity = true }},
		{"partition UUIDs never set", func(r *ref) { r.noUUIDs = true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			if v := Violations(t, newRef(c.mut)); !anyContains(v, "slot b is not whole for N+1") {
				t.Errorf("violations %q: none says slot b is not whole", v)
			}
		})
	}
}

// TestPinnedEFIDefaultIsOverridden (#2094 point 2): with the owner's
// LoaderEntryDefault pinning N-1, an activator that leaves the pin in
// place leaves N-1 the effective boot, and the check says so. A pin on N
// names an entry Install removes, so the loader passes over it.
func TestPinnedEFIDefaultIsOverridden(t *testing.T) {
	v := Violations(t, newRef(func(r *ref) { r.keepPin = true }))
	if !anyContains(v, `EFI pin on N-1, uncut: effective next boot "agentos_1.conf"`) {
		t.Errorf("violations %q", v)
	}
	for _, p := range pins {
		if p.efi != bootab.EntryID(prev) && anyContains(v, p.name+",") {
			t.Errorf("violations under %s: %q", p.name, v)
		}
	}
}

// TestExhaustedTriesFallBack (UPD-1, Security finding 1 on #3964): an
// activator that pins loader.conf's default to N+1's counted entry passes
// every cut, but once N+1's tries run out the pin still selects it, since
// systemd-boot matches a default with no boot assessment; the check says
// the box does not fall back to N-1.
func TestExhaustedTriesFallBack(t *testing.T) {
	v := Violations(t, newRef(func(r *ref) { r.exactPin = true }))
	if !anyContains(v, `no pin, uncut: after N+1's tries run out the next boot is "agentos_3.conf"`) {
		t.Errorf("violations %q", v)
	}
}

// TestSelectionFollowsSystemdBoot: one-shot, then LoaderEntryDefault, then
// loader.conf's default, each a glob matched in menu order with no boot
// assessment, then the first entry in menu order; menu order puts entries
// with no tries left last and newer versions first.
func TestSelectionFollowsSystemdBoot(t *testing.T) {
	es := map[string]Entry{
		"agentos_9.conf":  {Tries: 0},
		"agentos_10.conf": {Tries: 2},
		"agentos_2.conf":  {Tries: Blessed},
	}
	for _, c := range []struct {
		oneShot, efi, conf, want string
	}{
		{"", "", "", "agentos_10.conf"},
		{"", "", "agentos_9.conf", "agentos_9.conf"}, // exact pin: no assessment
		{"", "", "agentos_*", "agentos_10.conf"},     // glob: menu order
		{"", "agentos_2.conf", "agentos_9.conf", "agentos_2.conf"},
		{"", "gone.conf", "", "agentos_10.conf"}, // a pin matching nothing is passed over
		{"agentos_9.conf", "agentos_2.conf", "", "agentos_9.conf"},
	} {
		if got := effective(esp{es, c.conf}, c.oneShot, c.efi); got != c.want {
			t.Errorf("one-shot %q, EFI %q, loader.conf %q: %q, want %q", c.oneShot, c.efi, c.conf, got, c.want)
		}
	}
	es["agentos_10.conf"] = Entry{Tries: 0}
	if got := effective(esp{es, ""}, "", ""); got != "agentos_2.conf" {
		t.Errorf("with both counted entries out of tries: %q", got)
	}
	if got := effective(esp{map[string]Entry{}, "x"}, "", ""); got != "" {
		t.Errorf("empty menu: %q", got)
	}
}

// TestRebootKeepsTheLoaderVariables: a boot after a cut finds the owner's
// pin and one-shot pick as they were; NVRAM is not the ESP.
func TestRebootKeepsTheLoaderVariables(t *testing.T) {
	d := scenario(pin{efi: "agentos_1.conf", oneShot: "agentos_2.conf"})
	if err := d.SetEFIDefault("agentos_2.conf"); err != nil {
		t.Fatal(err)
	}
	r := d.reboot()
	if r.efi != "agentos_2.conf" || r.oneShot != "agentos_2.conf" {
		t.Errorf("after reboot: EFI %q, one-shot %q", r.efi, r.oneShot)
	}
}

// TestCheckCatchesNilAfterCut: an Install that swallows the cut fails.
func TestCheckCatchesNilAfterCut(t *testing.T) {
	v := Violations(t, func(d *Disk, src update.Source) apply.Activator { return swallow{&ref{d: d, src: src}} })
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
	v := Violations(t, func(d *Disk, src update.Source) apply.Activator { return forever{&ref{d: d, src: src}} })
	if !anyContains(v, "did not finish") {
		t.Errorf("violations %q", v)
	}
}

type forever struct{ *ref }

func (f forever) Install(context.Context, *update.Verified) error {
	for {
		if err := f.d.WritePart("b", bootab.PartUsr, []byte("x")); err != nil {
			return err
		}
	}
}

// TestCutStopsEveryWrite: after the cut no call changes the disk, so a
// partway state is exactly what the steps before it wrote.
func TestCutStopsEveryWrite(t *testing.T) {
	d := Scenario()
	d.cutAt = 1
	if err := d.SetDefault("agentos_1.conf"); !errors.Is(err, ErrCut) {
		t.Fatalf("SetDefault after cut: %v", err)
	}
	for name, f := range map[string]func() error{
		"WriteEntry":    func() error { return d.WriteEntry("x", Entry{}) },
		"RemoveEntry":   func() error { return d.RemoveEntry("agentos_2.conf") },
		"SyncESP":       d.SyncESP,
		"SetEFIDefault": func() error { return d.SetEFIDefault("agentos_1.conf") },
		"TruncatePart":  func() error { return d.TruncatePart("b", bootab.PartUsr) },
		"WritePart":     func() error { return d.WritePart("b", bootab.PartVerity, []byte("x")) },
		"SyncPart":      func() error { return d.SyncPart("b", bootab.PartUsr) },
		"SetSlotUUIDs":  func() error { return d.SetSlotUUIDs("b", "x", "y") },
		"SetSlotLabel":  func() error { return d.SetSlotLabel("b", "x") },
		"VerifySlot":    func() error { return d.VerifySlot("b", updatetest.UsrHash(inst)) },
	} {
		if err := f(); !errors.Is(err, ErrCut) {
			t.Errorf("%s after cut: %v", name, err)
		}
	}
	es, def, _ := d.Entries()
	v := d.views()[1]
	if def != "" || len(es) != 2 || d.efi != "" || d.Touched("b") || !d.holds(v, "b", updatetest.UsrHash(inst)) {
		t.Errorf("disk changed after the cut: %v %q %q %+v", es, def, d.efi, v.slots["b"])
	}
}

// TestScenarioSlotsAreWhole: the starting disk's slots are whole for their
// releases and for nothing else, so a violation is the activator's.
func TestScenarioSlotsAreWhole(t *testing.T) {
	d := Scenario()
	v := d.views()[0]
	for s, h := range map[string]string{"a": updatetest.UsrHash(prev), "b": updatetest.UsrHash(inst)} {
		if !d.holds(v, s, h) || d.holds(v, s, updatetest.UsrHash(next)) {
			t.Errorf("slot %s: whole for %s %v, for N+1 %v", s, h, d.holds(v, s, h), d.holds(v, s, updatetest.UsrHash(next)))
		}
		if err := d.VerifySlot(s, h); err != nil {
			t.Errorf("slot %s: %v", s, err)
		}
	}
	if err := d.VerifySlot("b", updatetest.UsrHash(prev)); err == nil {
		t.Error("slot b verifies against N-1's hash")
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
