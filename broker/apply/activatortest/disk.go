// Package activatortest is the acceptance check for an apply.Activator's
// Install after an other-root boot (broker/apply ASSUMPTIONS A12(3), (4)):
// booted on N-1 with N blessed and default, Install of N+1 overwrites N's
// slot, never writes the booted slot, and leaves N-1 the default boot if
// it is cut at any step, including after the slot writes begin.
//
// The activator under test runs over a Disk: a model of the ESP and the
// two /usr slots that can be cut (a power cut) before any write. A real
// activator is written against an interface with Disk's method set, so
// the same check runs on it; its production adapter maps each method to
// the ESP file or block-device operation it names.
package activatortest

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/apply"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

// ErrCut is every Disk call's answer once the power is cut.
var ErrCut = errors.New("activatortest: power cut")

// Blessed is Entry.Tries for an entry with no try counter: it is never
// counted down, so the loader never falls back from it (A12(1)).
const Blessed = -1

// Entry is a boot loader entry on the ESP: the slot it boots, its
// usrhash= and its tries left (Blessed when it has no counter).
type Entry struct {
	Slot    string
	UsrHash string
	Tries   int
}

// esp is the ESP's boot menu: its entries by ID and the default entry.
type esp struct {
	Entries map[string]Entry
	Default string
}

func (e esp) clone() esp {
	return esp{Entries: maps.Clone(e.Entries), Default: e.Default}
}

// slot is one /usr slot: its bytes, and whether a write since the last
// SyncSlot left them torn on a cut.
type slot struct {
	data  string
	dirty bool
	old   string // the bytes a cut leaves when !dirty: the last synced
}

// Disk is the model. Each mutating call counts one step; the cutAt'th
// step and every call after it fail with ErrCut and change nothing. ESP
// writes reach the disk only at SyncESP (a FAT ESP may also keep some
// unsynced writes, so the check judges both the synced view and the
// written one). A slot write tears the slot until SyncSlot.
type Disk struct {
	mu      sync.Mutex
	booted  string
	esp     esp // as written
	synced  esp // as on disk at the last SyncESP
	slots   map[string]*slot
	steps   int
	cutAt   int // 0: never
	cut     bool
	touched map[string]bool // slots written
}

// NewDisk is a disk booted on slot booted, with the given slot contents
// and boot menu, all synced.
func NewDisk(booted string, slots map[string]string, entries map[string]Entry, def string) *Disk {
	d := &Disk{booted: booted, slots: map[string]*slot{}, touched: map[string]bool{}}
	for s, b := range slots {
		d.slots[s] = &slot{data: b, old: b}
	}
	d.esp = esp{Entries: maps.Clone(entries), Default: def}
	d.synced = d.esp.clone()
	return d
}

// step counts a mutating call and reports whether it may run.
func (d *Disk) step() error {
	if d.cut {
		return ErrCut
	}
	d.steps++
	if d.cutAt != 0 && d.steps >= d.cutAt {
		d.cut = true
		return ErrCut
	}
	return nil
}

func (d *Disk) read() error {
	if d.cut {
		return ErrCut
	}
	return nil
}

// BootedSlot is the slot the running boot came from (the loader's
// LoaderEntrySelected).
func (d *Disk) BootedSlot() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.booted, d.read()
}

// Slots lists the slot names, sorted.
func (d *Disk) Slots() ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Sorted(maps.Keys(d.slots)), d.read()
}

// Entries is the boot menu as written, and its default entry.
func (d *Disk) Entries() (map[string]Entry, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return maps.Clone(d.esp.Entries), d.esp.Default, d.read()
}

// WriteEntry writes boot entry id.
func (d *Disk) WriteEntry(id string, e Entry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.step(); err != nil {
		return err
	}
	d.esp.Entries[id] = e
	return nil
}

// RemoveEntry deletes boot entry id.
func (d *Disk) RemoveEntry(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.step(); err != nil {
		return err
	}
	delete(d.esp.Entries, id)
	return nil
}

// SetDefault sets the default entry (loader.conf default).
func (d *Disk) SetDefault(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.step(); err != nil {
		return err
	}
	d.esp.Default = id
	return nil
}

// SyncESP makes the ESP's writes durable.
func (d *Disk) SyncESP() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.step(); err != nil {
		return err
	}
	d.synced = d.esp.clone()
	return nil
}

// TruncateSlot empties slot s for a new image; it tears s until SyncSlot.
func (d *Disk) TruncateSlot(s string) error {
	return d.writeSlot(s, func(sl *slot) { sl.data = "" })
}

// WriteSlot appends p to slot s; it tears s until SyncSlot.
func (d *Disk) WriteSlot(s string, p []byte) error {
	return d.writeSlot(s, func(sl *slot) { sl.data += string(p) })
}

func (d *Disk) writeSlot(s string, f func(*slot)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	sl, ok := d.slots[s]
	if !ok {
		return fmt.Errorf("activatortest: no slot %q", s)
	}
	if err := d.step(); err != nil {
		return err
	}
	d.touched[s] = true
	sl.dirty = true
	f(sl)
	return nil
}

// SyncSlot makes slot s's writes durable.
func (d *Disk) SyncSlot(s string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	sl, ok := d.slots[s]
	if !ok {
		return fmt.Errorf("activatortest: no slot %q", s)
	}
	if err := d.step(); err != nil {
		return err
	}
	sl.dirty, sl.old = false, sl.data
	return nil
}

// ReadSlot is slot s's bytes, for verifying the written image against
// its root hash (veritysetup verify, A4).
func (d *Disk) ReadSlot(s string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	sl, ok := d.slots[s]
	if !ok {
		return "", fmt.Errorf("activatortest: no slot %q", s)
	}
	return sl.data, d.read()
}

// torn marks a slot's bytes after a cut mid-write.
const torn = "\x00torn"

// view is what a boot after a cut finds: the boot menu and the slots.
type view struct {
	name  string
	esp   esp
	slots map[string]string
}

// views are the states a cut can leave: the ESP as last synced and as
// written, each with the slots as they reach the disk.
func (d *Disk) views() []view {
	d.mu.Lock()
	defer d.mu.Unlock()
	slots := map[string]string{}
	for s, sl := range d.slots {
		slots[s] = sl.old
		if sl.dirty {
			slots[s] = torn
		}
	}
	return []view{
		{"synced ESP", d.synced.clone(), slots},
		{"written ESP", d.esp.clone(), maps.Clone(slots)},
	}
}

// reboot is the disk a boot after the cut finds, on the synced view, booted
// on the same slot.
func (d *Disk) reboot() *Disk {
	v := d.views()[0]
	return NewDisk(d.booted, v.slots, v.esp.Entries, v.esp.Default)
}

// Releases N-1, N and N+1 of the check.
const (
	prev = 1 // N-1: booted on slot a, blessed
	inst = 2 // N: on slot b, blessed and the default (installed_other_root)
	next = 3 // N+1: the release Install writes (its /usr root hash is the manifest's)
)

// Scenario is the A12 other-root disk: booted on slot a running N-1, with
// N blessed and default on slot b.
func Scenario() *Disk {
	return NewDisk("a",
		map[string]string{"a": updatetest.UsrHash(prev), "b": updatetest.UsrHash(inst)},
		map[string]Entry{
			"agentos-1": {Slot: "a", UsrHash: updatetest.UsrHash(prev), Tries: Blessed},
			"agentos-2": {Slot: "b", UsrHash: updatetest.UsrHash(inst), Tries: Blessed},
		}, "agentos-2")
}

// maxSteps bounds the cut sweep, so an activator that never finishes fails.
const maxSteps = 2000

// Violations runs Install of N+1 over the Scenario disk, cut before each of
// its steps in turn and once uncut, and returns every way it breaks A12(3)
// or (4). After each cut it also reboots onto the synced view and runs
// Install again uncut, which must finish as an uncut run does.
func Violations(t testing.TB, newActivator func(*Disk) apply.Activator) []string {
	t.Helper()
	rel := updatetest.Release(t, next, false, map[string][]byte{"host-image/usr.img": []byte("usr")})
	m, err := rel.Manifest()
	if err != nil {
		return []string{fmt.Sprintf("release: %v", err)}
	}
	want := m.UsrRootHash
	var out []string
	for k := 1; k <= maxSteps; k++ {
		d := Scenario()
		d.cutAt = k
		err := newActivator(d).Install(t.Context(), rel)
		if !d.cut {
			if err != nil {
				return append(out, fmt.Sprintf("uncut Install: %v", err))
			}
			return append(out, finished(d, want, "uncut")...)
		}
		at := fmt.Sprintf("cut at step %d", k)
		if err == nil {
			out = append(out, at+": Install returned nil after the cut")
		}
		out = append(out, partway(d, want, at)...)
		r := d.reboot()
		r.cutAt = maxSteps
		if err := newActivator(r).Install(t.Context(), rel); r.cut {
			return append(out, fmt.Sprintf("%s, Install again after reboot did not finish in %d steps", at, maxSteps))
		} else if err != nil {
			out = append(out, fmt.Sprintf("%s, Install again after reboot: %v", at, err))
			continue
		}
		out = append(out, finished(r, want, at+", Install again after reboot")...)
	}
	return append(out, fmt.Sprintf("Install did not finish in %d steps", maxSteps))
}

// Check fails t with each of Violations.
func Check(t *testing.T, newActivator func(*Disk) apply.Activator) {
	t.Helper()
	for _, v := range Violations(t, newActivator) {
		t.Error(v)
	}
}

// partway checks a cut Install: the booted slot is intact, and every view
// boots a whole image: the default is N-1's entry, or an entry whose slot
// holds all of its image (N before any byte of its slot is written, N+1
// once it is written and synced, and only counted, so a bad N+1 falls
// back); no blessed entry points at a slot that does not hold its image;
// and no N+1 entry is without a try counter. Once a byte of N's slot is
// written, only N-1 is left to be the default until N+1 is whole.
func partway(d *Disk, want, at string) []string {
	out := intact(d, at)
	for _, v := range d.views() {
		w := at + ", " + v.name
		def, ok := v.esp.Entries[v.esp.Default]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: default %q is not in the boot menu", w, v.esp.Default))
		case def.Slot == "a" && def.UsrHash == updatetest.UsrHash(prev):
		case v.slots[def.Slot] == def.UsrHash && def.UsrHash == want && def.Tries > 0:
		case v.slots[def.Slot] == def.UsrHash && def.UsrHash == updatetest.UsrHash(inst):
		default:
			out = append(out, fmt.Sprintf("%s: default %q is %+v, not N-1 on the booted slot nor a whole, counted N+1 (slot holds %q)", w, v.esp.Default, def, v.slots[def.Slot]))
		}
		for id, e := range v.esp.Entries {
			if e.Tries == Blessed && v.slots[e.Slot] != e.UsrHash {
				out = append(out, fmt.Sprintf("%s: blessed entry %q points at slot %s, which holds %q, not %q", w, id, e.Slot, v.slots[e.Slot], e.UsrHash))
			}
			if e.UsrHash == want && e.Tries <= 0 {
				out = append(out, fmt.Sprintf("%s: N+1's entry %q has no try counter", w, id))
			}
		}
	}
	return out
}

// finished checks a completed Install on the synced view: N+1 is on slot b
// and its counted entry is the next boot, N is gone from the boot menu,
// and N-1 still boots from the intact slot a.
func finished(d *Disk, want, at string) []string {
	out := intact(d, at)
	v := d.views()[0]
	if got := v.slots["b"]; got != want {
		out = append(out, fmt.Sprintf("%s: slot b holds %q, not N+1", at, got))
	}
	def := v.esp.Entries[v.esp.Default]
	if def.Slot != "b" || def.UsrHash != want || def.Tries <= 0 {
		out = append(out, fmt.Sprintf("%s: next boot %q is %+v, not N+1 counted on slot b", at, v.esp.Default, def))
	}
	booted := false
	for id, e := range v.esp.Entries {
		switch {
		case e.UsrHash == updatetest.UsrHash(inst):
			out = append(out, fmt.Sprintf("%s: N's entry %q is still in the boot menu", at, id))
		case e.Slot == "a" && e.UsrHash == updatetest.UsrHash(prev) && e.Tries == Blessed:
			booted = true
		}
	}
	if !booted {
		out = append(out, at+": N-1's blessed entry on slot a is gone")
	}
	return out
}

// intact checks the booted slot was never written.
func intact(d *Disk, at string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.touched[d.booted] || d.slots[d.booted].data != updatetest.UsrHash(prev) {
		return []string{fmt.Sprintf("%s: the booted slot %s was written", at, d.booted)}
	}
	return nil
}
