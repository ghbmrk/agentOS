// Package activatortest is the acceptance check for an apply.Activator's
// Install after an other-root boot (broker/apply ASSUMPTIONS A12(3), (4)):
// booted on N-1 with N blessed and default, Install of N+1 overwrites N's
// slot, never writes the booted slot, and leaves N-1 the effective default
// boot if it is cut at any step, including after the slot writes begin.
//
// The activator under test runs over a Disk: a model of the ESP, the
// loader's EFI variables and the two /usr slots, each a data and a verity
// partition with GPT UUIDs and a label, that can be cut (a power cut)
// before any write. A real activator is written against an interface with
// Disk's method set (bootab.Disk), so the same check runs on it; its
// production adapter maps each method to the ESP file, EFI variable,
// partition or veritysetup call it names. A slot is whole for a root hash
// only when both partitions hold that release's image bytes and their
// UUIDs are the ones the initrd looks for (#2094).
package activatortest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/apply"
	"github.com/ghbmrk/agentos/broker/apply/bootab"
	"github.com/ghbmrk/agentos/broker/update"
	"github.com/ghbmrk/agentos/broker/update/updatetest"
)

// ErrCut is every Disk call's answer once the power is cut.
var ErrCut = errors.New("activatortest: power cut")

// Blessed is Entry.Tries for an entry with no try counter: it is never
// counted down, so the loader never falls back from it (A12(1)).
const Blessed = bootab.Blessed

// Entry is a boot loader entry on the ESP: the slot it boots, its
// usrhash= and its tries left (Blessed when it has no counter).
type Entry = bootab.Entry

// esp is the ESP's boot menu: its entries by ID and loader.conf's default.
type esp struct {
	Entries map[string]Entry
	Default string
}

func (e esp) clone() esp {
	return esp{Entries: maps.Clone(e.Entries), Default: e.Default}
}

// part is one partition's bytes, and whether a write since the last
// SyncPart left them torn on a cut.
type part struct {
	data  string
	dirty bool
	old   string // the bytes a cut leaves when !dirty: the last synced
}

// slot is one /usr slot: its data and verity partitions, their GPT UUIDs
// and their label. GPT writes are durable when they return.
type slot struct {
	parts        map[string]*part
	data, verity string // partition UUIDs
	label        string
}

// image is the SHA-256 of a release's two partition images.
type image struct{ data, verity [32]byte }

// Image is the data and verity partition bytes of release version in
// this check. Its root hash is updatetest.UsrHash(version).
func Image(version int64) (data, verity []byte) {
	return []byte(strings.Repeat(fmt.Sprintf("usr image %d;", version), 7)),
		[]byte(strings.Repeat(fmt.Sprintf("verity %d;", version), 3))
}

// uuids is the GPT UUID pair the initrd finds for root hash h: its first
// and last 128 bits. It is derived here on its own, not by bootab's
// PartitionUUIDs, so the check does not take the activator's word.
func uuids(h string) (data, verity string) {
	if len(h) != 64 {
		return "", ""
	}
	u := func(x string) string {
		return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
	}
	return u(h[:32]), u(h[32:])
}

// Disk is the model. Each mutating call counts one step; the cutAt'th
// step and every call after it fail with ErrCut and change nothing. ESP
// writes reach the disk only at SyncESP (a FAT ESP may also keep some
// unsynced writes, so the check judges both the synced view and the
// written one). A partition write tears the partition until SyncPart. EFI
// variables and GPT UUIDs and labels are durable when set.
type Disk struct {
	mu       sync.Mutex
	booted   string
	bootID   string
	cmdline  string
	selected string
	efi      string // LoaderEntryDefault, "" when unset
	esp      esp    // as written
	synced   esp    // as on disk at the last SyncESP
	slots    map[string]*slot
	images   map[string]image // by root hash, for VerifySlot and wholeness
	steps    int
	cutAt    int // 0: never
	cut      bool
	badSlot  bool            // VerifySlot always fails
	touched  map[string]bool // slots written
}

// NewDisk is a disk booted on slot booted, with each slot holding the
// whole release of the given root hash, and the given boot menu, all
// synced. The releases are those of the hashes in holds plus any in
// extra; each root hash h must be updatetest.UsrHash of a version.
func NewDisk(booted string, holds map[string]string, entries map[string]Entry, def string, extra ...string) *Disk {
	d := &Disk{booted: booted, slots: map[string]*slot{}, images: map[string]image{}, touched: map[string]bool{}}
	version := func(h string) int64 {
		v, err := strconv.ParseInt(h, 16, 64)
		if err != nil || updatetest.UsrHash(v) != h {
			panic(fmt.Sprintf("activatortest: %q is not updatetest.UsrHash of a version", h))
		}
		return v
	}
	for _, h := range slices.Concat(slices.Collect(maps.Values(holds)), extra) {
		data, verity := Image(version(h))
		d.images[h] = image{sha256.Sum256(data), sha256.Sum256(verity)}
	}
	for s, h := range holds {
		data, verity := Image(version(h))
		du, vu := uuids(h)
		d.slots[s] = &slot{
			parts: map[string]*part{bootab.PartUsr: {data: string(data), old: string(data)}, bootab.PartVerity: {data: string(verity), old: string(verity)}},
			data:  du, verity: vu, label: fmt.Sprintf("agentos_%d", version(h)),
		}
	}
	d.esp = esp{Entries: maps.Clone(entries), Default: def}
	d.synced = d.esp.clone()
	d.bootID = "boot-1"
	if e, ok := entries[def]; ok && e.Slot == booted {
		d.selected = def
	}
	for id, e := range entries {
		if d.selected == "" && e.Slot == booted && e.Tries == Blessed {
			d.selected = id
		}
	}
	d.cmdline = "quiet usrhash=" + holds[booted]
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

// SetBoot sets what the running boot reports: its ID, the kernel command
// line and LoaderEntrySelected.
func (d *Disk) SetBoot(id, cmdline, selected string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bootID, d.cmdline, d.selected = id, cmdline, selected
}

// BreakVerify makes every later VerifySlot fail, as veritysetup verify
// does on a slot whose bytes do not match its root hash.
func (d *Disk) BreakVerify() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.badSlot = true
}

// BootID is the running boot's ID.
func (d *Disk) BootID() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.bootID, d.read()
}

// Cmdline is the running kernel's command line.
func (d *Disk) Cmdline() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cmdline, d.read()
}

// Selected is LoaderEntrySelected.
func (d *Disk) Selected() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.selected, d.read()
}

// BootedSlot is the slot the running boot came from.
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

// Entries is the boot menu as written, and loader.conf's default.
func (d *Disk) Entries() (map[string]Entry, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return maps.Clone(d.esp.Entries), d.esp.Default, d.read()
}

// Effective is the entry the loader boots by default on the ESP as
// written: LoaderEntryDefault when it names an entry, else loader.conf's.
func (d *Disk) Effective() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return effective(d.esp, d.efi)
}

func effective(e esp, efi string) string {
	if _, ok := e.Entries[efi]; ok && efi != "" {
		return efi
	}
	return e.Default
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

// SetDefault sets loader.conf's default. A LoaderEntryDefault naming an
// entry in the menu overrides it, as in systemd-boot, so an activator
// that needs id to be the effective boot either sets that variable to id
// or clears it (#2094 point 2).
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

// EFIDefault is LoaderEntryDefault, "" when unset.
func (d *Disk) EFIDefault() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.efi, d.read()
}

// SetEFIDefault sets LoaderEntryDefault; "" deletes it.
func (d *Disk) SetEFIDefault(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.step(); err != nil {
		return err
	}
	d.efi = id
	return nil
}

func (d *Disk) part(s, p string) (*part, error) {
	sl, ok := d.slots[s]
	if !ok {
		return nil, fmt.Errorf("activatortest: no slot %q", s)
	}
	pt, ok := sl.parts[p]
	if !ok {
		return nil, fmt.Errorf("activatortest: slot %s has no partition %q", s, p)
	}
	return pt, nil
}

// TruncatePart empties slot s's partition p for a new image; it tears p
// until SyncPart.
func (d *Disk) TruncatePart(s, p string) error {
	return d.writePart(s, p, func(pt *part) { pt.data = "" })
}

// WritePart appends b to slot s's partition p; it tears p until SyncPart.
func (d *Disk) WritePart(s, p string, b []byte) error {
	return d.writePart(s, p, func(pt *part) { pt.data += string(b) })
}

func (d *Disk) writePart(s, p string, f func(*part)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	pt, err := d.part(s, p)
	if err != nil {
		return err
	}
	if err := d.step(); err != nil {
		return err
	}
	d.touched[s] = true
	pt.dirty = true
	f(pt)
	return nil
}

// SyncPart makes slot s's partition p's writes durable.
func (d *Disk) SyncPart(s, p string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	pt, err := d.part(s, p)
	if err != nil {
		return err
	}
	if err := d.step(); err != nil {
		return err
	}
	pt.dirty, pt.old = false, pt.data
	return nil
}

// SetSlotUUIDs sets slot s's partition UUIDs.
func (d *Disk) SetSlotUUIDs(s, data, verity string) error {
	return d.setSlot(s, func(sl *slot) { sl.data, sl.verity = data, verity })
}

// SetSlotLabel sets slot s's partition label.
func (d *Disk) SetSlotLabel(s, label string) error {
	return d.setSlot(s, func(sl *slot) { sl.label = label })
}

func (d *Disk) setSlot(s string, f func(*slot)) error {
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
	f(sl)
	return nil
}

// VerifySlot checks slot s's partitions, as written, against root hash h:
// both hold the image of the release with that root hash.
func (d *Disk) VerifySlot(s, h string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.read(); err != nil {
		return err
	}
	sl, ok := d.slots[s]
	if !ok {
		return fmt.Errorf("activatortest: no slot %q", s)
	}
	im, ok := d.images[h]
	if d.badSlot || !ok || sha256.Sum256([]byte(sl.parts[bootab.PartUsr].data)) != im.data || sha256.Sum256([]byte(sl.parts[bootab.PartVerity].data)) != im.verity {
		return fmt.Errorf("activatortest: slot %s does not verify against %s", s, h)
	}
	return nil
}

// ReadSlot is slot s's partition p's bytes as written.
func (d *Disk) ReadSlot(s, p string) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	pt, err := d.part(s, p)
	if err != nil {
		return "", err
	}
	return pt.data, d.read()
}

// Touched reports whether any partition, UUID or label of slot s was
// written.
func (d *Disk) Touched(s string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.touched[s]
}

// torn marks a partition's bytes after a cut mid-write.
const torn = "\x00torn"

// vslot is a slot as a boot after a cut finds it.
type vslot struct {
	data, verity string // partition bytes
	uuidData     string
	uuidVerity   string
	label        string
}

// view is what a boot after a cut finds: the boot menu, LoaderEntryDefault
// and the slots.
type view struct {
	name  string
	esp   esp
	efi   string
	slots map[string]vslot
}

// views are the states a cut can leave: the ESP as last synced and as
// written, each with the slots as they reach the disk.
func (d *Disk) views() []view {
	d.mu.Lock()
	defer d.mu.Unlock()
	slots := map[string]vslot{}
	for s, sl := range d.slots {
		at := func(p string) string {
			if pt := sl.parts[p]; !pt.dirty {
				return pt.old
			}
			return torn
		}
		slots[s] = vslot{at(bootab.PartUsr), at(bootab.PartVerity), sl.data, sl.verity, sl.label}
	}
	return []view{
		{"synced ESP", d.synced.clone(), d.efi, slots},
		{"written ESP", d.esp.clone(), d.efi, maps.Clone(slots)},
	}
}

// holds reports whether slot s in v is whole for root hash h: both
// partitions hash to that release's images, and the UUIDs are the ones
// the initrd finds for h (#2094 points 1 and 3).
func (d *Disk) holds(v view, s, h string) bool {
	im, ok := d.images[h]
	sl, ok2 := v.slots[s]
	du, vu := uuids(h)
	return ok && ok2 && sha256.Sum256([]byte(sl.data)) == im.data && sha256.Sum256([]byte(sl.verity)) == im.verity &&
		sl.uuidData == du && sl.uuidVerity == vu
}

// reboot is the disk a boot after the cut finds, on the synced view, booted
// on the same slot.
func (d *Disk) reboot() *Disk {
	v := d.views()[0]
	r := &Disk{booted: d.booted, bootID: "boot-2", cmdline: d.cmdline, selected: d.selected, efi: v.efi,
		esp: v.esp.clone(), synced: v.esp.clone(), slots: map[string]*slot{}, images: maps.Clone(d.images), touched: map[string]bool{}}
	for s, sl := range v.slots {
		r.slots[s] = &slot{
			parts: map[string]*part{bootab.PartUsr: {data: sl.data, old: sl.data}, bootab.PartVerity: {data: sl.verity, old: sl.verity}},
			data:  sl.uuidData, verity: sl.uuidVerity, label: sl.label,
		}
	}
	return r
}

// Releases N-1, N and N+1 of the check.
const (
	prev = 1 // N-1: booted on slot a, blessed
	inst = 2 // N: on slot b, blessed and the default (installed_other_root)
	next = 3 // N+1: the release Install writes
)

// Scenario is the A12 other-root disk: booted on slot a running N-1, with
// N blessed and default on slot b, and no LoaderEntryDefault.
func Scenario() *Disk { return scenario("") }

// scenario is Scenario with LoaderEntryDefault set to efi.
func scenario(efi string) *Disk {
	d := NewDisk("a",
		map[string]string{"a": updatetest.UsrHash(prev), "b": updatetest.UsrHash(inst)},
		map[string]Entry{
			"agentos-1": {Slot: "a", UsrHash: updatetest.UsrHash(prev), Tries: Blessed},
			"agentos-2": {Slot: "b", UsrHash: updatetest.UsrHash(inst), Tries: Blessed},
		}, "agentos-2", updatetest.UsrHash(next))
	d.efi = efi
	return d
}

// pins are the LoaderEntryDefault values the check runs under: unset, the
// owner's `d` pin on N-1 (#2094 point 2) and on N.
var pins = []string{"", "agentos-1", "agentos-2"}

// NextRelease is N+1 as the box's store checked it, with the source that
// serves its files: Image(3) as host-image/usr.img and usr.verity, root
// hash updatetest.UsrHash(3).
func NextRelease(t testing.TB) (*update.Verified, update.Source) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, pk, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		return pub, pk
	}
	dir := t.TempDir()
	p1, k1 := key()
	p2, k2 := key()
	sp, sk := key()
	tp, tk := key()
	repo, err := update.Init(filepath.Join(dir, "repo"), update.RootConfig{
		Root: []ed25519.PublicKey{p1, p2}, Targets: []ed25519.PublicKey{p1, p2},
		Snapshot: []ed25519.PublicKey{sp}, Timestamp: []ed25519.PublicKey{tp},
		RootThreshold: 2, TargetsThreshold: 2})
	must(err)
	for _, k := range []ed25519.PrivateKey{k1, k2} {
		must(repo.Sign("root", k))
	}
	data, verity := Image(next)
	local := map[string]string{bootab.DataFile: filepath.Join(dir, "usr.img"), bootab.VerityFile: filepath.Join(dir, "usr.verity")}
	must(os.WriteFile(local[bootab.DataFile], data, 0o600))
	must(os.WriteFile(local[bootab.VerityFile], verity, 0o600))
	must(repo.AddRelease(update.Manifest{Version: next, Channel: update.ChannelStable, UsrRootHash: updatetest.UsrHash(next),
		Files: []string{bootab.DataFile, bootab.VerityFile}}, local))
	for _, k := range []ed25519.PrivateKey{k1, k2} {
		must(repo.Sign("targets", k))
	}
	must(repo.Publish(sk, tk))
	root, err := os.ReadFile(filepath.Join(repo.Dir, "metadata", "1.root.json"))
	must(err)
	st, err := update.InitStore(filepath.Join(dir, "box"), root, inst)
	must(err)
	src := update.DirSource(repo.Dir)
	res, err := st.Check(src, update.Options{})
	must(err)
	if res.Release == nil {
		t.Fatal("activatortest: no release")
	}
	return res.Release, src
}

// maxSteps bounds the cut sweep, so an activator that never finishes fails.
const maxSteps = 2000

// Violations runs Install of N+1 over the Scenario disk, under each
// LoaderEntryDefault pin, cut before each of its steps in turn and once
// uncut, and returns every way it breaks A12(3) or (4). After each cut it
// also reboots onto the synced view and runs Install again uncut, which
// must finish as an uncut run does.
func Violations(t testing.TB, newActivator func(*Disk, update.Source) apply.Activator) []string {
	t.Helper()
	rel, src := NextRelease(t)
	var out []string
	for _, pin := range pins {
		out = append(out, violations(t, rel, src, pin, newActivator)...)
	}
	return out
}

func violations(t testing.TB, rel *update.Verified, src update.Source, pin string, newActivator func(*Disk, update.Source) apply.Activator) []string {
	m, err := rel.Manifest()
	if err != nil {
		return []string{fmt.Sprintf("release: %v", err)}
	}
	want := m.UsrRootHash
	var out []string
	for k := 1; k <= maxSteps; k++ {
		d := scenario(pin)
		d.cutAt = k
		err := newActivator(d, src).Install(t.Context(), rel)
		if !d.cut {
			at := fmt.Sprintf("pin %q, uncut", pin)
			if err != nil {
				return append(out, fmt.Sprintf("%s Install: %v", at, err))
			}
			return append(out, finished(d, want, at)...)
		}
		at := fmt.Sprintf("pin %q, cut at step %d", pin, k)
		if err == nil {
			out = append(out, at+": Install returned nil after the cut")
		}
		out = append(out, partway(d, want, at)...)
		r := d.reboot()
		r.cutAt = maxSteps
		if err := newActivator(r, src).Install(t.Context(), rel); r.cut {
			return append(out, fmt.Sprintf("%s, Install again after reboot did not finish in %d steps", at, maxSteps))
		} else if err != nil {
			out = append(out, fmt.Sprintf("%s, Install again after reboot: %v", at, err))
			continue
		}
		out = append(out, finished(r, want, at+", Install again after reboot")...)
	}
	return append(out, fmt.Sprintf("pin %q: Install did not finish in %d steps", pin, maxSteps))
}

// Check fails t with each of Violations.
func Check(t *testing.T, newActivator func(*Disk, update.Source) apply.Activator) {
	t.Helper()
	for _, v := range Violations(t, newActivator) {
		t.Error(v)
	}
}

// partway checks a cut Install: the booted slot is intact, and every view
// boots a whole image by default: the effective default is N-1's entry, or
// an entry whose slot is whole for it (N before any byte of its slot is
// written, N+1 once it is written, synced and given its UUIDs, and only
// counted, so a bad N+1 falls back); no blessed entry points at a slot
// that is not whole for it; and no N+1 entry is without a try counter.
// Once a byte of N's slot is written, only N-1 is left to be the default
// until N+1 is whole.
func partway(d *Disk, want, at string) []string {
	out := intact(d, at)
	for _, v := range d.views() {
		w := at + ", " + v.name
		id := effective(v.esp, v.efi)
		def, ok := v.esp.Entries[id]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: default %q is not in the boot menu", w, id))
		case def.Slot == "a" && def.UsrHash == updatetest.UsrHash(prev):
		case def.UsrHash == want && def.Tries > 0 && d.holds(v, def.Slot, want):
		case def.UsrHash == updatetest.UsrHash(inst) && d.holds(v, def.Slot, def.UsrHash):
		default:
			out = append(out, fmt.Sprintf("%s: default %q is %+v, not N-1 on the booted slot nor a whole, counted N+1 (slot %+v)", w, id, def, v.slots[def.Slot]))
		}
		for id, e := range v.esp.Entries {
			if e.Tries == Blessed && !d.holds(v, e.Slot, e.UsrHash) {
				out = append(out, fmt.Sprintf("%s: blessed entry %q points at slot %s, which is not whole for %s", w, id, e.Slot, e.UsrHash))
			}
			if e.UsrHash == want && e.Tries <= 0 {
				out = append(out, fmt.Sprintf("%s: N+1's entry %q has no try counter", w, id))
			}
		}
	}
	return out
}

// finished checks a completed Install on the synced view: N+1 is whole on
// slot b, labelled for it, and its counted entry is the effective next
// boot; N is gone from the boot menu, and N-1 still boots from the intact
// slot a.
func finished(d *Disk, want, at string) []string {
	out := intact(d, at)
	v := d.views()[0]
	if !d.holds(v, "b", want) {
		out = append(out, fmt.Sprintf("%s: slot b is not whole for N+1: %+v", at, v.slots["b"]))
	}
	if got := v.slots["b"].label; got != fmt.Sprintf("agentos_%d", next) {
		out = append(out, fmt.Sprintf("%s: slot b is labelled %q", at, got))
	}
	id := effective(v.esp, v.efi)
	def := v.esp.Entries[id]
	if def.Slot != "b" || def.UsrHash != want || def.Tries <= 0 {
		out = append(out, fmt.Sprintf("%s: effective next boot %q is %+v, not N+1 counted on slot b", at, id, def))
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
	data, _ := Image(prev)
	if d.touched[d.booted] || d.slots[d.booted].parts[bootab.PartUsr].data != string(data) {
		return []string{fmt.Sprintf("%s: the booted slot %s was written", at, d.booted)}
	}
	return nil
}
