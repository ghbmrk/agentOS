// Package bootab is the box's apply.Activator: it installs a verified
// release into the /usr slot not booted, and boots it next through
// systemd-boot's boot counting (UPD-1, UPD-1a; broker/apply ASSUMPTIONS
// A4, A12).
//
// It is written against Disk, the ESP, EFI variable and slot operations
// it needs, so activatortest.Check runs on it over a model that can be
// cut before any write. The production Disk maps each method to the ESP
// file, efivarfs variable, GPT partition or veritysetup call it names.
// Blessing is systemd-bless-boot's (A12(1)): this package never renames
// an entry to bless it.
//
// The control path never imports this package (ARC-2); only the process
// that hosts the applier links it.
package bootab

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/apply"
	"github.com/ghbmrk/agentos/broker/update"
)

// Blessed is Entry.Tries for an entry with no try counter: the loader
// never counts it down, so it never falls back from it (A12(1)).
const Blessed = -1

// Tries is the try counter Install gives a new entry (agentos_<v>+3.conf).
const Tries = 3

// The two partitions of a slot.
const (
	PartUsr    = "usr"
	PartVerity = "usr-verity"
)

// EmptyLabel is the partition label of a slot whose bytes are being
// replaced, as systemd-sysupdate marks a slot it is writing.
const EmptyLabel = "_empty"

// The release files a slot is written from.
const (
	DataFile   = "host-image/usr.img"
	VerityFile = "host-image/usr.verity"
)

// Entry is a boot loader entry on the ESP: the slot it boots, its
// usrhash= and its tries left (Blessed when it has no counter).
type Entry struct {
	Slot    string
	UsrHash string
	Tries   int
}

// Disk is what the activator reads and writes. Every write may be the
// last before a power cut. ESP writes are durable only after SyncESP; a
// partition write is durable only after SyncPart; EFI variable, GPT UUID
// and label writes are durable when they return.
type Disk interface {
	// BootID is this boot's ID (/proc/sys/kernel/random/boot_id).
	BootID() (string, error)
	// Cmdline is the running kernel's command line (/proc/cmdline).
	Cmdline() (string, error)
	// Selected is the entry the loader booted (LoaderEntrySelected).
	Selected() (string, error)
	// BootedSlot is the slot the running /usr comes from.
	BootedSlot() (string, error)
	// Slots lists the slot names.
	Slots() ([]string, error)
	// Entries is the boot menu as written, and loader.conf's default.
	Entries() (map[string]Entry, string, error)
	WriteEntry(id string, e Entry) error
	RemoveEntry(id string) error
	// SetDefault sets loader.conf's default. An EFI LoaderEntryDefault
	// that names an entry in the menu overrides it, as systemd-boot
	// does, so a caller that needs id to be the effective boot also
	// clears that variable (or sets it to id).
	SetDefault(id string) error
	SyncESP() error
	// EFIDefault is LoaderEntryDefault, "" when unset (the owner's `d`
	// pin in the boot menu).
	EFIDefault() (string, error)
	// SetEFIDefault sets LoaderEntryDefault; "" deletes it.
	SetEFIDefault(id string) error
	// TruncatePart starts slot s's partition part afresh; WritePart
	// appends to it; SyncPart makes its writes durable.
	TruncatePart(s, part string) error
	WritePart(s, part string, p []byte) error
	SyncPart(s, part string) error
	// SetSlotUUIDs sets the GPT partition UUIDs of slot s's data and
	// verity partitions.
	SetSlotUUIDs(s, data, verity string) error
	// SetSlotLabel sets both partitions' GPT label.
	SetSlotLabel(s, label string) error
	// VerifySlot checks slot s's data against its verity partition and
	// rootHash (veritysetup verify).
	VerifySlot(s, rootHash string) error
}

// Config is what the activator needs beyond its Disk.
type Config struct {
	// Source is where Install fetches the release's files: the source
	// that checked it. Every file is read only through v.Fetch (A4).
	Source update.Source
	// Staging holds a private directory per Install for the fetched
	// files. It must be a real directory, not a symlink, and not group-
	// or world-writable.
	Staging string
	// Restart boots the next entry (systemctl reboot).
	Restart func(context.Context) error
}

type activator struct {
	d Disk
	c Config
}

// New is the activator over d.
func New(d Disk, c Config) apply.Activator { return &activator{d: d, c: c} }

// PartitionUUIDs are the GPT UUIDs systemd's initrd looks for given
// usrhash=rootHash: the first 128 bits of the root hash for the data
// partition and the last 128 for verity (Discoverable Partitions
// Specification; repart Verity=).
func PartitionUUIDs(rootHash string) (data, verity string, err error) {
	b, err := hex.DecodeString(rootHash)
	if err != nil || len(b) != 32 {
		return "", "", fmt.Errorf("bootab: root hash %q is not 64 hex digits", rootHash)
	}
	u := func(b []byte) string {
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	}
	return u(b[:16]), u(b[16:]), nil
}

// EntryID is the ID of release version's boot entry; its file on the ESP
// carries the try counter (agentos_<version>+3.conf).
func EntryID(version int64) string { return fmt.Sprintf("agentos_%d.conf", version) }

// Label is the GPT label of a slot holding release version.
func Label(version int64) string { return fmt.Sprintf("agentos_%d", version) }

// slots is the booted slot and the one Install writes: the slot not
// booted, whatever the update store holds as installed (A12(3)).
func (a *activator) slots() (booted, inactive string, err error) {
	booted, err = a.d.BootedSlot()
	if err != nil {
		return "", "", err
	}
	all, err := a.d.Slots()
	if err != nil {
		return "", "", err
	}
	var other []string
	seen := false
	for _, s := range all {
		if s == booted {
			seen = true
		} else {
			other = append(other, s)
		}
	}
	if !seen || len(other) != 1 {
		return "", "", fmt.Errorf("bootab: booted slot %q among slots %q: want it and one other", booted, all)
	}
	return booted, other[0], nil
}

// running is the blessed entry on the booted slot.
func running(es map[string]Entry, booted string) (string, error) {
	var ids []string
	for id, e := range es {
		if e.Slot == booted && e.Tries == Blessed {
			ids = append(ids, id)
		}
	}
	if len(ids) != 1 {
		return "", fmt.Errorf("bootab: %d blessed entries on the booted slot %q, want 1", len(ids), booted)
	}
	return ids[0], nil
}

// effective is the entry the loader boots by default: LoaderEntryDefault
// when it names an entry in the menu, else loader.conf's default.
func effective(es map[string]Entry, def, efi string) string {
	if _, ok := es[efi]; ok && efi != "" {
		return efi
	}
	return def
}

// makeDefault leaves id the effective default, durably: loader.conf's
// default written and synced, then a LoaderEntryDefault naming another
// entry cleared (#2094 point 2). A cut between the two leaves the old
// pin in force, which only ever names an entry that still boots whole.
func (a *activator) makeDefault(id string) error {
	if err := a.d.SetDefault(id); err != nil {
		return err
	}
	if err := a.d.SyncESP(); err != nil {
		return err
	}
	efi, err := a.d.EFIDefault()
	if err != nil {
		return err
	}
	if efi != "" && efi != id {
		return a.d.SetEFIDefault("")
	}
	return nil
}

// retire makes the running entry the effective default unless it already
// boots the booted slot, then takes every entry on slot s out of the menu,
// durably, before any byte of s is written (A12(4)). With all false
// (Abandon) it touches only counted entries on s: a blessed entry stays
// the default until an Install replaces it (A12(2)).
func (a *activator) retire(booted, s string, all bool) error {
	es, def, err := a.d.Entries()
	if err != nil {
		return err
	}
	efi, err := a.d.EFIDefault()
	if err != nil {
		return err
	}
	e, ok := es[effective(es, def, efi)]
	if all && (!ok || e.Slot != booted) || !all && ok && e.Slot == s && e.Tries != Blessed {
		id, err := running(es, booted)
		if err != nil {
			return err
		}
		if err := a.makeDefault(id); err != nil {
			return err
		}
	}
	for id, e := range es {
		if e.Slot == s && (all || e.Tries != Blessed) {
			if err := a.d.RemoveEntry(id); err != nil {
				return err
			}
		}
	}
	return a.d.SyncESP()
}

// stage fetches the slot's two files through v.Fetch into a fresh private
// directory under Staging, so a short or altered file never reaches the
// slot (A4).
func (a *activator) stage(v *update.Verified) (dir string, err error) {
	fs, err := v.Files()
	if err != nil {
		return "", err
	}
	n := 0
	for _, f := range fs {
		if f.Path == DataFile || f.Path == VerityFile {
			n++
		}
	}
	if n != 2 {
		return "", fmt.Errorf("bootab: release lacks %s or %s", DataFile, VerityFile)
	}
	if a.c.Source == nil {
		return "", errors.New("bootab: no source")
	}
	fi, err := os.Lstat(a.c.Staging)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("bootab: staging %q is not a directory only its owner writes (%v)", a.c.Staging, fi.Mode())
	}
	dir, err = os.MkdirTemp(a.c.Staging, "install-*")
	if err != nil {
		return "", err
	}
	for _, p := range []string{DataFile, VerityFile} {
		if err := v.Fetch(a.c.Source, p, filepath.Join(dir, filepath.Base(p))); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

// chunk is the size of each partition write.
const chunk = 1 << 20

// write copies a staged file, which Fetch checked against its signed
// length and hash, into slot s's partition part and syncs it.
func (a *activator) write(s, part, path string) error {
	fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer fd.Close()
	if err := a.d.TruncatePart(s, part); err != nil {
		return err
	}
	buf := make([]byte, chunk)
	for {
		k, rerr := fd.Read(buf)
		if k > 0 {
			if err := a.d.WritePart(s, part, buf[:k]); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return a.d.SyncPart(s, part)
}

// Install writes release v to the slot not booted and makes its counted
// entry the next boot (A4, A12). Nothing is written before both files are
// fetched and checked; no entry is written before the slot verifies.
func (a *activator) Install(ctx context.Context, v *update.Verified) error {
	m, err := v.Manifest()
	if err != nil {
		return err
	}
	data, verity, err := PartitionUUIDs(m.UsrRootHash)
	if err != nil {
		return err
	}
	booted, s, err := a.slots()
	if err != nil {
		return err
	}
	dir, err := a.stage(v)
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.retire(booted, s, true); err != nil {
		return err
	}
	if err := a.d.SetSlotLabel(s, EmptyLabel); err != nil {
		return err
	}
	for _, w := range []struct{ part, file string }{{PartUsr, DataFile}, {PartVerity, VerityFile}} {
		if err := a.write(s, w.part, filepath.Join(dir, filepath.Base(w.file))); err != nil {
			return err
		}
	}
	if err := a.d.VerifySlot(s, m.UsrRootHash); err != nil {
		return fmt.Errorf("bootab: slot %s does not verify against %s: %w", s, m.UsrRootHash, err)
	}
	if err := a.d.SetSlotUUIDs(s, data, verity); err != nil {
		return err
	}
	if err := a.d.SetSlotLabel(s, Label(m.Version)); err != nil {
		return err
	}
	id := EntryID(m.Version)
	if err := a.d.WriteEntry(id, Entry{Slot: s, UsrHash: m.UsrRootHash, Tries: Tries}); err != nil {
		return err
	}
	if err := a.d.SyncESP(); err != nil {
		return err
	}
	return a.makeDefault(id)
}

// Abandon makes the running entry the effective default again and takes
// the counted entries on the other slot out of the menu. It is a no-op
// when nothing was installed.
func (a *activator) Abandon(context.Context) error {
	booted, s, err := a.slots()
	if err != nil {
		return err
	}
	return a.retire(booted, s, false)
}

// Restart boots the next entry.
func (a *activator) Restart(ctx context.Context) error {
	if a.c.Restart == nil {
		return errors.New("bootab: no restart hook")
	}
	return a.c.Restart(ctx)
}

// Booted reports this boot: its ID, the usrhash= it runs and whether the
// entry the loader selected is blessed and boots that hash. An unreadable
// variable or a command line with no single usrhash= is an error.
func (a *activator) Booted(context.Context) (apply.Boot, error) {
	id, err := a.d.BootID()
	if err != nil {
		return apply.Boot{}, err
	}
	cmd, err := a.d.Cmdline()
	if err != nil {
		return apply.Boot{}, err
	}
	var hashes []string
	for _, f := range strings.Fields(cmd) {
		if h, ok := strings.CutPrefix(f, "usrhash="); ok {
			hashes = append(hashes, h)
		}
	}
	if len(hashes) != 1 {
		return apply.Boot{}, fmt.Errorf("bootab: %d usrhash= on the command line, want 1", len(hashes))
	}
	if _, _, err := PartitionUUIDs(hashes[0]); err != nil {
		return apply.Boot{}, err
	}
	sel, err := a.d.Selected()
	if err != nil {
		return apply.Boot{}, err
	}
	es, _, err := a.d.Entries()
	if err != nil {
		return apply.Boot{}, err
	}
	e, ok := es[sel]
	return apply.Boot{ID: id, UsrRootHash: hashes[0], Blessed: ok && e.Tries == Blessed && e.UsrHash == hashes[0]}, nil
}
