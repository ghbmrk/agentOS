package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ghbmrk/agentos/broker/camnode"
	"github.com/ghbmrk/agentos/broker/camwire"
)

// slots are the board's A/B root slots on a Raspberry Pi CM4 class board
// with tryboot (camnode ASSUMPTIONS CAM-bin-2): autoboot.txt on the boot partition
// names the default boot partition under [all] and the one-shot one under
// [tryboot]; each slot's signed manifest is a file on the data partition.
// The data partition is untrusted storage: the node verifies the running
// slot's manifest, and hashes the slot against it, at every start.
type slots struct {
	autoboot  string
	manifests string
	dev       [2]string
	part      [2]int
	run       int // the running slot: 0 (A) or 1 (B)
}

var errSlot = errors.New("running partition is neither slot")

func newSlots(autoboot, manifests string, dev [2]string, part [2]int, running int) (*slots, error) {
	s := &slots{autoboot: autoboot, manifests: manifests, dev: dev, part: part}
	switch running {
	case part[0]:
		s.run = 0
	case part[1]:
		s.run = 1
	default:
		return nil, errSlot
	}
	return s, nil
}

func (s *slots) manifest(i int) string {
	return filepath.Join(s.manifests, string(rune('a'+i))+".manifest")
}

// running is the running slot's signed manifest (nil: none, the factory
// image) and the SHA-256 of the image it names, read back from the slot.
// A manifest that does not parse is refused here; camnode verifies the
// rest.
func (s *slots) running() ([]byte, [32]byte, error) {
	var sum [32]byte
	p, err := os.ReadFile(s.manifest(s.run))
	if errors.Is(err, os.ErrNotExist) {
		return nil, sum, nil
	}
	if err != nil {
		return nil, sum, err
	}
	_, m, err := camwire.ParseSignedManifest(p)
	if err != nil {
		return nil, sum, err
	}
	f, err := os.Open(s.dev[s.run])
	if err != nil {
		return nil, sum, err
	}
	defer f.Close()
	h := sha256.New()
	if n, err := io.Copy(h, io.LimitReader(f, int64(m.Size))); err != nil || uint64(n) != m.Size {
		return nil, sum, errors.New("running slot is shorter than its manifest")
	}
	copy(sum[:], h.Sum(nil))
	return p, sum, nil
}

// Stage drops the inactive slot's manifest, so a half-written slot never
// has one, and opens its device for writing.
func (s *slots) Stage(size uint64) (camnode.Staged, error) {
	o := 1 - s.run
	if err := os.Remove(s.manifest(o)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(s.dev[o], os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	end, err := f.Seek(0, io.SeekEnd)
	if err != nil || uint64(end) < size {
		f.Close()
		return nil, errors.New("image larger than the inactive slot")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return &staged{s: s, f: f, slot: o}, nil
}

// MarkGood makes the running slot the default and the other the one-shot.
func (s *slots) MarkGood() error { return s.writeAutoboot() }

// Reboot restarts into the one-shot slot (sys_linux.go).
func (s *slots) Reboot() error { return reboot() }

// writeAutoboot writes autoboot.txt naming the running slot as the default
// and the other as the one-shot.
func (s *slots) writeAutoboot() error {
	body := fmt.Sprintf("[all]\ntryboot_a_b=1\nboot_partition=%d\n[tryboot]\nboot_partition=%d\n", s.part[s.run], s.part[1-s.run])
	return writeSynced(s.autoboot, []byte(body))
}

type staged struct {
	s    *slots
	f    *os.File
	slot int
}

func (t *staged) Write(p []byte) (int, error) { return t.f.Write(p) }

// Arm syncs the slot, stores its manifest, and leaves autoboot.txt naming
// it as the one-shot (Reboot then asks for it).
func (t *staged) Arm(manifest []byte) error {
	if err := t.f.Sync(); err != nil {
		t.f.Close()
		return err
	}
	if err := t.f.Close(); err != nil {
		return err
	}
	if err := writeSynced(t.s.manifest(t.slot), manifest); err != nil {
		return err
	}
	return t.s.writeAutoboot()
}

func (t *staged) Abort() error {
	t.f.Close()
	if err := os.Remove(t.s.manifest(t.slot)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// writeSynced writes path whole: a temporary file beside it, synced,
// renamed over it, then the directory synced.
func writeSynced(path string, p []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(p); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil { // durable:exempt lifecycle:exempt durable is old core (tools/old_core.txt), so the new core cannot list here; a boot selector and a slot's signed manifest, not a lifecycle; the file and directory are synced here
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
