package proc

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// Restoring a backup's content (BAK-1, LOG-4, KRN-content-backup): the
// items of each content/<store> section go back into their store
// directories before the kernel starts, and its start re-applies every
// logged erase before it serves a read (kernel.OpenContent).

var (
	// ErrRestoreNotEmpty: content is restored only onto an empty drive.
	ErrRestoreNotEmpty = errors.New("run: I restore content only into an empty content folder")
	// ErrContentSection: a content section's items are not framed whole.
	ErrContentSection = errors.New("run: a backup's content section does not hold whole items")
)

// RestoreSections reads every section of an opened content object: the
// log section to log (nil discards it), and each content/<store>
// section's items into contentDir/<store>, contentDir absent or empty.
// The items are staged beside contentDir and moved into place only once
// secs ends whole (io.EOF), so no restored item is in place before every
// section's length and sum are checked (MIG-4-recovery-a-6). On an error
// contentDir is as it was, and log holds bytes not to be trusted.
func RestoreSections(secs *backup.Sections, log io.Writer, contentDir string) error {
	if des, err := os.ReadDir(contentDir); err == nil && len(des) > 0 {
		return ErrRestoreNotEmpty
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(contentDir)
	stage, err := os.MkdirTemp(parent, ".content-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	var stores []string
	for {
		sec, r, err := secs.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if sec.Name == "log" {
			if log == nil {
				log = io.Discard
			}
			if _, err := io.Copy(log, r); err != nil {
				return err
			}
			continue
		}
		// A section name is a label (MIG-4-recovery-a-10): only a name a
		// file store takes becomes a directory.
		store, _ := strings.CutPrefix(sec.Name, "content/")
		if !ValidStoreName(store) {
			return fmt.Errorf("%w: section %q", ErrStoreName, sec.Name)
		}
		dir := filepath.Join(stage, store)
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		if err := restoreItems(r, dir); err != nil {
			return fmt.Errorf("section %s: %w", sec.Name, err)
		}
		stores = append(stores, dir)
	}
	for _, d := range append(stores, stage) {
		if err := privfile.SyncDir(d); err != nil {
			return err
		}
	}
	if err := os.Remove(contentDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(stage, contentDir); err != nil {
		return err
	}
	return privfile.SyncDir(parent)
}

// restoreItems writes each item framed in r into dir, checking its length
// and that its hash is its ciphertext's, and refusing one twice.
func restoreItems(r io.Reader, dir string) error {
	seen := map[kernel.Hash]bool{}
	for {
		var hd [itemFrame]byte
		if _, err := io.ReadFull(r, hd[:]); errors.Is(err, io.EOF) {
			return nil
		} else if errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrContentSection
		} else if err != nil {
			return err
		}
		h, n := kernel.Hash(hd[:sha256.Size]), binary.BigEndian.Uint32(hd[sha256.Size:])
		if n > maxSealed || seen[h] {
			return ErrContentSection
		}
		ct := make([]byte, n)
		if _, err := io.ReadFull(r, ct); errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ErrContentSection
		} else if err != nil {
			return err
		}
		if kernel.Hash(sha256.Sum256(ct)) != h {
			return ErrContentSection
		}
		seen[h] = true
		if err := privfile.WriteAtomic(dir, itemName(h), ct, nil); err != nil {
			return err
		}
	}
}
