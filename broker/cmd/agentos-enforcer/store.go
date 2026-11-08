package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// The enforcer's state files, each under the state directory (ASSUMPTIONS
// ENF-l-3). Every one is the enforcer's own: nothing the core sends is
// written here except through a package that checked it.
const (
	fileEnrol      = "enrol.json"    // enrol.Book: passkey, codes' verifiers, phase
	filePolicy     = "policy.json"   // policy.Engine: signed versions, steps, pending
	fileCut        = "cut.json"      // the core trip (cut.go)
	fileCert       = "page-tls.json" // the page's root and leaf (page.Cert)
	fileChannelKey = "channel.key"   // the enforcer's Ed25519 channel key
	fileCoreKey    = "core.pub"      // the kernel's channel sub-key, pinned at set-up
	fileCoreCA     = "core-ca.der"   // the core's page authority (CH-9), optional
	fileAlerts     = "alerts.jsonl"  // alert.Alerts journal
	fileHeads      = "heads.jsonl"   // heads.Store journal
)

var errStateDir = errors.New("state directory must be a directory owned by this user with no group or other access")

// checkStateDir refuses a state directory another user could read or
// replace: a symlink, one not owned by the running user, or one with any
// group or other permission bit.
func checkStateDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode()&fs.ModeSymlink != 0 || fi.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s: %w", dir, errStateDir)
	}
	return nil
}

// fileStore is a policy.Store and an enrol.Store on one file: Save
// replaces the whole file atomically (write, sync, rename, sync the
// directory), so a power loss leaves either the old state or the new one,
// never a torn one.
type fileStore struct {
	path string
	// fault is the lifecycle test's seam: a non-nil error from it fails
	// Save before any write. after fails it once the new file is in
	// place, as a failed directory sync does. Nil in production.
	fault, after func(path string) error
}

func (f fileStore) Load() ([]byte, error) {
	b, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (f fileStore) Save(b []byte) error {
	if f.fault != nil {
		if err := f.fault(f.path); err != nil {
			return err
		}
	}
	if err := writeAtomic(f.path, b); err != nil || f.after == nil {
		return err
	}
	return f.after(f.path)
}

func writeAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after the rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil { // durable:exempt lifecycle:exempt the enforcer links nothing of agentOS (brief decision 1, arc2_test.go), so it cannot use durable; this is its own write-sync-rename-sync of one state file
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// fileJournal is an alert.Journal and a heads.Journal: one append-only
// file. Append is durable when it returns; Load returns every byte
// appended, a torn last line included, for the package to cut.
type fileJournal struct{ path string }

func (j fileJournal) Load() ([]byte, error) {
	b, err := os.ReadFile(j.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (j fileJournal) Append(b []byte) error {
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (j fileJournal) Truncate(n int) error {
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Truncate(int64(n)); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
