package run

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ghbmrk/agentos/broker/clerk"
)

// The Secrets file and its temporary, inside the clerk's own directory.
const (
	secretsName = "secrets"
	maxSecrets  = 1 << 20
)

// ErrOldFormat refuses the at-rest form written before slot kinds, a JSON map
// of slot to blob. Nothing in that form was written outside tests, so it is
// refused, never migrated (clerk ASSUMPTIONS MIG-4-exit-e, #2643 d).
var ErrOldFormat = errors.New("run: secrets file is in the old slot-to-blob form; refused")

// errSecretsTooLarge refuses a Secrets file past maxSecrets, at open and at
// every write.
var errSecretsTooLarge = errors.New("run: secrets file too large")

// OpenSecrets opens a clerk's Secrets from dir, the clerk's own directory, and
// makes every later Put durable in it (CLK-1, STO-2). dir and the file in it
// must belong to this process's uid and be closed to every other uid, so
// another clerk's process cannot open them. A missing file is an empty store.
// Nothing here migrates or repairs: a form that does not load is an error.
func OpenSecrets(dir string, s clerk.Sealer) (*clerk.Secrets, error) {
	if err := private(dir, true); err != nil {
		return nil, err
	}
	sec := clerk.NewSecrets(s, func(b []byte) error {
		// A form the next open would refuse is never written: the write
		// fails and the store keeps its last form (#2738 Security 2).
		if len(b) > maxSecrets {
			return errSecretsTooLarge
		}
		return writeAtomic(dir, secretsName, b, nil)
	})
	f, err := os.OpenFile(filepath.Join(dir, secretsName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return sec, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := privateFile(f); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSecrets+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecrets {
		return nil, errSecretsTooLarge
	}
	if old(b) {
		return nil, ErrOldFormat
	}
	if err := sec.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("run: secrets file does not load: %w", err)
	}
	return sec, nil
}

// old reports the slot-to-blob form: a slot whose value is a string.
func old(b []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return false
	}
	for _, v := range m {
		if len(v) > 0 && v[0] == '"' {
			return true
		}
	}
	return false
}

// private checks that path is this uid's own, open to no other uid, and not a
// symlink.
func private(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return ownOnly(path, fi, dir)
}

func privateFile(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return ownOnly(f.Name(), fi, false)
}

func ownOnly(path string, fi os.FileInfo, dir bool) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok:
		return fmt.Errorf("run: %s: no owner", path)
	case dir && !fi.IsDir(), !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("run: %s: not a plain %s", path, map[bool]string{true: "directory", false: "file"}[dir])
	case int(st.Uid) != os.Geteuid():
		return fmt.Errorf("run: %s: owned by uid %d, not this clerk's", path, st.Uid)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("run: %s: open to other uids (%v)", path, fi.Mode().Perm())
	}
	return nil
}

// writeAtomic replaces the file name in dir with b so that a crash at any
// point leaves one whole form, the old or the new (#2643 c): write name.tmp,
// fsync it, rename it over the old one, fsync the directory. A temporary left
// by a crash is never read and is replaced here. stop, for tests only, ends
// the write after step i as a crash would; nil runs every step.
func writeAtomic(dir, name string, b []byte, stop func(i int) bool) error {
	tmp, dst := filepath.Join(dir, name+".tmp"), filepath.Join(dir, name)
	var f *os.File
	steps := []func() error{
		func() error {
			if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			var err error
			f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
			return err
		},
		func() error { _, err := f.Write(b); return err },
		func() error { return f.Sync() },
		func() error { return f.Close() },
		func() error { return os.Rename(tmp, dst) }, // durable:exempt lifecycle:exempt durable is old core (tools/old_core.txt), so the new core cannot list here; this is sealed content, not a lifecycle, and the next step syncs the directory
		func() error {
			if err := syncDir(dir); err != nil {
				return fmt.Errorf("%w: %w", errUnsynced, err)
			}
			return nil
		},
	}
	for i, step := range steps {
		if err := step(); err != nil {
			if f != nil && i < 3 {
				f.Close()
			}
			return err
		}
		if stop != nil && stop(i) {
			if f != nil && i < 3 {
				f.Close()
			}
			return errStopped
		}
	}
	return nil
}

var errStopped = errors.New("run: write stopped")

// errUnsynced is a write whose rename succeeded but whose directory sync
// failed: the new form is in place, and may or may not survive a crash, so
// the write neither failed nor took effect for certain (#2742 item 7).
var errUnsynced = errors.New("run: written, but the directory sync failed")

// syncDir syncs dir; a variable so a test can fail it.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
