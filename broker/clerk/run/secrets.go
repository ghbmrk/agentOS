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
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
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
	return openSecrets(dir, s, nil)
}

// openSecrets is OpenSecrets; stop, for tests only, is every write's
// privfile.WriteAtomic stop.
func openSecrets(dir string, s clerk.Sealer, stop func(i int) bool) (*clerk.Secrets, error) {
	if err := privfile.Check(dir, true); err != nil {
		return nil, err
	}
	sec := clerk.NewSecrets(s, func(b []byte) error {
		// A form the next open would refuse is never written: the write
		// fails and the store keeps its last form (#2738 Security 2).
		if len(b) > maxSecrets {
			return errSecretsTooLarge
		}
		return privfile.WriteAtomic(dir, secretsName, b, stop)
	})
	f, err := os.OpenFile(filepath.Join(dir, secretsName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return sec, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := privfile.CheckFile(f); err != nil {
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
