package apnet

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ghbmrk/agentos/broker/durable"
)

// UpFailuresName is agentos-ap's count of consecutive failures to bring
// the access point up on the card's network (#1525, CH-12), kept beside
// the network file (Path), root-only 0600. agentosd reads it and texts
// the owner once per version of the network when it reaches
// UpFailureBound.
const UpFailuresName = "ap-up-failures.json"

// UpFailureBound is how many consecutive failures, each a restart of
// agentos-ap (its unit waits 5 s), make a problem worth a text.
const UpFailureBound = 3

// maxUpFailures bounds what is read of the record.
const maxUpFailures = 1 << 10

// UpFailures is the record: which version of the network file failed
// (NetworkID), never its password (ARC-1), and how many times in a row.
type UpFailures struct {
	Network string `json:"network"`
	Count   int    `json:"count"`
}

// UpFailuresPath is the record's path for the network file at apNet.
func UpFailuresPath(apNet string) string {
	return filepath.Join(filepath.Dir(apNet), UpFailuresName)
}

// NetworkID names the version of the network file at apNet without
// reading it: its modification time, to the nanosecond, and size.
// Every rewrite is a rename of a newly written file (durable.WriteFile),
// so each rotation gets a new one. No inode: the control path may not
// import syscall (ARC-2).
func NetworkID(apNet string) (string, error) {
	fi, err := os.Stat(apNet)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%d", fi.ModTime().UnixNano(), fi.Size()), nil
}

// RecordUpFailure counts one more failure for the network file's current
// version, starting again at one for a new version, and returns the
// record.
func RecordUpFailure(apNet string) (UpFailures, error) {
	id, err := NetworkID(apNet)
	if err != nil {
		return UpFailures{}, fmt.Errorf("card network: %w", err)
	}
	f, err := ReadUpFailures(apNet)
	if err != nil || f.Network != id {
		f = UpFailures{Network: id}
	}
	f.Count++
	b, err := json.Marshal(f)
	if err != nil {
		return UpFailures{}, err
	}
	if err := durable.WriteFile(UpFailuresPath(apNet), b, 0o600); err != nil && !errors.Is(err, durable.ErrDirSync) {
		return UpFailures{}, err
	}
	return f, nil
}

// ClearUpFailures drops the record once the network is served.
func ClearUpFailures(apNet string) error {
	if err := os.Remove(UpFailuresPath(apNet)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ReadUpFailures reads the record; none is a zero count.
func ReadUpFailures(apNet string) (UpFailures, error) {
	fh, err := os.Open(UpFailuresPath(apNet))
	if errors.Is(err, os.ErrNotExist) {
		return UpFailures{}, nil
	}
	if err != nil {
		return UpFailures{}, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxUpFailures+1))
	if err != nil {
		return UpFailures{}, err
	}
	if len(b) > maxUpFailures {
		return UpFailures{}, errors.New("up failures: too long")
	}
	var f UpFailures
	if err := json.Unmarshal(b, &f); err != nil {
		return UpFailures{}, fmt.Errorf("up failures: %w", err)
	}
	return f, nil
}
