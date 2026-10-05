package hint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// Outcome is what happened to one hint, or to an owner decision on one.
type Outcome string

const (
	Queued     Outcome = "queued"      // waiting for the next daily batch
	Asked      Outcome = "asked"       // waiting for the owner (policy "ask")
	Approved   Outcome = "approved"    // the owner approved asked hint Ref; it is queued
	Declined   Outcome = "declined"    // the owner declined asked hint Ref
	Withheld   Outcome = "withheld"    // policy "never"
	Duplicate  Outcome = "duplicate"   // the same hint is waiting, or was queued or asked today
	OverLimit  Outcome = "over_limit"  // that class's waiting queue was full; dropped
	Refused    Outcome = "refused"     // failed the schema; no content recorded
	Forwarded  Outcome = "forwarded"   // queued hint Ref is in the batch being sent
	SendFailed Outcome = "send_failed" // the send for Forwarded record Ref failed; it did not cross
)

// Record is one log line. Day is the UTC date; nothing finer is kept. A
// Refused record carries no kind or fields. Ref links a record to the one
// it acts on, as each Outcome says.
type Record struct {
	Seq      int               `json:"seq"`
	Day      string            `json:"day"`
	Outcome  Outcome           `json:"outcome"`
	Category string            `json:"category,omitempty"`
	Kind     string            `json:"kind,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	Ref      int               `json:"ref,omitempty"`
}

// Log is the owner-visible hint log (OSS-1, OSS-7).
type Log interface {
	Append(Record) error
	List() ([]Record, error)
}

// MemLog is an in-memory Log, for tests.
type MemLog struct {
	mu sync.Mutex
	rs []Record
}

func (l *MemLog) Append(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rs = append(l.rs, r)
	return nil
}

func (l *MemLog) List() ([]Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Record(nil), l.rs...), nil
}

// FileLog appends one JSON line per record and syncs each write.
type FileLog struct {
	mu       sync.Mutex
	path     string
	repaired bool
}

// OpenFileLog opens or creates the log at path, readable by the owner only.
// A last line cut off by a crash mid-write is removed, since a record is
// written before what it describes, so nothing it described happened;
// Repaired reports that. Damage anywhere else is an error.
func OpenFileLog(path string) (*FileLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	l := &FileLog{path: path}
	if n := len(data); n > 0 && data[n-1] != '\n' {
		if err := f.Truncate(int64(bytes.LastIndexByte(data, '\n') + 1)); err != nil {
			return nil, err
		}
		if err := f.Sync(); err != nil {
			return nil, err
		}
		l.repaired = true
	}
	if _, err := l.List(); err != nil {
		return nil, err
	}
	return l, nil
}

// Repaired reports whether opening removed a torn last line.
func (l *FileLog) Repaired() bool { return l.repaired }

func (l *FileLog) Append(r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (l *FileLog) List() ([]Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rs []Record
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("hint log %s line %d: %v", l.path, n, err)
		}
		rs = append(rs, r)
	}
	return rs, sc.Err()
}
