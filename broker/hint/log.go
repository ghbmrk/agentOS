package hint

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Outcome is what happened to one hint, or to an owner decision on one.
type Outcome string

const (
	Forwarded  Outcome = "forwarded"   // handed to the outbox
	Asked      Outcome = "asked"       // waiting for the owner (policy "ask")
	Approved   Outcome = "approved"    // the owner approved an asked hint; it was forwarded
	Declined   Outcome = "declined"    // the owner declined an asked hint
	Withheld   Outcome = "withheld"    // policy "never"
	Duplicate  Outcome = "duplicate"   // the same hint already crossed or was asked today
	OverLimit  Outcome = "over_limit"  // today's DailyLimit was reached
	Refused    Outcome = "refused"     // failed the schema; no content recorded
	SendFailed Outcome = "send_failed" // the send for record Ref failed; it did not cross
)

// Record is one log line. Day is the UTC date; nothing finer is kept. A
// Refused record carries no kind or fields. Ref names the Asked record an
// Approved or Declined record settles, or the Forwarded or Approved record
// whose send a SendFailed record reports.
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
	mu   sync.Mutex
	path string
}

// OpenFileLog opens or creates the log at path, readable by the owner only.
func OpenFileLog(path string) (*FileLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	l := &FileLog{path: path}
	if _, err := l.List(); err != nil {
		return nil, err
	}
	return l, nil
}

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
