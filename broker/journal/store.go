package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/durable"
)

// Store is the durable medium under the journal. Append must not return nil
// until the line is durable (fsynced for a file).
type Store interface {
	Append(line []byte) error
	ReadAll() ([]byte, error)
	// Truncate drops everything from byte n on. Replay uses it to remove a
	// torn final line before appending.
	Truncate(n int64) error
	// Rewrite atomically replaces the whole journal. Only Erase uses it,
	// to remove a deleted source's content from records already written.
	Rewrite(data []byte) error
}

// FileStore is a Store backed by one append-only file.
type FileStore struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// OpenFile opens or creates the journal file at path, readable by its owner
// only. It takes an exclusive lock, so two engines cannot share one journal,
// and fsyncs the parent directory, so a newly created file's directory entry
// is as durable as the records written to it.
func OpenFile(path string) (*FileStore, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("%w: %v", ErrLocked, err)
	}
	if err := syncDir(filepath.Dir(path)); err != nil {
		f.Close()
		return nil, err
	}
	return &FileStore{f: f, path: path}, nil
}

// syncDir fsyncs a directory. A variable so tests can observe it.
var syncDir = durable.SyncDir

func (s *FileStore) Append(line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Write(line); err != nil {
		return err
	}
	return s.f.Sync()
}

func (s *FileStore) ReadAll() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.ReadFile(s.path)
}

func (s *FileStore) Truncate(n int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.f.Truncate(n); err != nil {
		return err
	}
	return s.f.Sync()
}

// Rewrite writes data to a sibling file, fsyncs and locks it, renames it
// over the journal, and fsyncs the directory. The lock moves with the new
// file, so no second engine can open the journal in between.
func (s *FileStore) Rewrite(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.path
	tmp := path + ".tmp"
	t, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		t.Close()
		os.Remove(tmp)
		return err
	}
	if err := syscall.Flock(int(t.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(err)
	}
	if _, err := t.Write(data); err != nil {
		return fail(err)
	}
	if err := t.Sync(); err != nil {
		return fail(err)
	}
	err = durable.Rename(tmp, path)
	if err != nil && !errors.Is(err, durable.ErrDirSync) {
		return fail(err)
	}
	s.f.Close()
	s.f = t
	return err
}

func (s *FileStore) Close() error { return s.f.Close() }

// MemStore is an in-memory Store for tests and simulations.
type MemStore struct {
	mu   sync.Mutex
	data []byte
}

func (s *MemStore) Append(line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append(s.data, line...)
	return nil
}

func (s *MemStore) ReadAll() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.data), nil
}

func (s *MemStore) Rewrite(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = bytes.Clone(data)
	return nil
}

func (s *MemStore) Truncate(n int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < int64(len(s.data)) {
		s.data = s.data[:n]
	}
	return nil
}

// RecordType names a journal record.
type RecordType string

const (
	RecSubmitted     RecordType = "submitted"
	RecAuthorized    RecordType = "authorized"
	RecDenied        RecordType = "denied"
	RecRecheckFailed RecordType = "recheck_failed"
	RecDispatched    RecordType = "dispatched"
	RecObserved      RecordType = "observed"
	RecCancel        RecordType = "cancel_requested"
	RecQuality       RecordType = "quality"
	RecStop          RecordType = "stop"
	RecResume        RecordType = "resume"
	RecEgress        RecordType = "egress" // an egress decision, not an intent
	RecErased        RecordType = "erased" // a deleted source's content removed (CAP-3)
)

// recordVersion is the journal schema version. Replay refuses newer records
// rather than misreading them.
const recordVersion = 1

// Record is one journal entry. The journal is the single audit trail for
// effects and for broker-state changes alike (OP-5).
type Record struct {
	V        int         `json:"v"`
	Seq      uint64      `json:"seq"`
	At       time.Time   `json:"at"`
	Type     RecordType  `json:"type"`
	ID       string      `json:"id,omitempty"`
	Intent   *Intent     `json:"intent,omitempty"`
	Attempt  int         `json:"attempt,omitempty"`
	Result   Result      `json:"result,omitempty"`
	Source   string      `json:"source,omitempty"`
	Evidence string      `json:"evidence,omitempty"`
	Reason   string      `json:"reason,omitempty"`
	Guest    string      `json:"guest,omitempty"`
	Accepted bool        `json:"accepted,omitempty"`
	Verdict  Verdict     `json:"verdict,omitempty"`
	Egress   *EgressNote `json:"egress,omitempty"`
	Sleep    *SleepNote  `json:"sleep,omitempty"`
	// FP and EFP carry an erased intent's fingerprints, so OP-1 still
	// recognises a resubmission once its parameters are gone.
	FP  string `json:"fp,omitempty"`
	EFP string `json:"efp,omitempty"`
}

// encodeRecord renders a record as one line: 8 hex digits of CRC-32 over the
// JSON, a space, the JSON, and a newline.
func encodeRecord(r Record) ([]byte, error) {
	js, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	line := make([]byte, 0, len(js)+10)
	line = fmt.Appendf(line, "%08x ", crc32.ChecksumIEEE(js))
	line = append(line, js...)
	return append(line, '\n'), nil
}

func decodeLine(line []byte) (Record, error) {
	var r Record
	if len(line) < 10 || line[8] != ' ' {
		return r, fmt.Errorf("malformed line")
	}
	want, err := strconv.ParseUint(string(line[:8]), 16, 32)
	if err != nil {
		return r, fmt.Errorf("malformed checksum")
	}
	js := line[9:]
	if crc32.ChecksumIEEE(js) != uint32(want) {
		return r, fmt.Errorf("checksum mismatch")
	}
	d := json.NewDecoder(bytes.NewReader(js))
	d.UseNumber()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	if r.V != recordVersion {
		return r, fmt.Errorf("unsupported record version %d", r.V)
	}
	return r, nil
}

// decodeJournal parses a journal and returns its records and the length of
// the valid prefix.
//
// Only a final segment with no newline is treated as torn and dropped. That
// write never completed, so Append never returned and nothing acted on it
// (in particular no executor ran for an unfinished "dispatched" record). A
// complete line that fails its checksum is corruption, and replay fails
// closed: silently dropping a durable "dispatched" record could let an
// effect run twice.
func decodeJournal(data []byte) ([]Record, int64, error) {
	var recs []Record
	off := 0
	for off < len(data) {
		nl := bytes.IndexByte(data[off:], '\n')
		if nl < 0 {
			break
		}
		r, err := decodeLine(data[off : off+nl])
		if err != nil {
			return nil, 0, fmt.Errorf("%w: record at byte %d: %v", ErrCorrupt, off, err)
		}
		if r.Seq != uint64(len(recs)+1) {
			return nil, 0, fmt.Errorf("%w: record at byte %d has seq %d, want %d", ErrCorrupt, off, r.Seq, len(recs)+1)
		}
		recs = append(recs, r)
		off += nl + 1
	}
	return recs, int64(off), nil
}
