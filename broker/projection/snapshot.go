package projection

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// snapVersion is the snapshot envelope version. Boot ignores other versions
// and replays in full rather than misreading them.
const snapVersion = 1

// header is a snapshot's envelope. Seq is the journal sequence number the
// snapshot reflects; Anchor identifies the record at Seq, so a snapshot of
// another journal (a restored backup, a reset box) is not applied to this
// one. Sum is SHA-256 over the projection's data.
type header struct {
	V      int    `json:"v"`
	Name   string `json:"name"`
	Seq    uint64 `json:"seq"`
	Anchor string `json:"anchor"`
	Sum    string `json:"sum"`
}

// anchor identifies a journal record by the fields an erase rewrite keeps:
// sequence number, type, intent ID and time.
func anchor(r journal.Record) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%d\x00%s\x00%s\x00%s", r.Seq, r.Type, r.ID, r.At.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h[:])
}

// encode renders a snapshot as a JSON header line followed by the data.
func encode(h header, data []byte) ([]byte, error) {
	sum := sha256.Sum256(data)
	h.Sum = hex.EncodeToString(sum[:])
	js, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(js)+1+len(data))
	out = append(out, js...)
	out = append(out, '\n')
	return append(out, data...), nil
}

func decode(b []byte) (header, []byte, error) {
	var h header
	nl := bytes.IndexByte(b, '\n')
	if nl < 0 {
		return h, nil, errors.New("malformed snapshot: no header")
	}
	if err := json.Unmarshal(b[:nl], &h); err != nil {
		return h, nil, fmt.Errorf("malformed snapshot header: %v", err)
	}
	if h.V != snapVersion {
		return h, nil, fmt.Errorf("unsupported snapshot version %d", h.V)
	}
	data := b[nl+1:]
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != h.Sum {
		return h, nil, errors.New("snapshot checksum mismatch")
	}
	return h, data, nil
}

func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// MemStore is an in-memory Store for tests and simulations.
type MemStore struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (m *MemStore) Load(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(b), nil
}

func (m *MemStore) Save(name string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.files == nil {
		m.files = map[string][]byte{}
	}
	m.files[name] = bytes.Clone(data)
	return nil
}

func (m *MemStore) Delete(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, name)
	return nil
}

// DirStore keeps each projection's snapshot as <dir>/<name>.snap, readable
// by its owner only. Save replaces the file atomically, so the directory
// holds one snapshot per projection and older ones are gone (RES-4).
type DirStore struct{ dir string }

// OpenDir returns a DirStore over dir, creating it with mode 0700. The
// directory belongs on the volume that holds the journal, inside its
// storage reserve (RES-4).
func OpenDir(dir string) (*DirStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &DirStore{dir: dir}, nil
}

func (d *DirStore) path(name string) string { return filepath.Join(d.dir, name+".snap") }

func (d *DirStore) Load(name string) ([]byte, error) { return os.ReadFile(d.path(name)) }

// Save writes a temporary sibling, fsyncs it, renames it over the snapshot
// and fsyncs the directory.
func (d *DirStore) Save(name string, data []byte) error {
	p := d.path(name)
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, p) // durable:exempt SIM-fs moves this to its WriteFile helper
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(d.dir)
}

// Delete removes the snapshot and any temporary copy, then fsyncs the
// directory so the removal is durable.
func (d *DirStore) Delete(name string) error {
	p := d.path(name)
	for _, f := range []string{p, p + ".tmp"} {
		if err := os.Remove(f); err != nil && !isNotExist(err) {
			return err
		}
	}
	return syncDir(d.dir)
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
