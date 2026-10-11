package recall

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/durable"
)

// Dir is the index's durable medium (R8): a small meta log (header,
// preferences, tombstones, used owner messages) and numbered item segments,
// each a JSON-lines file of items. A deletion rewrites only the segments
// that held the deleted items, so its cost does not grow with the index.
//
// Append must not return until the data is durable. Rewrite atomically
// replaces a segment, so a deletion leaves no copy of the deleted data in
// any live file (CAP-3); nil data removes the segment.
type Dir interface {
	Meta() Store
	Segments() ([]uint32, error)
	ReadSegment(n uint32) ([]byte, error)
	ReadAt(n uint32, off int64, p []byte) error
	// Append adds data to segment n (creating it) and returns the offset it
	// was written at.
	Append(n uint32, data []byte) (int64, error)
	Rewrite(n uint32, data []byte) error
}

// DirStore is a Dir in a directory readable by its owner only: meta.jsonl
// (a FileStore) and seg-NNNNNNNN.jsonl files. Segment rewrites write a
// sibling file, fsync it, rename it into place, and fsync the directory.
type DirStore struct {
	mu   sync.Mutex
	path string
	meta *FileStore
	segs map[uint32]*os.File
	// broken is set when a rewrite renamed a segment into place but could
	// not reopen it; appends to it then fail rather than go to the old,
	// unlinked file.
	broken map[uint32]error
}

// OpenDir opens or creates the index directory at path (0700). The meta
// log's lock keeps two brokers from sharing one index.
func OpenDir(path string) (*DirStore, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return nil, err
	}
	meta, err := OpenFile(filepath.Join(path, "meta.jsonl"))
	if err != nil {
		return nil, err
	}
	d := &DirStore{path: path, meta: meta, segs: map[uint32]*os.File{}, broken: map[uint32]error{}}
	// Leftovers of a rewrite a crash cut off are never live.
	durable.SweepTemp(path)
	return d, nil
}

func (d *DirStore) segPath(n uint32) string {
	return filepath.Join(d.path, fmt.Sprintf("seg-%08d.jsonl", n))
}

func (d *DirStore) Meta() Store { return d.meta }

func (d *DirStore) Segments() ([]uint32, error) {
	names, err := filepath.Glob(filepath.Join(d.path, "seg-*.jsonl"))
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, p := range names {
		s := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "seg-"), ".jsonl")
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			continue
		}
		out = append(out, uint32(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// file returns segment n's handle, opening (and creating) it. Caller holds mu.
func (d *DirStore) file(n uint32, create bool) (*os.File, error) {
	if err := d.broken[n]; err != nil {
		return nil, err
	}
	if f := d.segs[n]; f != nil {
		return f, nil
	}
	flag := os.O_RDWR | os.O_APPEND
	if create {
		flag |= os.O_CREATE
	}
	f, err := os.OpenFile(d.segPath(n), flag, 0o600)
	if err != nil {
		return nil, err
	}
	if create {
		if err := f.Chmod(0o600); err != nil {
			f.Close()
			return nil, err
		}
		if err := durable.SyncDir(d.path); err != nil {
			f.Close()
			return nil, err
		}
	}
	d.segs[n] = f
	return f, nil
}

func (d *DirStore) ReadSegment(n uint32) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return os.ReadFile(d.segPath(n))
}

func (d *DirStore) ReadAt(n uint32, off int64, p []byte) error {
	d.mu.Lock()
	f, err := d.file(n, false)
	d.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = f.ReadAt(p, off)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func (d *DirStore) Append(n uint32, data []byte) (int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := d.file(n, true)
	if err != nil {
		return 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	off := fi.Size()
	if _, err := f.Write(data); err != nil {
		return 0, err
	}
	return off, f.Sync()
}

func (d *DirStore) Rewrite(n uint32, data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.segPath(n)
	if data == nil {
		if f := d.segs[n]; f != nil {
			f.Close()
			delete(d.segs, n)
		}
		delete(d.broken, n)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return durable.SyncDir(d.path)
	}
	werr := durable.WriteFile(p, data, 0o600)
	if werr != nil && !errors.Is(werr, durable.ErrDirSync) {
		return werr
	}
	// The old handle now points at an unlinked file: swap it even when
	// only the directory sync failed.
	if f := d.segs[n]; f != nil {
		f.Close()
		delete(d.segs, n)
	}
	if _, err := d.file(n, false); err != nil {
		d.broken[n] = fmt.Errorf("recall: segment reopen after rewrite: %w", err)
		return d.broken[n]
	}
	return werr
}

// Close releases the files and the lock.
func (d *DirStore) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for n, f := range d.segs {
		f.Close()
		delete(d.segs, n)
	}
	return d.meta.Close()
}

// MemDir is an in-memory Dir for tests and simulations.
type MemDir struct {
	mu   sync.Mutex
	meta MemStore
	segs map[uint32][]byte
}

// NewMemDir returns an empty MemDir.
func NewMemDir() *MemDir { return &MemDir{segs: map[uint32][]byte{}} }

func (m *MemDir) Meta() Store { return &m.meta }

func (m *MemDir) Segments() ([]uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]uint32, 0, len(m.segs))
	for n := range m.segs {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func (m *MemDir) ReadSegment(n uint32) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.segs[n]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(b), nil
}

func (m *MemDir) ReadAt(n uint32, off int64, p []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := m.segs[n]
	if off < 0 || off+int64(len(p)) > int64(len(b)) {
		return io.ErrUnexpectedEOF
	}
	copy(p, b[off:])
	return nil
}

func (m *MemDir) Append(n uint32, data []byte) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	off := int64(len(m.segs[n]))
	m.segs[n] = append(m.segs[n], data...)
	return off, nil
}

func (m *MemDir) Rewrite(n uint32, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if data == nil {
		delete(m.segs, n)
		return nil
	}
	m.segs[n] = bytes.Clone(data)
	return nil
}

// Bytes returns everything stored, meta and segments, for tests that check
// what remains on the medium.
func (m *MemDir) Bytes() []byte {
	meta, _ := m.meta.ReadAll()
	m.mu.Lock()
	defer m.mu.Unlock()
	ns := make([]uint32, 0, len(m.segs))
	for n := range m.segs {
		ns = append(ns, n)
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i] < ns[j] })
	out := meta
	for _, n := range ns {
		out = append(out, m.segs[n]...)
	}
	return out
}
