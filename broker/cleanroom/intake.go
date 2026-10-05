package cleanroom

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ghbmrk/agentos/broker/hint"
)

// ErrHint marks a hint the clean room refuses: not the exact canonical
// form of a valid hint of the public schema.
var ErrHint = errors.New("cleanroom: not a canonical hint")

// ErrFull is returned when a batch would take the queue past MaxQueue.
var ErrFull = errors.New("cleanroom: job queue is full")

// job is one hint waiting for, or running in, a clean room.
type job struct {
	ID       string `json:"id"`
	Hint     string `json:"hint"` // canonical form, as received
	Day      string `json:"day"`  // UTC day received
	Attempts int    `json:"attempts"`

	path string
}

// wire is the canonical hint as the emitter writes it (hint.Canonical).
type wire struct {
	Schema  int               `json:"schema"`
	Kind    string            `json:"kind"`
	Embargo bool              `json:"embargo"`
	Fields  map[string]string `json:"fields"`
}

// parseCanonical accepts only the exact bytes the public schema's Canonical
// produces for a valid hint: anything else (another schema version, key
// order, spacing, escapes, an embargo mark the schema does not give the
// kind) is refused, so nothing but the choice of hint reaches a clean room.
func parseCanonical(s *hint.Schema, b []byte) (hint.Hint, bool, error) {
	var w wire
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return hint.Hint{}, false, ErrHint
	}
	h := hint.Hint{Kind: w.Kind, Fields: w.Fields}
	c, err := s.Canonical(h)
	if err != nil || !bytes.Equal(c, b) {
		return hint.Hint{}, false, ErrHint
	}
	return h, w.Embargo, nil
}

// Send takes one day's batch of canonical hints from the emitter
// (hint.Outbox). Every hint is checked before any is queued, and the batch
// is queued by one rename, so it is taken whole or not at all and the
// emitter can resend a refused batch.
func (b *Builder) Send(batch [][]byte) error {
	for _, c := range batch {
		if _, _, err := parseCanonical(b.cfg.Schema, c); err != nil {
			return err
		}
	}
	if len(batch) == 0 {
		return nil
	}
	b.qmu.Lock()
	defer b.qmu.Unlock()
	jobs, err := b.queued()
	if err != nil {
		return err
	}
	if len(jobs)+len(batch) > b.cfg.MaxQueue {
		return ErrFull
	}
	day := b.cfg.Now().UTC().Format("2006-01-02")
	tmp, err := os.MkdirTemp(b.cfg.Dir, "incoming-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for i, c := range batch {
		j := job{ID: newID(), Hint: string(c), Day: day}
		if err := writeJSON(filepath.Join(tmp, fmt.Sprintf("%04d-%s.json", i, j.ID)), j); err != nil {
			return err
		}
	}
	// Batch directories sort by arrival: a sequence above every one queued.
	name := fmt.Sprintf("%016x", b.nextBatch())
	if err := os.Rename(tmp, filepath.Join(b.queueDir(), name)); err != nil {
		return err
	}
	if err := syncDir(b.queueDir()); err != nil {
		return err
	}
	select {
	case b.wake <- struct{}{}:
	default:
	}
	return nil
}

func (b *Builder) queueDir() string { return filepath.Join(b.cfg.Dir, "queue") }

func (b *Builder) nextBatch() uint64 {
	var n uint64
	ents, _ := os.ReadDir(b.queueDir())
	for _, e := range ents {
		var v uint64
		if _, err := fmt.Sscanf(e.Name(), "%016x", &v); err == nil && v >= n {
			n = v + 1
		}
	}
	if n <= b.lastBatch {
		n = b.lastBatch + 1
	}
	b.lastBatch = n
	return n
}

// queued lists waiting jobs, oldest batch first, in batch order.
func (b *Builder) queued() ([]*job, error) {
	batches, err := os.ReadDir(b.queueDir())
	if err != nil {
		return nil, err
	}
	var out []*job
	for _, d := range batches {
		if !d.IsDir() {
			continue
		}
		dir := filepath.Join(b.queueDir(), d.Name())
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		if len(ents) == 0 {
			os.Remove(dir)
			continue
		}
		sort.Slice(ents, func(i, k int) bool { return ents[i].Name() < ents[k].Name() })
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			j := &job{}
			p := filepath.Join(dir, e.Name())
			if err := readJSON(p, j); err != nil {
				return nil, err
			}
			j.path = p
			out = append(out, j)
		}
	}
	return out, nil
}

func newID() string {
	var r [6]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(r[:])
}

func writeJSON(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFile(path, data)
}

// writeFile writes data durably: a synced temporary file renamed into place.
func writeFile(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
