package pubid

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// WireBytes is the constant body size of one publication. Every day that
// sends, including an empty day from Pulse, is this long, so the size of a
// batch and the fact of an empty day are not visible as a length.
const WireBytes = 64 << 10

// Transport delivers one constant-size body. The same body for a day may
// be offered twice after a crash; a later, different batch for that day is
// a new delivery (security N1 on #163).
type Transport interface {
	Post(day string, body []byte) error
}

// Wire is a Sender. It pads each batch to WireBytes (or Size), remembers
// each accepted day and batch hash, and does not send that pair again. A
// different batch for a day already published is sent, never dropped.
type Wire struct {
	Path string // accepted day+hash pairs; created 0600
	Post Transport
	Size int // 0 means WireBytes
	Rand func([]byte) (int, error)
}

type wireState struct {
	Sent []wireSent `json:"sent"`
}

type wireSent struct {
	Day  string `json:"day"`
	Hash string `json:"hash"`
}

// Publish sends batch for day, padded to a constant size.
func (w *Wire) Publish(day string, batch [][]byte) error {
	if err := w.check(day); err != nil {
		return err
	}
	sum := batchHash(batch)
	st, err := w.load()
	if err != nil {
		return err
	}
	if accepted(st, day, sum) {
		return nil
	}
	body, err := w.pack(batch)
	if err != nil {
		return err
	}
	if err := w.Post.Post(day, body); err != nil {
		return err
	}
	st.Sent = append(st.Sent, wireSent{Day: day, Hash: sum})
	return w.store(st)
}

// Pulse sends one empty constant-size body for day when nothing has been
// accepted for it yet, so a day with no items looks like any other day.
// A day that already published is left as it was.
func (w *Wire) Pulse(day string) error {
	if err := w.check(day); err != nil {
		return err
	}
	st, err := w.load()
	if err != nil {
		return err
	}
	for _, s := range st.Sent {
		if s.Day == day {
			return nil
		}
	}
	return w.Publish(day, nil)
}

func (w *Wire) check(day string) error {
	if w == nil || w.Path == "" || w.Post == nil {
		return errors.New("pubid: wire path and transport are required")
	}
	if day == "" || len(day) > 32 || !allDays(day) {
		return fmt.Errorf("pubid: bad publication day %q", day)
	}
	return nil
}

func allDays(s string) bool {
	for _, r := range s {
		if r != '-' && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func (w *Wire) size() int {
	if w.Size > 0 {
		return w.Size
	}
	return WireBytes
}

func batchHash(batch [][]byte) string {
	h := sha256.New()
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(batch)))
	h.Write(n[:])
	for _, b := range batch {
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func accepted(st wireState, day, sum string) bool {
	for _, s := range st.Sent {
		if s.Day == day && s.Hash == sum {
			return true
		}
	}
	return false
}

// pack writes a constant-size body: item count, then each item's length and
// bytes, then random padding. A batch that does not fit is refused rather
// than sent at a different length.
func (w *Wire) pack(batch [][]byte) ([]byte, error) {
	size := w.size()
	if size < 8 || size > 8<<20 {
		return nil, fmt.Errorf("pubid: wire size %d", size)
	}
	var buf bytes.Buffer
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(batch)))
	buf.Write(n[:])
	for _, b := range batch {
		if buf.Len()+4+len(b) > size {
			return nil, errors.New("pubid: batch does not fit the constant body")
		}
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		buf.Write(n[:])
		buf.Write(b)
	}
	body := make([]byte, size)
	copy(body, buf.Bytes())
	rnd := w.Rand
	if rnd == nil {
		rnd = rand.Read
	}
	if _, err := rnd(body[buf.Len():]); err != nil {
		return nil, err
	}
	return body, nil
}

func (w *Wire) load() (wireState, error) {
	b, err := os.ReadFile(w.Path)
	if errors.Is(err, os.ErrNotExist) {
		return wireState{}, nil
	}
	if err != nil {
		return wireState{}, err
	}
	var st wireState
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&st); err != nil {
		return wireState{}, fmt.Errorf("pubid: wire %s: %w", w.Path, err)
	}
	return st, nil
}

func (w *Wire) store(st wireState) error {
	if err := checkDir(filepath.Dir(w.Path)); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeAtomic(w.Path, b)
}
