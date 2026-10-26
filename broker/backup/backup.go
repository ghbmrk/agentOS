package backup

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Recaller is the kernel's view of a subject: *kernel.State satisfies it.
type Recaller interface {
	Recall(subject string) (kernel.Recall, bool)
}

// Manifest begins a content object's plaintext. It carries the page CA and
// the edge key with the revoked-edge-key record as opaque data (CH-9,
// HW-15), and has no field for a kernel or holder key. Restore trusts none
// of it until the owner-page step (slice b).
type Manifest struct {
	Version     int       `json:"version"`
	BackupID    string    `json:"backup_id"`
	Created     int64     `json:"created"`
	Recipient   string    `json:"recipient"`
	PageCA      []byte    `json:"page_ca"`
	EdgeKey     []byte    `json:"edge_key"`
	RevokedEdge [][]byte  `json:"revoked_edge"`
	Sections    []Section `json:"sections"`
}

// Section is one stretch of the content object after the manifest.
type Section struct {
	Name   string `json:"name"`
	Length int64  `json:"length"`
	SHA256 string `json:"sha256"`
}

// Source is a section to back up. Write opens it twice, once to hash it
// for the manifest and once to copy it, and fails if the two differ.
type Source struct {
	Name string
	Open func() (io.ReadCloser, error)
}

// Input is what one backup holds.
type Input struct {
	Recipient   Recipient
	Created     int64
	PageCA      []byte
	EdgeKey     []byte
	RevokedEdge [][]byte
	Sections    []Source
	Keys        kernel.Keys // read only through List and Get
	State       Recaller
}

// Record is what the box keeps about a backup: public and opaque only, no
// key. The caller persists every Record Write and Rewrap return.
type Record struct {
	BackupID   string    `json:"backup_id"`
	Recipient  Recipient `json:"recipient"`
	Created    int64     `json:"created"`
	Generation uint64    `json:"generation"` // of the current key table
	Subjects   []string  `json:"subjects"`   // sorted, in the current key table
	ContentSum string    `json:"content_sha256"`
	TableSum   string    `json:"table_sha256"`
}

const (
	maxManifest = 1 << 20
	// firstGeneration is the key table Write puts; the content object is
	// generation 0.
	firstGeneration = 1
)

var (
	ErrSection = errors.New("backup: a section is named log or content/<store>, once each")
	ErrChanged = errors.New("backup: a section changed while it was copied")
	ErrSum     = errors.New("backup: a section does not match its manifest")
)

// validSection is the closed set of section names: log, and content/<store>
// for any name the kernel takes as a content store (kernel.ValidStore). A
// section name is a label, never a file path.
func validSection(n string) bool {
	if n == "log" {
		return true
	}
	s, ok := strings.CutPrefix(n, "content/")
	return ok && kernel.ValidStore(s)
}

func checkSections(names []string) error {
	seen := map[string]bool{}
	for _, n := range names {
		if !validSection(n) || seen[n] {
			return fmt.Errorf("%w: %q", ErrSection, n)
		}
		seen[n] = true
	}
	return nil
}

func newID() ([idLen]byte, error) {
	var id [idLen]byte
	_, err := io.ReadFull(rand.Reader, id[:])
	return id, err
}

// hashSource reads src through, returning its length and SHA-256.
func hashSource(src Source, w io.Writer) (int64, string, error) {
	rc, err := src.Open()
	if err != nil {
		return 0, "", fmt.Errorf("backup: section %s: %w", src.Name, err)
	}
	defer rc.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(h, w), rc)
	if err != nil {
		return 0, "", fmt.Errorf("backup: section %s: %w", src.Name, err)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// Write writes one backup: the content object to w, and its first key
// table to t. The key table holds the data key of each live subject the
// table lists; it is built before any byte is written, so a refused table
// writes nothing.
func Write(w io.Writer, t Target, in Input) (Record, error) {
	if _, _, err := in.Recipient.keys(); err != nil {
		return Record{}, err
	}
	names := make([]string, len(in.Sections))
	for i, s := range in.Sections {
		names[i] = s.Name
	}
	if err := checkSections(names); err != nil {
		return Record{}, err
	}
	subjects, err := in.Keys.List()
	if err != nil {
		return Record{}, err
	}
	entries, err := liveEntries(subjects, in.Keys, in.State)
	if err != nil {
		return Record{}, err
	}
	id, err := newID()
	if err != nil {
		return Record{}, err
	}
	m := Manifest{Version: version, BackupID: hex.EncodeToString(id[:]), Created: in.Created,
		Recipient: in.Recipient.ID(), PageCA: in.PageCA, EdgeKey: in.EdgeKey, RevokedEdge: in.RevokedEdge}
	for _, s := range in.Sections {
		n, sum, err := hashSource(s, io.Discard)
		if err != nil {
			return Record{}, err
		}
		m.Sections = append(m.Sections, Section{Name: s.Name, Length: n, SHA256: sum})
	}
	mb, err := json.Marshal(m)
	if err != nil {
		return Record{}, err
	}
	if len(mb) > maxManifest {
		return Record{}, errors.New("backup: the manifest is over 1 MiB")
	}

	sum := sha256.New()
	bw := bufio.NewWriterSize(io.MultiWriter(w, sum), chunkSize)
	sw, err := sealTo(bw, in.Recipient, header{kind: KindContent, backupID: id})
	if err != nil {
		return Record{}, err
	}
	if _, err := sw.Write(binary.BigEndian.AppendUint32(nil, uint32(len(mb)))); err != nil {
		return Record{}, err
	}
	if _, err := sw.Write(mb); err != nil {
		return Record{}, err
	}
	for i, s := range in.Sections {
		n, h, err := hashSource(s, sw)
		if err != nil {
			return Record{}, err
		}
		if n != m.Sections[i].Length || h != m.Sections[i].SHA256 {
			return Record{}, fmt.Errorf("%w: %s", ErrChanged, s.Name)
		}
	}
	if err := sw.Close(); err != nil {
		return Record{}, err
	}
	if err := bw.Flush(); err != nil {
		return Record{}, err
	}

	rec := Record{BackupID: m.BackupID, Recipient: in.Recipient, Created: in.Created,
		Generation: firstGeneration, ContentSum: hex.EncodeToString(sum.Sum(nil))}
	tb, err := sealTable(in.Recipient, id, firstGeneration, entries)
	if err != nil {
		return Record{}, err
	}
	if err := t.PutTable(rec.BackupID, firstGeneration, tb); err != nil {
		return Record{}, err
	}
	rec.Subjects, rec.TableSum = entrySubjects(entries), sumHex(tb)
	return rec, nil
}

func sumHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Sections reads a content object's sections in manifest order, checking
// each one's length and SHA-256 as it ends. Its first error sticks: every
// later Next returns it, so a caller that drops one never sees io.EOF.
type Sections struct {
	r    io.Reader
	list []Section
	i    int
	cur  *sectionReader
	err  error
}

// sectionReader keeps its first error other than io.EOF and returns it
// from every later Read.
type sectionReader struct {
	s    Section
	r    io.Reader
	h    hash.Hash
	left int64
	err  error
}

func (s *sectionReader) Read(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if s.left == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > s.left {
		p = p[:s.left]
	}
	n, err := s.r.Read(p)
	s.h.Write(p[:n])
	s.left -= int64(n)
	switch {
	case errors.Is(err, io.EOF) && s.left > 0:
		err = ErrSum
	case s.left == 0 && hex.EncodeToString(s.h.Sum(nil)) != s.s.SHA256:
		err = ErrSum
	case s.left == 0 && err == nil:
		err = io.EOF
	}
	if err != nil && !errors.Is(err, io.EOF) {
		s.err = err
	}
	return n, err
}

// Next finishes the section before (reading what the caller left) and
// returns the next one. After the last section it checks the object ends
// there and returns io.EOF; a reader returns ErrSum, or the open error,
// for a section that does not match, and so does every later Next.
func (s *Sections) Next() (Section, io.Reader, error) {
	if s.err != nil {
		return Section{}, nil, s.err
	}
	sec, r, err := s.next()
	if err != nil && !errors.Is(err, io.EOF) {
		s.err = err
	}
	return sec, r, err
}

func (s *Sections) next() (Section, io.Reader, error) {
	if s.cur != nil {
		if _, err := io.Copy(io.Discard, s.cur); err != nil {
			return Section{}, nil, err
		}
		s.cur = nil
	}
	if s.i == len(s.list) {
		var b [1]byte
		switch n, err := io.ReadFull(s.r, b[:]); {
		case n > 0:
			return Section{}, nil, ErrSum
		case errors.Is(err, io.EOF):
			return Section{}, nil, io.EOF
		default:
			return Section{}, nil, err
		}
	}
	sec := s.list[s.i]
	s.i++
	s.cur = &sectionReader{s: sec, r: s.r, h: sha256.New(), left: sec.Length}
	if sec.Length == 0 && hex.EncodeToString(s.cur.h.Sum(nil)) != sec.SHA256 {
		return Section{}, nil, ErrSum
	}
	return sec, s.cur, nil
}

// Open opens a content object with the recovery key and reads its
// manifest. The sections follow through the returned Sections.
func Open(r io.Reader, rk []byte) (Manifest, *Sections, error) {
	h, body, err := openFrom(r, rk, KindContent)
	if err != nil {
		return Manifest{}, nil, err
	}
	var lb [4]byte
	if _, err := io.ReadFull(body, lb[:]); err != nil {
		return Manifest{}, nil, ErrOpen
	}
	n := binary.BigEndian.Uint32(lb[:])
	if n > maxManifest {
		return Manifest{}, nil, ErrHeader
	}
	mb := make([]byte, n)
	if _, err := io.ReadFull(body, mb); err != nil {
		return Manifest{}, nil, ErrOpen
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(mb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, nil, fmt.Errorf("backup: manifest: %w", err)
	}
	if m.Version != version || m.BackupID != hex.EncodeToString(h.backupID[:]) || m.Recipient != hex.EncodeToString(h.recipient[:]) || h.gen != 0 {
		return Manifest{}, nil, ErrHeader
	}
	names := make([]string, len(m.Sections))
	for i, s := range m.Sections {
		if s.Length < 0 {
			return Manifest{}, nil, ErrHeader
		}
		names[i] = s.Name
	}
	if err := checkSections(names); err != nil {
		return Manifest{}, nil, err
	}
	return m, &Sections{r: body, list: slices.Clone(m.Sections)}, nil
}
