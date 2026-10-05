package recovery

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
)

// Needle is a secret that must not appear in plaintext storage (A8): the
// vault data key (a canary key in tests and owner sessions), the
// code-generator seed, the grid seed, the recovery key, the passphrase.
type Needle struct {
	Name  string
	Value []byte
	// Text marks a printed secret (passphrase, recovery key text): it is
	// also looked for without dashes, in lower case, and as UTF-16.
	Text bool
}

// Finding is one match. It never carries the value.
type Finding struct {
	Source   string
	Offset   int64
	Needle   string
	Encoding string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s at %s+%d (%s)", f.Needle, f.Source, f.Offset, f.Encoding)
}

type pattern struct {
	b        []byte
	needle   string
	encoding string
}

// Scanner looks for every needle in raw bytes, hex (either case), base64
// and base64url at every alignment inside a larger blob, base32 (standard
// and Crockford, either case) at every alignment, and any 15-byte raw or
// hex fragment of a binary value. Matching is one pass over the input.
type Scanner struct {
	pats   []pattern
	byKey  map[uint64][]int
	first2 [1 << 16 / 64]uint64
	maxLen int
}

const minPattern = 8

// fragment is the window length for partial leaks of binary values (96
// bits: no false matches). Windows start every 4 bytes, so any 15
// consecutive bytes of a value contain one.
const fragment = 12

// NewScanner prepares the patterns for needles.
func NewScanner(needles []Needle) (*Scanner, error) {
	s := &Scanner{byKey: map[uint64][]int{}}
	seen := map[string]bool{}
	add := func(b []byte, n, enc string) {
		if len(b) < minPattern || seen[string(b)] {
			return
		}
		seen[string(b)] = true
		s.pats = append(s.pats, pattern{append([]byte(nil), b...), n, enc})
	}
	for _, nd := range needles {
		if len(nd.Value) < minPattern {
			return nil, fmt.Errorf("recovery: needle %s shorter than %d bytes", nd.Name, minPattern)
		}
		v := nd.Value
		add(v, nd.Name, "raw")
		addEncodings(v, nd.Name, add)
		if nd.Text {
			t := string(v)
			for _, alt := range []string{strings.ReplaceAll(t, "-", ""), strings.ToLower(t), strings.ToLower(strings.ReplaceAll(t, "-", ""))} {
				add([]byte(alt), nd.Name, "text form")
			}
			add(utf16le(t), nd.Name, "utf-16")
		} else if len(v) > fragment {
			for i := 0; i+fragment <= len(v); i += 4 {
				add(v[i:i+fragment], nd.Name, "raw fragment")
				f := hex.EncodeToString(v[i : i+fragment])
				add([]byte(f), nd.Name, "hex fragment")
				add([]byte(strings.ToUpper(f)), nd.Name, "hex fragment")
			}
		}
	}
	for i, p := range s.pats {
		k := binary.LittleEndian.Uint64(p.b[:8])
		s.byKey[k] = append(s.byKey[k], i)
		f := uint16(p.b[0]) | uint16(p.b[1])<<8
		s.first2[f/64] |= 1 << (f % 64)
		if len(p.b) > s.maxLen {
			s.maxLen = len(p.b)
		}
	}
	return s, nil
}

var crockfordEnc = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

func addEncodings(v []byte, name string, add func([]byte, string, string)) {
	h := hex.EncodeToString(v)
	add([]byte(h), name, "hex")
	add([]byte(strings.ToUpper(h)), name, "hex")
	for i := 0; i < 3; i++ {
		w := v[i:]
		w = w[:len(w)/3*3]
		add([]byte(base64.StdEncoding.EncodeToString(w)), name, "base64")
		add([]byte(base64.URLEncoding.EncodeToString(w)), name, "base64url")
	}
	for i := 0; i < 5; i++ {
		w := v[i:]
		w = w[:len(w)/5*5]
		for _, e := range []*base32.Encoding{base32.StdEncoding, crockfordEnc} {
			t := e.EncodeToString(w)
			add([]byte(t), name, "base32")
			add([]byte(strings.ToLower(t)), name, "base32")
		}
	}
}

func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}

// Reader scans one stream (a file, a partition, a raw device).
func (s *Scanner) Reader(source string, r io.Reader) ([]Finding, error) {
	var out []Finding
	found := map[[2]int64]bool{}
	const block = 1 << 20
	buf := make([]byte, 0, block+s.maxLen)
	var base int64 // offset of buf[0] in the stream
	for {
		n, err := io.ReadFull(r, buf[len(buf):len(buf)+block])
		buf = buf[:len(buf)+n]
		eof := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !eof {
			return out, err
		}
		// Patterns starting before limit are fully inside buf, or are
		// rescanned after the carry-over at the next block.
		limit := len(buf) - s.maxLen + 1
		if eof {
			limit = len(buf) - minPattern + 1
		}
		for i := 0; i < limit; i++ {
			f := uint16(buf[i]) | uint16(buf[i+1])<<8
			if s.first2[f/64]&(1<<(f%64)) == 0 {
				continue
			}
			for _, pi := range s.byKey[binary.LittleEndian.Uint64(buf[i:i+8])] {
				p := s.pats[pi]
				if i+len(p.b) <= len(buf) && bytes.Equal(buf[i:i+len(p.b)], p.b) {
					key := [2]int64{base + int64(i), int64(pi)}
					if !found[key] {
						found[key] = true
						out = append(out, Finding{source, base + int64(i), p.needle, p.encoding})
					}
				}
			}
		}
		if eof {
			return out, nil
		}
		if limit < 0 {
			limit = 0
		}
		base += int64(limit)
		buf = append(buf[:0], buf[limit:]...)
	}
}

// Tree scans every regular file under root without following symlinks.
// Anything that is not a regular file, directory, or symlink is skipped
// and listed in skipped.
func (s *Scanner) Tree(root string) (findings []Finding, skipped []string, err error) {
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if !d.Type().IsRegular() {
			skipped = append(skipped, p)
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		got, err := s.Reader(p, f)
		findings = append(findings, got...)
		return err
	})
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Source < findings[j].Source })
	return findings, skipped, err
}

// ErrFound is returned by callers that require a clean scan.
var ErrFound = errors.New("recovery: secret material found in plaintext")
