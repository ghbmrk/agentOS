package match

import (
	"strings"
	"testing"
)

// KRN-12: a stream of small writes scans once per carryPattern bytes, not
// once per write, and Result scans what is pending (#3876).
func TestStreamScansInChunks(t *testing.T) {
	v := []byte("q7Xz2pL9mW4vR8tY3nB6kJ5h")
	m := New([]Value{{ID: 4, Bytes: v}}, nil)
	s := m.Stream()
	for _, c := range v {
		s.Write([]byte{c})
	}
	if s.pending != len(v) || len(s.res.Trips) != 0 || s.res.Pattern {
		t.Fatalf("small writes scanned: pending %d, %+v", s.pending, s.res)
	}
	if r := s.Result(); len(r.Trips) != 1 || r.Trips[0] != 4 || !r.Pattern || s.pending != 0 {
		t.Fatalf("Result did not scan what was pending: %+v, pending %d", r, s.pending)
	}
	s.Write([]byte(strings.Repeat("a", carryPattern-1)))
	if s.pending != carryPattern-1 {
		t.Fatalf("a write under carryPattern scanned: pending %d", s.pending)
	}
	s.Write([]byte("a"))
	if s.pending != 0 || len(s.buf) != carryPattern {
		t.Fatalf("a full chunk did not scan: pending %d, tail %d", s.pending, len(s.buf))
	}
}

// KRN-12: the joined tail is carried across a chunk edge, and a JSON
// escape split there is joined, so a wrapped value across the edge trips
// (#4500).
func TestStreamJoinsAcrossChunks(t *testing.T) {
	v := []byte("q7Xz2pL9mW4vR8tY3nB6kJ5h")
	m := New([]Value{{ID: 4, Bytes: v}}, nil)
	for cut := 1; cut < len(v); cut++ {
		for _, br := range []string{"\n", `\n`, `\r\n`, `\\n`, `\\\\r\\\\n`} {
			w := string(v[:cut]) + br + string(v[cut:])
			for at := range len(br) + 1 {
				s := m.Stream()
				s.Write([]byte(strings.Repeat("a", carryPattern-cut-at) + w[:cut+at]))
				if s.pending != 0 {
					t.Fatalf("no chunk scanned before the edge: pending %d", s.pending)
				}
				s.Write([]byte(w[cut+at:]))
				if r := s.Result(); len(r.Trips) != 1 {
					t.Fatalf("%q cut at %d+%d across a chunk edge tripped %v", w, cut, at, r.Trips)
				}
			}
		}
	}
}

// KRN-12: a removed break is carried with the joined tail, moved with it,
// so a form that begins inside one trips after a chunk edge (#4582).
func TestStreamCarriesBreaks(t *testing.T) {
	m := New([]Value{{ID: 4, Bytes: []byte("nq7Xz2pL9mW4vR8tY3nB6kJ5h")}}, nil)
	for _, extra := range []int{1, 100, carryPattern} {
		s := m.Stream()
		s.Write([]byte(`\n` + strings.Repeat("a", carryPattern+extra) + `C:\\nq7Xz2pL9m\nW4v`))
		if s.pending != 0 || len(s.breaks) != 2 || len(s.joined) != carryPattern {
			t.Fatalf("no chunk scanned and cut: pending %d, %d breaks, joined %d", s.pending, len(s.breaks), len(s.joined))
		}
		s.Write([]byte("R8tY3nB6kJ5h"))
		if r := s.Result(); len(r.Trips) != 1 {
			t.Fatalf("a form begun in a break %d bytes past a chunk edge tripped %v", extra, r.Trips)
		}
	}
}

// KRN-12: a one-byte value, too short for a base64 form at every offset,
// makes a matcher without failing.
func TestOneByteValue(t *testing.T) {
	if m := New([]Value{{ID: 4, Bytes: []byte("n")}}, nil); len(m.first['n']) == 0 {
		t.Fatal("the raw form is not indexed by its first byte")
	}
}
