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
		for _, br := range []string{"\n", `\n`, `\r\n`} {
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
