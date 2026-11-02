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
