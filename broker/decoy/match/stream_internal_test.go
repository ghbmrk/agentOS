package match

import (
	"bytes"
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

// KRN-12: break records stay bounded: one large write of escaped breaks
// keeps only those whose rest may be still to come, a place keeps each
// distinct break once, and a record holds at most "u000a" (#4582).
func TestBreaksBounded(t *testing.T) {
	m := New([]Value{{ID: 4, Bytes: []byte("nq7Xz2pL9mW4vR8tY3nB6kJ5h")}}, nil)
	s := m.Stream()
	s.Write([]byte(strings.Repeat(`x\n`, 1<<18)))
	if len(s.breaks) > m.carry+1 || cap(s.breaks) > 4*m.carry {
		t.Fatalf("%d break records (cap %d) after one write, carry %d", len(s.breaks), cap(s.breaks), m.carry)
	}
	s = m.Stream()
	s.Write([]byte(strings.Repeat(`\n\r`, 1000)))
	if len(s.breaks) != 2 || string(s.breaks[0].b) != "n" {
		t.Fatalf("breaks at one place kept %d records, first %q", len(s.breaks), s.breaks[0].b)
	}
	s = m.Stream()
	s.Write([]byte(`\\\\\\u000a`))
	if len(s.breaks) != 1 || string(s.breaks[0].b) != "u000a" {
		t.Fatalf("a long break kept %+v", s.breaks)
	}
}

// KRN-12: the last break's place moves with the joined tail, so a break
// split by another across a chunk edge ("%0" + JSON \n + "A") stays
// unremoved, as DECOY-a-5 states (#4582).
func TestFloorCarried(t *testing.T) {
	s := New([]Value{{ID: 4, Bytes: []byte("q7Xz2pL9mW4vR8tY3nB6kJ5h")}}, nil).Stream()
	s.Write([]byte(strings.Repeat("a", carryPattern) + `%0\n`))
	s.Write([]byte("A"))
	if s.pending != 1 || !bytes.HasSuffix(s.joined, []byte("%0A")) {
		t.Fatalf("pending %d, joined ends %q", s.pending, s.joined[len(s.joined)-4:])
	}
}

// KRN-12: a held break is matched and let go as soon as the longest form's
// rest has come, carry bytes after it, and not before; carry is the longest
// form but one byte (#5007).
func TestBreakReleasedAtCarry(t *testing.T) {
	v := []byte("q7Xz2pL9mW4vR8tY3nB6kJ5h")
	want := 0
	for _, f := range encodings(v) {
		want = max(want, len(f)-1)
	}
	m := New([]Value{{ID: 4, Bytes: v}}, nil)
	if m.carry != want {
		t.Fatalf("carry %d, want the longest form but one, %d", m.carry, want)
	}
	for _, n := range []int{want - 1, want} {
		s := m.Stream()
		s.Write([]byte(`\n` + strings.Repeat("x", n)))
		held := 0
		if n < want {
			held = 1 // its rest may be still to come
		}
		if len(s.breaks) != held {
			t.Fatalf("%d bytes after a break of carry %d: %d held", n, want, len(s.breaks))
		}
	}
}

// KRN-12: open counts only a break head a later byte could still end: '\'s,
// then at most one "u", "u0", "u00" or "u000", or "%" or "%0" (#5007).
func TestOpenHeads(t *testing.T) {
	for w, n := range map[string]int{
		`x\`: 1, `x\\u00`: 5, `\u000`: 5, "%0": 2, "x%": 1,
		`\uu000`: 0, "xu0": 0, "u000": 0, "x": 0, "": 0,
	} {
		if got := open([]byte(w)); got != n {
			t.Errorf("open(%q) = %d, want %d", w, got, n)
		}
	}
}

// CLK-4: a run under 24 characters is no token, whatever its entropy, as
// candidate requires (#5007).
func TestHighEntropyFloor(t *testing.T) {
	if s := "abcdefghijklmnopqrsTUVW"; highEntropy(s) || !highEntropy(s+"X") {
		t.Fatal("highEntropy's 24-character floor moved")
	}
}

// KRN-12: a form lying wholly inside a removed break is in neither the text
// as written nor as joined, so it does not trip: here the hex "000a" of
// NUL LF inside a CR-split JSON \u000a (#5007).
func TestFormInsideBreak(t *testing.T) {
	m := New([]Value{{ID: 4, Bytes: []byte{0, '\n'}}}, nil)
	if r := m.Scan([]byte("\\u0\r00a")); len(r.Trips) != 0 {
		t.Fatalf("a form inside a break tripped %v", r.Trips)
	}
	if r := m.Scan([]byte("x000ay")); len(r.Trips) != 1 {
		t.Fatalf("the hex form as written did not trip: %v", r.Trips)
	}
}
