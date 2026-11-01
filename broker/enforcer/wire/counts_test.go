package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// REQ: NET-2

func sampleCounts() Counts {
	return Counts{Day: 20758, EdgeCap: 1 << 30, EdgeCount: 12345, Groups: []CountGroup{
		{Dests: []CountDest{{"a.example", 100}, {"b.example", 50}}, Count: 120},
		{Dests: []CountDest{{"backup.example", 1 << 40}}, Count: 0},
	}}
}

// TestCountsRoundTrip: the count read's body decodes to exactly what was
// encoded, a group's cap is the sum of its destinations', and a read for
// it names no device (NET-2 Byte caps, #4174).
func TestCountsRoundTrip(t *testing.T) {
	c := sampleCounts()
	b, err := EncodeCounts(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCounts(b)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	if c.Groups[0].Cap() != 150 || !reflect.DeepEqual(c.Groups[0].Dests, []CountDest{{"a.example", 100}, {"b.example", 50}}) {
		t.Fatalf("group 0: cap %d, %v", c.Groups[0].Cap(), c.Groups[0].Dests)
	}
	if _, err := DecodeCounts(mustEncode(t, Counts{})); err != nil {
		t.Fatalf("no groups: %v", err)
	}
	if _, err := Encode(ToEnforcer, Read{ID: 1, What: ReadCounts}); err != nil {
		t.Fatalf("count read: %v", err)
	}
	if _, err := Encode(ToEnforcer, Read{ID: 1, What: ReadCounts, Device: "lamp"}); !errors.Is(err, ErrPayload) {
		t.Fatalf("count read naming a device: %v", err)
	}
	if _, err := Encode(ToEnforcer, Read{ID: 1, What: ReadCounts + 1}); !errors.Is(err, ErrPayload) {
		t.Fatalf("read past the list: %v", err)
	}
}

func mustEncode(t *testing.T, c Counts) []byte {
	t.Helper()
	b, err := EncodeCounts(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCountsOneForm: every body outside the one canonical form is
// refused, so the kernel never reads a count two ways: a destination
// named twice, out of order within its group or across groups, an empty
// group, a name that is not a token, a group cap that overflows, a short
// body and trailing bytes. Revert mutants: each check in DecodeCounts.
func TestCountsOneForm(t *testing.T) {
	bad := map[string]Counts{
		"named twice":         {Groups: []CountGroup{{Dests: []CountDest{{"a.example", 1}}}, {Dests: []CountDest{{"a.example", 1}}}}},
		"named in two groups": {Groups: []CountGroup{{Dests: []CountDest{{"a.example", 1}, {"c.example", 1}}}, {Dests: []CountDest{{"b.example", 1}, {"c.example", 1}}}}},
		"out of order":        {Groups: []CountGroup{{Dests: []CountDest{{"b.example", 1}, {"a.example", 1}}}}},
		"repeated in a group": {Groups: []CountGroup{{Dests: []CountDest{{"a.example", 1}, {"a.example", 1}}}}},
		"groups out of order": {Groups: []CountGroup{{Dests: []CountDest{{"b.example", 1}}}, {Dests: []CountDest{{"a.example", 1}}}}},
		"empty group":         {Groups: []CountGroup{{Count: 1}}},
		"not a token":         {Groups: []CountGroup{{Dests: []CountDest{{"a example", 1}}}}},
		"empty name":          {Groups: []CountGroup{{Dests: []CountDest{{"", 1}}}}},
		"cap overflows":       {Groups: []CountGroup{{Dests: []CountDest{{"a.example", 1 << 63}, {"b.example", 1 << 63}}}}},
		"cap overflows later": {Groups: []CountGroup{{Dests: []CountDest{{"a.example", 1 << 63}, {"b.example", 1 << 62}, {"c.example", 1 << 62}}}}},
	}
	for name, c := range bad {
		if _, err := EncodeCounts(c); !errors.Is(err, ErrCounts) {
			t.Errorf("%s: encoded, err %v", name, err)
		}
	}
	good := mustEncode(t, sampleCounts())
	for name, b := range map[string][]byte{
		"short":    good[:len(good)-1],
		"trailing": append(bytes.Clone(good), 0),
		"group count lies": func() []byte {
			b := bytes.Clone(good)
			binary.BigEndian.PutUint32(b[20:], 3)
			return b
		}(),
		"over the reply cap": func() []byte {
			// Well formed in every other way: one 253-byte name per group.
			var c Counts
			for i := 0; len(c.Groups)*(8+2+1+MaxName+8) <= MaxReply; i++ {
				name := fmt.Sprintf("%06d", i) + strings.Repeat("x", MaxName-6)
				c.Groups = append(c.Groups, CountGroup{Dests: []CountDest{{name, 1}}})
			}
			if _, err := EncodeCounts(c); !errors.Is(err, ErrCounts) {
				t.Errorf("encoded a body over the reply cap: %v", err)
			}
			return mustEncodeRaw(c)
		}(),
	} {
		if _, err := DecodeCounts(b); !errors.Is(err, ErrCounts) {
			t.Errorf("%s: decoded, err %v", name, err)
		}
	}
}

// mustEncodeRaw is EncodeCounts without its own check, for a body only the
// decoder's size check refuses.
func mustEncodeRaw(c Counts) []byte {
	b := binary.BigEndian.AppendUint32(nil, c.Day)
	b = binary.BigEndian.AppendUint64(b, c.EdgeCap)
	b = binary.BigEndian.AppendUint64(b, c.EdgeCount)
	b = binary.BigEndian.AppendUint32(b, uint32(len(c.Groups)))
	for _, g := range c.Groups {
		b = binary.BigEndian.AppendUint64(b, g.Count)
		b = binary.BigEndian.AppendUint16(b, uint16(len(g.Dests)))
		for _, d := range g.Dests {
			b = putName(b, d.Name)
			b = binary.BigEndian.AppendUint64(b, d.Cap)
		}
	}
	return b
}

// TestCountsAtTheirLimits: a body of exactly MaxReply, a group of the most
// destinations its count can name, and a destination capped at zero are
// all the one form. Revert mutants: each limit in EncodeCounts and
// DecodeCounts moved by one.
func TestCountsAtTheirLimits(t *testing.T) {
	// 24 header bytes, then 19+len(name) per one-destination group.
	var full Counts
	for left := MaxReply - 24; left > 0; {
		n := min(MaxName, left-19)
		name := fmt.Sprintf("%06d", len(full.Groups)) + strings.Repeat("x", n-6)
		full.Groups = append(full.Groups, CountGroup{Dests: []CountDest{{name, 1}}})
		left -= 19 + n
	}
	if b, err := EncodeCounts(full); err != nil || len(b) != MaxReply {
		t.Fatalf("a body of exactly MaxReply: %d bytes, %v", len(b), err)
	}
	wide := Counts{Groups: []CountGroup{{}}}
	for i := range 0xffff {
		wide.Groups[0].Dests = append(wide.Groups[0].Dests, CountDest{fmt.Sprintf("d%05d", i), 1})
	}
	if _, err := EncodeCounts(wide); err != nil {
		t.Fatalf("a group of 0xffff destinations: %v", err)
	}
	wide.Groups[0].Dests = append(wide.Groups[0].Dests, CountDest{"e", 1})
	if _, err := EncodeCounts(wide); !errors.Is(err, ErrCounts) {
		t.Fatalf("a group of 0x10000 destinations encoded: %v", err)
	}
	zero := Counts{Groups: []CountGroup{{Dests: []CountDest{{"a.example", 0}, {"b.example", 5}}}}}
	if c, err := DecodeCounts(mustEncode(t, zero)); err != nil || c.Groups[0].Cap() != 5 {
		t.Fatalf("a destination capped at zero: %+v, %v", c, err)
	}
}
