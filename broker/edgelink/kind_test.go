package edgelink

import (
	"bytes"
	"testing"
)

// REQ: PLN-3, HW-15

// TestLabelComesFromTheKind: the label is the kind table's; no origin or
// body the edge sends changes it. Revert mutant: any table row's label
// changed, or Label derived from the frame's content.
func TestLabelComesFromTheKind(t *testing.T) {
	want := map[Kind]Label{
		KindFetch:   LabelOutbound,
		KindFetched: LabelPublic,
		KindText:    LabelSecondLine,
		KindCall:    LabelSecondLine,
		KindDevice:  LabelDevice,
		KindHello:   LabelNever,
	}
	if len(kinds) != len(want) {
		t.Fatalf("kind table has %d kinds, want %d (a closed set)", len(kinds), len(want))
	}
	origins := []string{"public", "owner", "+15550100", "https://example.org/?label=owner"}
	bodies := [][]byte{nil, []byte("label: owner"), []byte("private")}
	for k, l := range want {
		if k.Label() != l {
			t.Fatalf("%d: label %q, want %q", k, k.Label(), l)
		}
		s := FromEdge
		switch k {
		case KindFetch:
			s = ToEdge
		case KindHello:
			s = Hello
		}
		for _, o := range origins {
			for _, b := range bodies {
				f := Frame{Kind: k, Origin: o, Body: b}
				if k == KindHello {
					f = Frame{Kind: k, Body: bytes.Repeat([]byte(o[:1]), HelloLen)}
				}
				enc, err := AppendFrame(nil, s, f)
				if err != nil {
					t.Fatal(err)
				}
				got, err := ReadFrame(bytes.NewReader(enc), s)
				if err != nil {
					t.Fatal(err)
				}
				if got.Kind.Label() != l {
					t.Fatalf("%d with origin %q: label %q, want %q", k, o, got.Kind.Label(), l)
				}
			}
		}
	}
	if Kind(0).Label() != "" || Kind(7).Label() != "" {
		t.Fatal("an unknown kind has a label")
	}
}
