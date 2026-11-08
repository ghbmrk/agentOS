package offload

// REQ: NET-2

import (
	"testing"
)

func bit(name string, on bool) []byte {
	b := attr(bitName, cstr(name))
	if on {
		b = append(b, attr(bitValue, nil)...)
	}
	return attr(bitsBit|nlaNested, b)
}

// TestBitsetForms (ENF-cap-gro): both verbose forms read by name: a list
// holds only the set bits, a value and mask pair marks each set bit. A
// compact bitset, which this package never asks for, and a bit with no
// name are refused rather than read as nothing set, which would pass a
// merging port.
func TestBitsetForms(t *testing.T) {
	list := append(attr(bitsetNomask, nil), attr(bitsetBits|nlaNested, append(bit("rx-gro", false), bit("rx-lro", false)...))...)
	got, err := bitset(list)
	if err != nil || len(got) != 2 || !got["rx-gro"] || !got["rx-lro"] {
		t.Fatalf("list: %v %v", got, err)
	}
	masked := attr(bitsetBits|nlaNested, append(bit("rx-gro", true), bit("rx-lro", false)...))
	got, err = bitset(masked)
	if err != nil || len(got) != 1 || !got["rx-gro"] {
		t.Fatalf("value and mask: %v %v", got, err)
	}
	if got, err := bitset(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty list: %v %v", got, err)
	}
	compact := append(attr(2, []byte{32, 0, 0, 0}), attr(bitsetValue, []byte{1, 0, 0, 0})...)
	if _, err := bitset(compact); err == nil {
		t.Fatal("a compact bitset was read")
	}
	unnamed := attr(bitsetBits|nlaNested, attr(bitsBit|nlaNested, attr(bitValue, nil)))
	if _, err := bitset(append(attr(bitsetNomask, nil), unnamed...)); err == nil {
		t.Fatal("a bit with no name was read")
	}
	unterminated := attr(bitsetBits|nlaNested, attr(bitsBit|nlaNested, attr(bitName, []byte("rx-gro"))))
	if _, err := bitset(append(attr(bitsetNomask, nil), unterminated...)); err == nil {
		t.Fatal("a name with no terminator was read")
	}
}

// TestAttributes: attributes are padded to four bytes, nested types are
// read without their flag, and a malformed length ends the walk.
func TestAttributes(t *testing.T) {
	a := attr(bitName, cstr("rx"))
	if len(a) != 8 || ne.Uint16(a) != 7 {
		t.Fatalf("attr % x", a)
	}
	b := append(attr(featActive|nlaNested, a), attr(featWanted, []byte{9})...)
	if got := find(b, featActive); string(got) != string(a) {
		t.Fatalf("nested: % x", got)
	}
	if got := find(b, featWanted); len(got) != 1 || got[0] != 9 {
		t.Fatalf("after a nest: % x", got)
	}
	if got := find(attr(featHeader, nil), featHeader); got == nil || len(got) != 0 {
		t.Fatalf("a flag reads as present and empty: %v", got)
	}
	bad := append([]byte{200, 0, 4, 0}, attr(featWanted, []byte{9})...)
	if find(bad, featWanted) != nil {
		t.Fatal("read past a malformed length")
	}
}
