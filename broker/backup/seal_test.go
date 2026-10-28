package backup

// REQ: BAK-1

import (
	"bytes"
	"crypto/mlkem"
	"encoding/json"
	"errors"
	"testing"
)

var testID = [idLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

// Offsets of the header fields.
const (
	offKind = len(magic) + 1
	offID   = offKind + 1
	offGen  = offID + idLen
	offEph  = offGen + 8
	offCtM  = offEph + 32
)

func TestOpenNeedsBothSecrets(t *testing.T) {
	// White box: each shared secret changes the key.
	ssM, ssX := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	ctM, eph, rX, ek := bytes.Repeat([]byte{3}, 1088), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32), bytes.Repeat([]byte{6}, 1184)
	k0, err := combine(ssM, ssX, KindContent, ctM, eph, rX, ek)
	must(t, err)
	flip := func(b []byte) []byte { c := bytes.Clone(b); c[7] ^= 1; return c }
	for name, args := range map[string][6][]byte{
		"ssM": {flip(ssM), ssX, ctM, eph, rX, ek},
		"ssX": {ssM, flip(ssX), ctM, eph, rX, ek},
		"ctM": {ssM, ssX, flip(ctM), eph, rX, ek},
		"eph": {ssM, ssX, ctM, flip(eph), rX, ek},
		"rX":  {ssM, ssX, ctM, eph, flip(rX), ek},
		"ek":  {ssM, ssX, ctM, eph, rX, flip(ek)},
	} {
		k, err := combine(args[0], args[1], KindContent, args[2], args[3], args[4], args[5])
		must(t, err)
		if bytes.Equal(k, k0) {
			t.Errorf("a changed %s gives the same key", name)
		}
	}
	if k, _ := combine(ssM, ssX, KindKeyTable, ctM, eph, rX, ek); bytes.Equal(k, k0) {
		t.Error("the kind does not change the key")
	}
	// Black box: the X25519 half (eph.pub) and the ML-KEM half (ctM).
	obj := sealBytes(t, recipient(t, rk1), KindContent, testID, 0, []byte("body"))
	if got, err := openBytes(obj, rk1, KindContent); err != nil || string(got) != "body" {
		t.Fatalf("round trip: %q, %v", got, err)
	}
	for _, off := range []int{offEph, offEph + 31, offCtM, offCtM + 500, offCtM + 1087} {
		bad := bytes.Clone(obj)
		bad[off] ^= 0x40
		if _, err := openBytes(bad, rk1, KindContent); err == nil {
			t.Errorf("opens with header byte %d changed", off)
		}
	}
}

func TestKindAndHeaderAreBound(t *testing.T) {
	r := recipient(t, rk1)
	tb := sealBytes(t, r, KindKeyTable, testID, 4, []byte("table"))
	if _, err := openBytes(tb, rk1, KindContent); err == nil {
		t.Fatal("a table object opens as content")
	}
	// Relabelled as content, the kind is still bound through the key.
	relabel := bytes.Clone(tb)
	relabel[offKind] = kindCode[KindContent]
	if _, err := openBytes(relabel, rk1, KindContent); err == nil {
		t.Fatal("a table object relabelled as content opens")
	}
	if got, err := openBytes(tb, rk1, KindKeyTable); err != nil || string(got) != "table" {
		t.Fatalf("round trip: %q, %v", got, err)
	}
	for i := range headerLen {
		bad := bytes.Clone(tb)
		bad[i] ^= 1
		if _, err := openBytes(bad, rk1, KindKeyTable); err == nil {
			t.Errorf("opens with header byte %d changed", i)
		}
	}
	// Named fields, for the record: backup ID, generation.
	for _, off := range []int{offID, offGen + 7} {
		bad := bytes.Clone(tb)
		bad[off] ^= 0x80
		if _, err := openBytes(bad, rk1, KindKeyTable); err == nil {
			t.Errorf("opens with byte %d changed", off)
		}
	}
}

// chunks splits a sealed object into its header and sealed chunks.
func chunks(obj []byte) (hdr []byte, cs [][]byte) {
	hdr, rest := obj[:headerLen], obj[headerLen:]
	for len(rest) > chunkSize+tagSize {
		cs, rest = append(cs, rest[:chunkSize+tagSize]), rest[chunkSize+tagSize:]
	}
	return hdr, append(cs, rest)
}

func join(hdr []byte, cs ...[]byte) []byte {
	out := bytes.Clone(hdr)
	for _, c := range cs {
		out = append(out, c...)
	}
	return out
}

func TestTruncatedReorderedOrExtendedFails(t *testing.T) {
	r := recipient(t, rk1)
	body := make([]byte, 3*chunkSize+chunkSize/2)
	for i := range body {
		body[i] = byte(i * 7)
	}
	obj := sealBytes(t, r, KindContent, testID, 0, body)
	if got, err := openBytes(obj, rk1, KindContent); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("round trip failed: %v", err)
	}
	hdr, cs := chunks(obj)
	if len(cs) != 4 {
		t.Fatalf("%d chunks, want 4", len(cs))
	}
	for name, bad := range map[string][]byte{
		"last chunk removed":     join(hdr, cs[:3]...),
		"two chunks swapped":     join(hdr, cs[1], cs[0], cs[2], cs[3]),
		"a chunk appended":       join(hdr, cs[0], cs[1], cs[2], cs[3], cs[1]),
		"last chunk cut short":   obj[:len(obj)-1],
		"one byte appended":      append(bytes.Clone(obj), 0),
		"every chunk but header": hdr,
	} {
		if _, err := openBytes(bad, rk1, KindContent); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: %v, want ErrOpen", name, err)
		}
	}
	// A zero-length body and a body ending on a chunk boundary round-trip.
	for _, n := range []int{0, chunkSize, 2 * chunkSize} {
		b := bytes.Repeat([]byte{9}, n)
		got, err := openBytes(sealBytes(t, r, KindContent, testID, 0, b), rk1, KindContent)
		if err != nil || !bytes.Equal(got, b) {
			t.Errorf("%d-byte body: %v", n, err)
		}
	}
	// A boundary body with its flagged last chunk removed fails.
	hdr, cs = chunks(sealBytes(t, r, KindContent, testID, 0, make([]byte, 2*chunkSize)))
	if _, err := openBytes(join(hdr, cs[0]), rk1, KindContent); !errors.Is(err, ErrOpen) {
		t.Errorf("boundary body cut at a chunk: %v", err)
	}
}

func TestRecipientIsDerivedAndPublicOnly(t *testing.T) {
	a, b := recipient(t, rk1), recipient(t, rk1)
	if !bytes.Equal(a.X, b.X) || !bytes.Equal(a.EK, b.EK) || a.ID() != b.ID() || len(a.ID()) != 32 {
		t.Fatal("the same recovery key gives another recipient")
	}
	if recipient(t, rk2).ID() == a.ID() {
		t.Fatal("two recovery keys give one recipient")
	}
	obj := sealBytes(t, a, KindContent, testID, 0, []byte("x"))
	if _, err := openBytes(obj, rk2, KindContent); !errors.Is(err, ErrOpen) {
		t.Fatalf("another recovery key: %v, want ErrOpen", err)
	}
	if _, err := RecipientFor(rk1[:15]); !errors.Is(err, ErrShortKey) {
		t.Fatalf("a 15-byte recovery key: %v", err)
	}
	enc, err := json.Marshal(a)
	must(t, err)
	x, dk, err := privateHalves(rk1)
	must(t, err)
	for name, secret := range map[string][]byte{"x25519": x.Bytes(), "mlkem seed": dk.Bytes(), "recovery key": rk1} {
		for _, form := range forms(secret) {
			if bytes.Contains(enc, form) {
				t.Errorf("the encoded recipient holds the %s", name)
			}
		}
	}
	var back Recipient
	must(t, json.Unmarshal(enc, &back))
	if back.ID() != a.ID() {
		t.Fatal("the recipient does not survive its encoding")
	}
}

// #3446: the clear header names no recipient, so a guess at the recovery
// key cannot be checked against many installs' uploads by one lookup. Two
// objects sealed to two recovery keys have the same header apart from the
// per-object ephemeral key and ML-KEM ciphertext, and no object holds the
// recipient's ID or public keys.
func TestTheHeaderNamesNoRecipient(t *testing.T) {
	a, b := recipient(t, rk1), recipient(t, rk2)
	oa := sealBytes(t, a, KindKeyTable, testID, 3, []byte("x"))
	ob := sealBytes(t, b, KindKeyTable, testID, 3, []byte("x"))
	fixed := headerLen - 32 - mlkem.CiphertextSize768
	if fixed != offEph || !bytes.Equal(oa[:fixed], ob[:fixed]) {
		t.Fatal("the header's fixed fields depend on the recipient")
	}
	id := a.id()
	for name, v := range map[string][]byte{"ID": id[:], "hex ID": []byte(a.ID()), "X25519 key": a.X, "ML-KEM key prefix": a.EK[:16]} {
		if bytes.Contains(oa, v) {
			t.Errorf("the object holds the recipient's %s", name)
		}
	}
	// An object in the old layout, with the recipient ID in its header, is
	// refused, not read.
	old := bytes.Clone(oa)
	old[len(magic)] = 1
	if _, err := openBytes(old, rk1, KindKeyTable); !errors.Is(err, ErrHeader) {
		t.Fatalf("a version 1 header: %v, want ErrHeader", err)
	}
}
