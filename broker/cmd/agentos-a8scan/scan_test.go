package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

// REQ: A8
// Acceptance: A8 (the scan tool's scanner, as recovery's copy in #5923)

// The scanner's edges, ported from recovery's
// TestScannerFindsEachLeakOnceAtItsOffsetUpToTheStreamsEdges (#5927): each
// check here fails on a mutant of scan.go that mutgate showed surviving.
func TestScannerFindsEachLeakAtItsOffsetAcrossBlocksAndEncodings(t *testing.T) {
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	has := func(fs []Finding, name, enc string) bool {
		for _, f := range fs {
			if f.Needle == name && (enc == "" || f.Encoding == enc) {
				return true
			}
		}
		return false
	}
	scan := func(nd Needle, blob []byte) []Finding {
		t.Helper()
		s, err := NewScanner([]Needle{nd})
		must(err)
		got, err := s.Reader("t", bytes.NewReader(blob))
		must(err)
		return got
	}

	v := make([]byte, 32)
	for i := range v {
		v[i] = byte(i*37 + 11)
	}
	bin := Needle{Name: "bin", Value: v}

	// Inside a larger base64url blob, at each of the three alignments, a
	// value of 0xff bytes is found as base64url: its standard base64 spells
	// '/' where base64url spells '_', so no other pattern matches.
	ff := Needle{Name: "ff", Value: bytes.Repeat([]byte{0xff}, 24)}
	for align := 0; align < 3; align++ {
		w := append(append([]byte("pre"[:align]), ff.Value...), "suffix-of-some-length"...)
		std := base64.StdEncoding.EncodeToString(w)
		if !strings.ContainsAny(std, "+/") {
			t.Fatalf("align %d: base64 %q has no '+' or '/', so it cannot tell base64url apart", align, std)
		}
		if got := scan(ff, []byte(base64.RawURLEncoding.EncodeToString(w))); !has(got, "ff", "base64url") {
			t.Errorf("base64url inside a blob at align %d: %v", align, got)
		}
	}

	// Inside a larger base32 blob only the value's whole 5-byte groups
	// encode the same; its last, partial group does not.
	for _, e := range []*base32.Encoding{base32.StdEncoding, crockfordEnc} {
		blob := e.EncodeToString(append(append([]byte(nil), v...), "suffix-of-some-length"...))
		for _, b := range []string{blob, strings.ToLower(blob)} {
			if got := scan(bin, []byte(b)); !has(got, "bin", "base32") {
				t.Errorf("base32 inside a blob %.12s...: %v", b, got)
			}
		}
	}

	// Offsets count from the stream's start in every block: the same value
	// at offset 5 and at offset 5 of the third scan window is two findings.
	s, err := NewScanner([]Needle{bin})
	must(err)
	step := int64(1<<20 - s.maxLen + 1) // what each full block moves the window by
	stream := make([]byte, 2*step+5+int64(len(v))+16)
	copy(stream[5:], v)
	copy(stream[2*step+5:], v)
	got, err := s.Reader("t", bytes.NewReader(stream))
	must(err)
	var raw []int64
	for _, f := range got {
		if f.Encoding == "raw" {
			raw = append(raw, f.Offset)
		}
	}
	if len(raw) != 2 || raw[0] != 5 || raw[1] != 2*step+5 {
		t.Errorf("raw findings at %v, want [5 %d]", raw, 2*step+5)
	}

	// A needle longer than a block is carried whole into the next one.
	huge := Needle{Name: "huge", Value: make([]byte, 1<<20+16), Text: true}
	_, err = rand.Read(huge.Value)
	must(err)
	if got := scan(huge, huge.Value); len(got) == 0 || got[0].Encoding != "raw" || got[0].Offset != 0 {
		t.Errorf("a needle longer than a block: %v", got)
	}

	// A read error ends the scan with that error, even when later reads
	// would reach the end: each read here fails at its copy to a closed file.
	closed, err := os.Create(filepath.Join(t.TempDir(), "closed"))
	must(err)
	must(closed.Close())
	if _, err := s.Reader("t", io.TeeReader(bytes.NewReader(stream), closed)); err == nil {
		t.Error("a failing reader scanned as clean")
	}

	// A needle shorter than a pattern is refused.
	if _, err := NewScanner([]Needle{{Name: "7", Value: []byte("needle7")}}); err == nil {
		t.Error("a 7-byte needle was accepted")
	}

	// A whole value is one finding per pattern: two encodings that spell
	// the same text are one pattern, so a value whose hex has no letters
	// reads as one hex finding in either case.
	one := func(what string, got []Finding, enc string) {
		t.Helper()
		if len(got) != 1 || got[0].Encoding != enc || got[0].Offset != 0 {
			t.Errorf("%s: %v, want one %s finding at 0", what, got, enc)
		}
	}
	digits := Needle{Name: "digits", Value: []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56}}
	one("hex with no letters", scan(digits, []byte("1234567890123456")), "hex")

	// A value too short for fragments is found as upper-case hex.
	short := Needle{Name: "short", Value: []byte("needle-8")}
	one("upper hex of a short value", scan(short, []byte(strings.ToUpper(hex.EncodeToString(short.Value)))), "hex")

	// A binary value's hex is found in either case, and the last 15 bytes
	// of it hold its last 12-byte window, found as hex in either case.
	tail := hex.EncodeToString(v[17:])
	for name, e := range map[string]string{
		"hex":      "xxxx" + hex.EncodeToString(v),
		"HEX":      "xxxx" + strings.ToUpper(hex.EncodeToString(v)),
		"tail hex": "xxxx" + tail,
		"tail HEX": "xxxx" + strings.ToUpper(tail),
	} {
		if got := scan(bin, []byte(e)); !has(got, "bin", "") {
			t.Errorf("%s: missed", name)
		}
	}
	if got := scan(bin, []byte("xxxx"+strings.ToUpper(tail))); !has(got, "bin", "hex fragment") {
		t.Errorf("upper tail hex is not a hex fragment: %v", got)
	}

	// A printed secret is also found with no dashes, in lower case, both,
	// and as UTF-16, each as its own form.
	text := Needle{Name: "text", Value: []byte("ABCD-EFGH-JKMN"), Text: true}
	for name, e := range map[string]string{
		"undashed":       "ABCDEFGHJKMN",
		"lower":          "abcd-efgh-jkmn",
		"lower undashed": "abcdefghjkmn",
	} {
		one(name, scan(text, []byte(e)), "text form")
	}
	var u16 []byte
	for _, c := range utf16.Encode([]rune("ABCD-EFGH-JKMN")) {
		u16 = append(u16, byte(c), byte(c>>8))
	}
	one("utf-16", scan(text, u16), "utf-16")
}
