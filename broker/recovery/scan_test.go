package recovery

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

// needles are every secret A8 requires to be absent from plaintext.
// A rotated card leaves secrets it did not replace blank.
func (x *box) needles(c Card) []Needle {
	out := []Needle{
		{Name: "vault data key", Value: dataKey(x.t, x.b.KeysPath, x.rk)},
		{Name: "code-generator seed", Value: x.vaultSeed()},
		{Name: "api key", Value: x.apiKey, Text: true},
	}
	if len(c.GridSeed) > 0 {
		out = append(out, Needle{Name: "grid seed", Value: c.GridSeed})
	}
	if rk, err := ParseRecoveryKey(c.RecoveryKey); err == nil {
		out = append(out, Needle{Name: "recovery key", Value: rk.b[:]},
			Needle{Name: "recovery key text", Value: []byte(c.RecoveryKey), Text: true})
	}
	if c.VaultPassphrase != "" {
		out = append(out, Needle{Name: "vault passphrase", Value: []byte(c.VaultPassphrase), Text: true})
	}
	for _, v := range []string{c.SetupSecret} {
		if v != "" {
			out = append(out, Needle{Name: "card secret", Value: []byte(v), Text: true})
		}
	}
	return out
}

// REQ: CRED-8, CRED-1
// Acceptance: A8 (plaintext scan)

func TestNoKeySeedOrGridMaterialInAnyPlaintextOnTheDriveOrInBackups(t *testing.T) {
	x := newBox(t)
	x.withPassphrase()
	// Exercise everything that writes: a backup kept on the drive, a
	// restore, a re-confirmation, a re-enrollment and a rotation. Needles
	// cover the card before and after rotation.
	before := x.card
	bk := x.backup()
	must(t, os.WriteFile(filepath.Join(x.dir, "broker", "backup.agentos"), bk, 0o600))
	nb, dst, err := x.restore(bk, x.rk, t0)
	must(t, err)
	_, err = Reconfirm(nb, Answer{Standing: []Standing{{"G1", "x"}}, Keep: []string{"G1"}}, Auth{Code: true, Local: true}, t0)
	must(t, err)
	oldSeed := x.vaultSeed()
	_, err = ReEnroll(x.b, x.rk, true, nil)
	must(t, err)
	after, err := x.rotate([]Part{PartGrid, PartPassphrase}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk})
	must(t, err)

	needles := append(x.needles(before), x.needles(after.Card)...)
	needles = append(needles, Needle{Name: "old code-generator seed", Value: oldSeed})
	s, err := NewScanner(needles)
	must(t, err)
	for _, root := range []string{x.dir, dst} {
		got, skipped, err := s.Tree(root)
		must(t, err)
		if len(got) != 0 || len(skipped) != 0 {
			t.Fatalf("%s: found %v, skipped %v", root, got, skipped)
		}
	}
}

func TestScannerCatchesEveryEncodingAtEveryAlignmentAcrossBlocks(t *testing.T) {
	x := newBox(t)
	needles := x.needles(x.card)
	s, err := NewScanner(needles)
	must(t, err)
	enc := func(v []byte, text bool) map[string][]byte {
		m := map[string][]byte{
			"raw":       v,
			"hex":       []byte(hex.EncodeToString(v)),
			"HEX":       []byte(strings.ToUpper(hex.EncodeToString(v))),
			"base32":    []byte(base32.StdEncoding.EncodeToString(v)),
			"crockford": []byte(crockfordEnc.EncodeToString(v)),
		}
		if text {
			var u []byte
			for _, x := range utf16.Encode([]rune(string(v))) {
				u = append(u, byte(x), byte(x>>8))
			}
			m["utf16"] = u
			m["undashed"] = []byte(strings.ReplaceAll(string(v), "-", ""))
			m["lower"] = []byte(strings.ToLower(string(v)))
		} else {
			m["15-byte fragment"] = v[3:18]
		}
		return m
	}
	for _, nd := range needles {
		for name, e := range enc(nd.Value, nd.Text) {
			// Embedded in a larger blob at every alignment, the blob
			// encoded as a whole for base64.
			for align := 0; align < 5; align++ {
				pad := make([]byte, (1<<20)-3+align) // straddles the 1 MiB block edge
				rand.Read(pad)
				blob := append(append(append([]byte(nil), pad...), e...), "tail-data"...)
				if got, _ := s.Reader("t", bytes.NewReader(blob)); !hasNeedle(got, nd.Name) {
					t.Errorf("%s as %s at align %d: missed", nd.Name, name, align)
				}
				if name == "raw" {
					w := append(append([]byte("prefix"[:align]), nd.Value...), "suffix-of-some-length"...)
					for _, e64 := range [][]byte{[]byte(base64.StdEncoding.EncodeToString(w)), []byte(base64.RawURLEncoding.EncodeToString(w))} {
						if got, _ := s.Reader("t", bytes.NewReader(e64)); !hasNeedle(got, nd.Name) {
							t.Errorf("%s inside base64 at align %d: missed", nd.Name, align)
						}
					}
				}
			}
		}
	}
	// Clean random data gives nothing.
	if got, _ := s.Reader("t", io.LimitReader(rand.Reader, 8<<20)); len(got) != 0 {
		t.Fatalf("false positives: %v", got)
	}
	// Findings carry no values.
	k := needles[0].Value
	got, _ := s.Reader("t", bytes.NewReader(k))
	if len(got) == 0 || strings.Contains(got[0].String(), hex.EncodeToString(k)[:16]) {
		t.Fatalf("finding: %v", got)
	}
}
func TestScannerFindsEachLeakOnceAtItsOffsetUpToTheStreamsEdges(t *testing.T) {
	scan := func(nd Needle, blob []byte) []Finding {
		t.Helper()
		s, err := NewScanner([]Needle{nd})
		must(t, err)
		got, err := s.Reader("t", bytes.NewReader(blob))
		must(t, err)
		return got
	}
	one := func(what string, got []Finding, enc string, off int64) {
		t.Helper()
		if len(got) != 1 || got[0].Encoding != enc || got[0].Offset != off {
			t.Errorf("%s: %v, want one %s finding at %d", what, got, enc, off)
		}
	}

	// The shortest needle is a pattern, found when it is the whole stream:
	// it starts at the last scanned position and ends at the stream's end.
	short := Needle{Name: "short", Value: []byte("needle-8")}
	if _, err := NewScanner([]Needle{{Name: "7", Value: short.Value[:7]}}); err == nil {
		t.Error("a 7-byte needle was accepted")
	}
	one("8-byte needle as the whole stream", scan(short, short.Value), "raw", 0)

	// A pattern running past the stream's end is no match, even where the
	// unread rest of the buffer holds its tail (zeros here).
	cut := Needle{Name: "cut", Value: []byte("ABCDEFGH\x00\x00\x00\x00")}
	if got := scan(cut, cut.Value[:8]); len(got) != 0 {
		t.Errorf("a needle cut at the stream's end was found: %v", got)
	}

	v := make([]byte, 32)
	for i := range v {
		v[i] = byte(i*37 + 11)
	}
	bin := Needle{Name: "bin", Value: v}
	// The last 15 bytes of a binary value hold its last 12-byte window,
	// found raw and as hex in either case.
	tail := v[17:]
	for name, e := range map[string][]byte{
		"raw":          tail,
		"hex":          []byte(hex.EncodeToString(tail)),
		"HEX":          []byte(strings.ToUpper(hex.EncodeToString(tail))),
		"lower base32": []byte(strings.ToLower(base32.StdEncoding.EncodeToString(v))),
		// Inside a larger encoded blob only the value's whole 5-byte groups
		// encode the same; its last, partial group does not.
		"base32 inside a blob": []byte(base32.StdEncoding.EncodeToString(append(append([]byte(nil), v...), "suffix-of-some-length"...))),
	} {
		if got := scan(bin, append([]byte("xxxx"), e...)); !hasNeedle(got, "bin") {
			t.Errorf("%s: missed", name)
		}
	}
	// A whole encoded value is one finding, at the start of its encoding:
	// the alignments cover each offset of the value once.
	one("base64 of the value", scan(bin, []byte(base64.StdEncoding.EncodeToString(v))), "base64", 0)
	one("base32 of the value", scan(bin, []byte(base32.StdEncoding.EncodeToString(v))), "base32", 0)
	// Two encodings that spell the same text are one pattern: a value
	// whose hex has no letters reads the same in either case.
	digits := Needle{Name: "digits", Value: []byte{0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56}}
	one("hex with no letters", scan(digits, []byte("1234567890123456")), "hex", 0)

	// Offsets count from the stream's start in every block: the same value
	// at offset 5 and at offset 5 of the third scan window is two findings.
	s, err := NewScanner([]Needle{bin})
	must(t, err)
	step := int64(1<<20 - s.maxLen + 1) // what each full block moves the window by
	stream := make([]byte, 2*step+5+int64(len(v))+16)
	copy(stream[5:], v)
	copy(stream[2*step+5:], v)
	got, err := s.Reader("t", bytes.NewReader(stream))
	must(t, err)
	var raw []int64
	for _, f := range got {
		if f.Encoding == "raw" {
			raw = append(raw, f.Offset)
		}
	}
	if len(raw) != 2 || raw[0] != 5 || raw[1] != 2*step+5 {
		t.Errorf("raw findings at %v, want [5 %d]", raw, 2*step+5)
	}

	// Patterns sharing a first 8 bytes at the block edge, where only the
	// shorter fits in this block, both come from the next block, in the
	// order NewScanner added them: the whole hex before its first fragment.
	edge := append(append(make([]byte, step), hex.EncodeToString(v)...), make([]byte, 4096)...)
	got, err = s.Reader("t", bytes.NewReader(edge))
	must(t, err)
	var at []string
	for _, f := range got {
		if f.Offset == step {
			at = append(at, f.Encoding)
		}
	}
	if strings.Join(at, ",") != "hex,hex fragment" {
		t.Errorf("findings at the block edge: %v, want [hex hex fragment]", at)
	}

	// A needle longer than a block is carried whole into the next one.
	huge := Needle{Name: "huge", Value: make([]byte, 1<<20+16), Text: true}
	_, err = rand.Read(huge.Value)
	must(t, err)
	if got := scan(huge, huge.Value); len(got) == 0 || got[0].Encoding != "raw" || got[0].Offset != 0 {
		t.Errorf("a needle longer than a block: %v", got)
	}

	// A read error ends the scan with that error, even when later reads
	// would reach the end: each read here fails at its copy to a closed file.
	closed, err := os.Create(filepath.Join(t.TempDir(), "closed"))
	must(t, err)
	must(t, closed.Close())
	if _, err := s.Reader("t", io.TeeReader(bytes.NewReader(stream), closed)); err == nil {
		t.Error("a failing reader scanned as clean")
	}
}

func TestTheScansOwnKeyReadingRefusesWhatItCannotOpen(t *testing.T) {
	// unwrapRecovery is this package's own reading of the key-slot file,
	// so A8's scan needles do not trust the vault code they audit.
	x := newBox(t)
	raw, err := os.ReadFile(x.b.KeysPath)
	must(t, err)
	if _, err := unwrapRecovery([]byte("{"), x.rk); err == nil || !strings.Contains(err.Error(), "key slots") {
		t.Errorf("an unreadable file: %v", err)
	}
	// With the recovery slot renamed to a TPM slot there is no recovery
	// slot, and the TPM slot is not tried with the recovery key.
	if bytes.Count(raw, []byte(`"kind":"recovery"`)) != 1 {
		t.Fatalf("want one recovery slot in %s", raw)
	}
	tpm := bytes.Replace(raw, []byte(`"kind":"recovery"`), []byte(`"kind":"tpm"`), 1)
	if _, err := unwrapRecovery(tpm, x.rk); err == nil || err.Error() != "recovery: no recovery slot" {
		t.Errorf("no recovery slot: %v", err)
	}
	if _, err := newGCM(make([]byte, 7)); err == nil {
		t.Error("a 7-byte AES key was accepted")
	}
}

func TestNewEntriesStopWhenTheirRandomDrawFails(t *testing.T) {
	// A failed random draw stores nothing: crypto/rand.Reader is swapped for
	// an empty reader around each call (no test in this package is
	// parallel), and the error must be the draw's own, not a later write's.
	real := rand.Reader
	defer func() { rand.Reader = real }()
	dry := func() { rand.Reader = io.LimitReader(real, 0) }
	wet := func() { rand.Reader = real }

	x := newBox(t)
	must(t, x.b.V.Delete(MACKeyName))
	dry()
	err := ensureMACKey(x.b.V)
	wet()
	if err != io.EOF {
		t.Fatalf("ensureMACKey on a failed draw: %v", err)
	}
	if _, ok := entryKind(x.b.V, MACKeyName); ok {
		t.Fatal("a MAC key was stored from a failed draw")
	}

	// No forget key: the draw for its counter authorization fails.
	y := newBox(t)
	must(t, y.b.V.Delete(ForgetKeyName))
	dry()
	err = ensureForgetLog(y.b.V, y.rk, nil)
	wet()
	if err != io.EOF {
		t.Fatalf("no forget key: %v", err)
	}
	if _, ok := entryKind(y.b.V, ForgetKeyName); ok {
		t.Fatal("a forget key was stored from a failed draw")
	}

	// No log: the draw for its ID fails.
	z := newBox(t)
	must(t, z.b.V.Delete(ForgetLogName))
	dry()
	err = ensureForgetLog(z.b.V, z.rk, nil)
	wet()
	if err != io.EOF {
		t.Fatalf("no forget log: %v", err)
	}
	if _, ok := entryKind(z.b.V, ForgetLogName); ok {
		t.Fatal("a forget log was stored from a failed draw")
	}
}

func hasNeedle(fs []Finding, name string) bool {
	for _, f := range fs {
		if f.Needle == name {
			return true
		}
	}
	return false
}

// An empty needle list is refused rather than built into a scanner that
// passes every scan (#5911): before the refusal, NewScanner(nil) left
// maxLen at 0 and Reader panicked on a stream of 1 MiB or more. A scanner
// with a needle reads 2 MiB of zeros, two full blocks, with no finding.
func TestNewScannerRefusesNoNeedlesAndScansAStreamOfTwoBlocks(t *testing.T) {
	for _, ns := range [][]Needle{nil, {}} {
		if s, err := NewScanner(ns); err == nil || s != nil {
			t.Errorf("NewScanner(%#v) = %v, %v; want a refusal", ns, s, err)
		}
	}
	s, err := NewScanner([]Needle{{Name: "short", Value: []byte("needle-8")}})
	must(t, err)
	got, err := s.Reader("zeros", bytes.NewReader(make([]byte, 2<<20)))
	must(t, err)
	if len(got) != 0 {
		t.Errorf("2 MiB of zeros: %v, want no finding", got)
	}
}
