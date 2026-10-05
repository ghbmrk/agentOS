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
func (x *box) needles(c Card) []Needle {
	rk, _ := ParseRecoveryKey(c.RecoveryKey)
	return []Needle{
		{Name: "vault data key", Value: dataKey(x.t, x.b.KeysPath, x.rk)},
		{Name: "code-generator seed", Value: x.vaultSeed()},
		{Name: "grid seed", Value: c.GridSeed},
		{Name: "recovery key", Value: rk.b[:]},
		{Name: "recovery key text", Value: []byte(c.RecoveryKey), Text: true},
		{Name: "vault passphrase", Value: []byte(c.VaultPassphrase), Text: true},
		{Name: "api key", Value: x.apiKey, Text: true},
	}
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
	_, err = Reconfirm(nb, []Standing{{"G1", "x"}}, []string{"G1"}, Auth{Code: true, Local: true})
	must(t, err)
	oldSeed := x.vaultSeed()
	_, err = ReEnroll(x.b, x.rk, true, nil)
	must(t, err)
	after, err := Rotate(x.b, []Part{PartWiFi, PartGrid, PartPassphrase}, Auth{Code: true, Local: true}, testGen, nil)
	must(t, err)

	needles := append(x.needles(before), x.needles(after)...)
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

func hasNeedle(fs []Finding, name string) bool {
	for _, f := range fs {
		if f.Needle == name {
			return true
		}
	}
	return false
}
