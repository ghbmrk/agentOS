package recovery

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: REC-1

func TestRecoveryKeyUsesTheCardFormat(t *testing.T) {
	k := mustKey(t)
	txt := k.Text()
	if len(txt) != 39 || strings.Count(txt, "-") != 7 {
		t.Fatalf("format: %q", txt)
	}
	for _, c := range strings.ReplaceAll(txt, "-", "") {
		if !strings.ContainsRune(Alphabet, c) {
			t.Fatalf("symbol %q outside the card alphabet", c)
		}
	}
	for _, in := range []string{txt, strings.ToLower(txt), strings.ReplaceAll(txt, "-", " "), strings.ReplaceAll(txt, "-", "")} {
		got, err := ParseRecoveryKey(in)
		if err != nil || got.Text() != txt {
			t.Fatalf("parse %q: %v", in, err)
		}
	}
	clean := strings.ReplaceAll(txt, "-", "")
	for _, bad := range []string{clean[:31], clean + "A", clean[:31] + "0", clean[:31] + "I", ""} {
		if _, err := ParseRecoveryKey(bad); err != ErrRecoveryKeyFormat {
			t.Fatalf("%q accepted", bad)
		}
	}
	for _, s := range []string{k.String(), k.GoString()} {
		if strings.Contains(s, clean[:8]) {
			t.Fatal("key formats its value")
		}
	}
}

// REQ: CRED-8
// Acceptance: A8 (key-slot header contents)

func TestKeySlotsHoldOnlyTPMPassphraseAndRecoverySlots(t *testing.T) {
	x := newBox(t)
	x.withPassphrase()
	raw, err := os.ReadFile(x.b.KeysPath)
	must(t, err)
	must(t, CheckKeys(raw))
	kf, _ := parseKeys(raw)
	kinds := map[string]int{}
	for _, s := range kf.Slots {
		kinds[s.Kind]++
	}
	if len(kinds) != 3 || kinds["tpm"] != 1 || kinds["passphrase"] != 1 || kinds["recovery"] != 1 {
		t.Fatalf("slots: %v", kinds)
	}
	s := string(raw)
	recSlot := s[strings.Index(s, `{"kind":"recovery"`):]
	recSlot = recSlot[:strings.Index(recSlot, "}")+1]
	bad := map[string]string{
		"extra top field":    strings.Replace(s, `"slots":`, `"seed":"AAAA","slots":`, 1),
		"code verifier kind": strings.Replace(s, `"kind":"recovery"`, `"kind":"totp"`, 1),
		"extra slot field":   strings.Replace(s, `"kind":"recovery"`, `"kind":"recovery","grid":"x"`, 1),
		"extra kdf field":    strings.Replace(s, `"threads"`, `"verifier":1,"threads"`, 1),
		"trailing":           s + `{}`,
		"second recovery":    strings.Replace(s, `"slots":[`, `"slots":[`+recSlot+`,`, 1),
		"recovery with kdf":  strings.Replace(s, `"kind":"recovery"`, `"kind":"recovery","kdf":{"salt":"AAAAAAAAAAAAAAAAAAAAAA==","time":1,"memory_kib":1,"threads":1}`, 1),
		"version":            strings.Replace(s, `"version":1`, `"version":2`, 1),
	}
	for name, m := range bad {
		if m == s {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if err := CheckKeys([]byte(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The mirror of the vault's key-slot format must stay exact: a slot
// rewritten by this package still opens in the vault, and the format alone
// unwraps the same key the vault uses.
func TestKeysMirrorMatchesTheVault(t *testing.T) {
	x := newBox(t)
	k := dataKey(t, x.b.KeysPath, x.rk)
	n, err := dropHostSlots(x.b.KeysPath)
	if err != nil || n != 1 {
		t.Fatalf("dropped %d: %v", n, err)
	}
	if k2 := dataKey(t, x.b.KeysPath, x.rk); !bytes.Equal(k, k2) {
		t.Fatal("rewrite changed the wrapped key")
	}
	v, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, Factor(x.rk))
	must(t, err)
	if s, ok := v.Secret("openai"); !ok || s.Reveal() != string(x.apiKey) {
		t.Fatal("vault does not open after the rewrite")
	}
	v.Close()
	// The independent unwrap really is the vault's key.
	if _, err := vault.Open(x.b.VaultPath, k); err != nil {
		t.Fatalf("mirror unwrap: %v", err)
	}
}

// REQ: REC-1
// Acceptance: A8 (restore onto a new drive)

func TestRestoreFromBackupOntoANewDrive(t *testing.T) {
	x := newBox(t)
	x.withPassphrase()
	bk := x.backup()
	later := t0.Add(48 * time.Hour)
	dst := filepath.Join(t.TempDir(), "new-drive")
	rep, err := Restore(bytes.NewReader(bk), x.rk, dst, lay, Options{}, later)
	must(t, err)
	if rep.Files < 5 || rep.DroppedHostSlots != 1 {
		t.Fatalf("report: %+v", rep)
	}
	sameTree(t, filepath.Join(x.dir, "broker"), filepath.Join(dst, "broker"))

	nb := openAt(t, dst, x.rk)
	if s, ok := nb.V.Secret("openai"); !ok || s.Reveal() != string(x.apiKey) {
		t.Fatal("vault contents not restored")
	}
	if s, ok := nb.V.Secret(SeedName); !ok || s.Reveal() != string(x.seed) {
		t.Fatal("code-generator seed not restored")
	}
	raw, _ := os.ReadFile(nb.KeysPath)
	must(t, CheckKeys(raw))
	if strings.Contains(string(raw), `"tpm"`) {
		t.Fatal("restored drive trusts a host (CRED-9)")
	}
	// The card's passphrase still opens it, for unknown-host unlock.
	v, err := vault.OpenSealed(nb.VaultPath, nb.KeysPath, vault.Passphrase(x.card.VaultPassphrase))
	must(t, err)
	v.Close()
	// It boots restricted (REC-2); the old drive does not.
	if st := LoadState(nb.V); !st.Restricted || st.Source != "backup" || !st.RestoredAt.Equal(later) {
		t.Fatalf("state: %+v", st)
	}
	if st := LoadState(x.b.V); st.Restricted {
		t.Fatalf("old drive: %+v", st)
	}
}

func TestRestoreFromTheOldDriveItself(t *testing.T) {
	x := newBox(t)
	dst := filepath.Join(t.TempDir(), "copy")
	if _, err := RestoreDrive(x.roots(), mustKey(t), dst, lay, Options{}, t0); err == nil {
		t.Fatal("restored with a wrong key")
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Fatal("wrong key left a restore behind")
	}
	_, err := RestoreDrive(x.roots(), x.rk, dst, lay, Options{}, t0)
	must(t, err)
	sameTree(t, filepath.Join(x.dir, "broker"), filepath.Join(dst, "broker"))
	if st := LoadState(openAt(t, dst, x.rk).V); !st.Restricted || st.Source != "drive" {
		t.Fatalf("state: %+v", st)
	}
	// A typo in the recovery key parses but opens nothing.
	txt := []byte(x.rk.Text())
	if txt[0] == 'A' {
		txt[0] = 'B'
	} else {
		txt[0] = 'A'
	}
	typo, err := ParseRecoveryKey(string(txt))
	must(t, err)
	if _, err := RestoreDrive(x.roots(), typo, filepath.Join(t.TempDir(), "t"), lay, Options{}, t0); err == nil {
		t.Fatal("a mistyped key restored")
	}
}

func TestOnlyTheRecoveryKeyOpensABackupAndDamageIsRefused(t *testing.T) {
	x := newBox(t)
	bk := x.backup()
	if _, _, err := x.restore(bk, mustKey(t), t0); err == nil {
		t.Fatal("wrong key opened the backup")
	}
	pl := int(binary.BigEndian.Uint32(bk[:4]))
	if pre := string(bk[4 : 4+pl]); strings.Contains(pre, "passphrase") || strings.Contains(pre, "tpm") || strings.Contains(pre, "slot") {
		t.Fatalf("preamble carries a slot: %s", pre)
	}
	cases := map[string][]byte{
		"flipped byte late":   flip(bk, len(bk)-40),
		"flipped byte middle": flip(bk, len(bk)/2),
		"flipped preamble":    flip(bk, 30),
		"truncated":           bk[:len(bk)-10],
		"cut at a chunk":      cutAtChunk(t, bk),
		"trailing data":       append(append([]byte(nil), bk...), 1, 2, 3),
		"empty":               nil,
	}
	for name, c := range cases {
		dst := filepath.Join(t.TempDir(), "d")
		if _, err := Restore(bytes.NewReader(c), x.rk, dst, lay, Options{}, t0); err == nil {
			t.Errorf("%s: restored", name)
		}
		if _, err := os.Lstat(dst); err == nil {
			t.Errorf("%s: left a partial restore", name)
		}
		if _, err := os.Lstat(dst + ".restoring"); err == nil {
			t.Errorf("%s: left the work directory", name)
		}
	}
	if _, err := Restore(bytes.NewReader(bk), x.rk, x.dir, lay, Options{}, t0); err == nil {
		t.Fatal("restore over an existing directory")
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 0x40
	return c
}

// cutAtChunk drops the final chunk, so every remaining chunk verifies.
func cutAtChunk(t *testing.T, bk []byte) []byte {
	off := 4 + int(binary.BigEndian.Uint32(bk[:4]))
	first, last := off, off
	for off < len(bk) {
		last = off
		off += 4 + int(binary.BigEndian.Uint32(bk[off:off+4]))
	}
	if last == first {
		t.Fatal("backup has one chunk; the test needs several")
	}
	return bk[:last]
}

func TestRestoreRefusesEntriesThatEscapeTheTarget(t *testing.T) {
	x := newBox(t)
	pub, err := backupPublic(x.rk)
	must(t, err)
	// A real drive's files, so that a harmless archive restores.
	keys, _ := os.ReadFile(x.b.KeysPath)
	vlt, _ := os.ReadFile(x.b.VaultPath)
	base := func(tw *tar.Writer) {
		dir(tw, "egress")
		file(tw, "egress/vault", string(vlt))
		file(tw, "egress/vault.keys", string(keys))
	}
	build := func(f func(*tar.Writer)) []byte {
		var buf bytes.Buffer
		must(t, sealTo(pub, &buf, t0, func(tw *tar.Writer) error { base(tw); f(tw); return nil }))
		return buf.Bytes()
	}
	if _, _, err := x.restore(build(func(tw *tar.Writer) { file(tw, "egress/fine", "x") }), x.rk, t0); err != nil {
		t.Fatalf("control: %v", err)
	}
	evil := map[string]func(*tar.Writer){
		"dotdot":   func(tw *tar.Writer) { file(tw, "../escape", "x") },
		"absolute": func(tw *tar.Writer) { file(tw, "/tmp/escape", "x") },
		"through symlink": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "d", Typeflag: tar.TypeSymlink, Linkname: "/tmp"})
			file(tw, "d/escape", "x")
		},
		"orphan":    func(tw *tar.Writer) { file(tw, "no/such/dir/f", "x") },
		"block dev": func(tw *tar.Writer) { tw.WriteHeader(&tar.Header{Name: "sda", Typeflag: tar.TypeBlock, Devmajor: 8}) },
		"char dev": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "mem", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 1})
		},
		"hard link": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "l", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"})
		},
		"dot slash": func(tw *tar.Writer) { file(tw, "./x", "x") },
		"duplicate": func(tw *tar.Writer) { file(tw, "egress/vault", "replaced") },
		"bad keys":  func(tw *tar.Writer) { file(tw, "egress/other", "x") },
	}
	for name, f := range evil {
		bk := build(f)
		if name == "bad keys" {
			var buf bytes.Buffer
			must(t, sealTo(pub, &buf, t0, func(tw *tar.Writer) error {
				dir(tw, "egress")
				file(tw, "egress/vault", string(vlt))
				file(tw, "egress/vault.keys", strings.Replace(string(keys), `"slots":`, `"seed":"x","slots":`, 1))
				return nil
			}))
			bk = buf.Bytes()
		}
		if _, dst, err := x.restore(bk, x.rk, t0); err == nil {
			t.Errorf("%s: restored", name)
		} else if _, err := os.Lstat(dst); err == nil {
			t.Errorf("%s: left a restore", name)
		}
		if _, err := os.Lstat("/tmp/escape"); err == nil {
			os.Remove("/tmp/escape")
			t.Fatalf("%s: wrote outside the target", name)
		}
	}
}

func dir(tw *tar.Writer, name string) {
	tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o700})
}

func file(tw *tar.Writer, name, body string) {
	tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body))})
	tw.Write([]byte(body))
}

func sameTree(t *testing.T, a, b string) {
	t.Helper()
	seen := 0
	must(t, filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
		must(t, err)
		rel, _ := filepath.Rel(a, p)
		q := filepath.Join(b, rel)
		fa, err := os.Lstat(p)
		must(t, err)
		fb, err := os.Lstat(q)
		if err != nil {
			t.Fatalf("%s missing after restore", rel)
		}
		seen++
		if rel != "." && fa.Mode() != fb.Mode() {
			t.Errorf("%s: mode %v, restored %v", rel, fa.Mode(), fb.Mode())
		}
		switch {
		case fa.Mode().IsRegular():
			x, _ := os.ReadFile(p)
			y, _ := os.ReadFile(q)
			if !bytes.Equal(x, y) {
				t.Errorf("%s: contents differ", rel)
			}
		case fa.Mode()&fs.ModeSymlink != 0:
			x, _ := os.Readlink(p)
			y, _ := os.Readlink(q)
			if x != y {
				t.Errorf("%s: link %q, restored %q", rel, x, y)
			}
		}
		return nil
	}))
	n := 0
	filepath.WalkDir(b, func(string, fs.DirEntry, error) error { n++; return nil })
	if n != seen {
		t.Errorf("restored tree has %d entries, original %d", n, seen)
	}
}

var _ = errors.Is
