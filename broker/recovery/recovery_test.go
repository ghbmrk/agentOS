package recovery

import (
	"archive/tar"
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: REC-1

func TestRecoveryKeyUsesTheCardFormat(t *testing.T) {
	k := mustKey(t)
	txt := k.Text()
	// Eight groups of four key symbols, each followed by a check symbol.
	if len(txt) != 47 || strings.Count(txt, "-") != 7 {
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
	for _, bad := range []string{clean[:39], clean + "A", clean[:39] + "0", clean[:39] + "I", ""} {
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

func otherSym(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

// Every one-symbol typo and every swap of two neighbouring symbols is
// caught, and the owner is told which group to look at.
func TestARecoveryKeyTypoNamesItsGroup(t *testing.T) {
	for n := 0; n < 20; n++ {
		clean := strings.ReplaceAll(mustKey(t).Text(), "-", "")
		for i := 0; i < len(clean); i++ {
			for _, c := range Alphabet {
				if byte(c) == clean[i] {
					continue
				}
				typo := clean[:i] + string(c) + clean[i+1:]
				var g *MistypedError
				if _, err := ParseRecoveryKey(typo); !errors.As(err, &g) || g.Group != i/5+1 {
					t.Fatalf("typo at %d: %v", i, err)
				}
			}
			if i+1 < len(clean) && i/5 == (i+1)/5 && clean[i] != clean[i+1] {
				swap := clean[:i] + clean[i+1:i+2] + clean[i:i+1] + clean[i+2:]
				var g *MistypedError
				if _, err := ParseRecoveryKey(swap); !errors.As(err, &g) || g.Group != i/5+1 {
					t.Fatalf("swap at %d: %v", i, err)
				}
			}
		}
	}
	var g *MistypedError
	clean := strings.ReplaceAll(mustKey(t).Text(), "-", "")
	_, err := ParseRecoveryKey(clean[:20] + otherSym(clean[20]) + clean[21:])
	if !errors.As(err, &g) || err.Error() != "recovery: group 5 of the recovery key looks mistyped; check it against the card" {
		t.Fatalf("message: %v", err)
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

// The mirror of the vault's key-slot format must stay exact: it reads the
// vault's keys file back byte for byte, before and after re-encryption,
// and the format alone unwraps the same key the vault uses.
func TestKeysMirrorMatchesTheVault(t *testing.T) {
	x := newBox(t)
	check := func(when string) {
		raw, err := os.ReadFile(x.b.KeysPath)
		must(t, err)
		kf, err := parseKeys(raw)
		must(t, err)
		out, err := json.Marshal(kf)
		must(t, err)
		if !bytes.Equal(out, raw) {
			t.Fatalf("%s: the mirror does not round-trip the vault's keys file", when)
		}
		// The independent unwrap really is the vault's key.
		if _, err := vault.Open(x.b.VaultPath, dataKey(t, x.b.KeysPath, x.rk)); err != nil {
			t.Fatalf("%s: mirror unwrap: %v", when, err)
		}
	}
	check("before re-encryption")
	// After vault.Reencrypt every slot carries a key ID (V7).
	if _, err := x.b.V.Reencrypt(Factor(x.rk)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(x.b.KeysPath)
	must(t, err)
	if !bytes.Contains(raw, []byte(`"key_id"`)) {
		t.Fatal("no key ID after re-encryption")
	}
	check("after re-encryption")
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
	sameTree(t, filepath.Join(x.dir, "broker"), filepath.Join(dst, "broker"), false)
	// The vault root is the vault's alone; top-level roots are 0700.
	for p, want := range map[string]os.FileMode{"egress": os.ModeDir | 0o700, "broker": os.ModeDir | 0o700,
		"egress/vault": 0o600, "egress/vault.keys": 0o600} {
		if fi, err := os.Lstat(filepath.Join(dst, p)); err != nil || fi.Mode() != want {
			t.Errorf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	if n := RestoreNotice(rep); !strings.Contains(n, "backup made 2026-10-05") || !strings.Contains(n, "leave them off") {
		t.Errorf("notice: %q", n)
	}

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
	sameTree(t, filepath.Join(x.dir, "broker"), filepath.Join(dst, "broker"), false)
	// Nothing authenticates the old drive's broker state.
	if st := LoadState(openAt(t, dst, x.rk).V); !st.Restricted || st.Source != "drive" || !st.Unverified {
		t.Fatalf("state: %+v", st)
	}
	// A different valid key (a typo that slips past the check symbols)
	// opens nothing.
	if _, err := RestoreDrive(x.roots(), mustKey(t), filepath.Join(t.TempDir(), "t"), lay, Options{}, t0); err == nil {
		t.Fatal("another key restored")
	}
}

// SR2-2: a symlink chain written onto the old drive offline (adversary
// D) is refused by a drive restore too, and leaves nothing behind.
func TestDriveRestoreRefusesASymlinkChain(t *testing.T) {
	x := newBox(t)
	b := filepath.Join(x.dir, "broker")
	for _, l := range [][2]string{{"a", "."}, {"b", "a/.."}, {"c", "b/.."}, {"d", "c/.."}, {"e", "d/target"}} {
		must(t, os.Symlink(l[1], filepath.Join(b, l[0])))
	}
	dst := filepath.Join(t.TempDir(), "copy")
	if _, err := RestoreDrive(x.roots(), x.rk, dst, lay, Options{}, t0); err == nil {
		t.Fatal("restored a symlink chain that leaves the root")
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Fatal("left a restore behind")
	}
}

func TestOnlyTheRecoveryKeyOpensABackupAndDamageIsRefused(t *testing.T) {
	x := newBox(t)
	bk := x.backup()
	if _, _, err := x.restore(bk, mustKey(t), t0); err == nil {
		t.Fatal("wrong key opened the backup")
	}
	pl := int(binary.BigEndian.Uint32(bk[:4]))
	// The preamble's fields are exactly prefix's: no slot of any kind.
	// (Its values are random base64, so they are not searched for words.)
	var pre map[string]json.RawMessage
	must(t, json.Unmarshal(bk[4:4+pl], &pre))
	var keys []string
	for k := range pre {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "created,ephemeral,magic,nonce_prefix,version" {
		t.Fatalf("preamble fields: %v", keys)
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
	mk, err := macKey(x.b.V)
	must(t, err)
	// A real drive's files, so that a harmless archive restores.
	keys, _ := os.ReadFile(x.b.KeysPath)
	vlt, _ := os.ReadFile(x.b.VaultPath)
	base := func(tw tarWriter) {
		dir(tw, "egress")
		file(tw, "egress/vault", string(vlt))
		file(tw, "egress/vault.keys", string(keys))
	}
	// seal builds an archive ending with a MAC under key (none when nil).
	seal := func(key []byte, f func(tarWriter)) []byte {
		var buf bytes.Buffer
		must(t, sealTo(pub, &buf, t0, func(raw *tar.Writer) error {
			tw := &digestTar{tw: raw, h: sha256.New()}
			f(tw)
			if key != nil {
				file(raw, macEntry, string(backupMAC(key, tw.h.Sum(nil))))
			}
			return nil
		}))
		return buf.Bytes()
	}
	build := func(f func(tarWriter)) []byte { return seal(mk, func(tw tarWriter) { base(tw); f(tw) }) }
	layerDirs := func(tw tarWriter) {
		for _, d := range []string{"broker", "broker/machines", "broker/machines/m1", "broker/machines/m1/upper"} {
			dir(tw, d)
		}
	}
	if _, _, err := x.restore(build(func(tw tarWriter) {
		file(tw, "egress/fine", "x")
		dir(tw, "broker")
		file(tw, "broker/fine", "x")
		tw.WriteHeader(&tar.Header{Name: "broker/link", Typeflag: tar.TypeSymlink, Linkname: "fine"})
		dir(tw, "broker/machines")
		dir(tw, "broker/machines/m1")
		dir(tw, "broker/machines/m1/upper")
		tw.WriteHeader(&tar.Header{Name: "broker/machines/m1/upper/etc-link", Typeflag: tar.TypeSymlink, Linkname: "/etc/hostname"})
	}), x.rk, t0); err != nil {
		t.Fatalf("control: %v", err)
	}
	evil := map[string][]byte{
		"dotdot":   build(func(tw tarWriter) { file(tw, "../escape", "x") }),
		"absolute": build(func(tw tarWriter) { file(tw, "/tmp/escape", "x") }),
		"through symlink": build(func(tw tarWriter) {
			tw.WriteHeader(&tar.Header{Name: "d", Typeflag: tar.TypeSymlink, Linkname: "/tmp"})
			file(tw, "d/escape", "x")
		}),
		"orphan":    build(func(tw tarWriter) { file(tw, "no/such/dir/f", "x") }),
		"block dev": build(func(tw tarWriter) { tw.WriteHeader(&tar.Header{Name: "sda", Typeflag: tar.TypeBlock, Devmajor: 8}) }),
		"char dev": build(func(tw tarWriter) {
			tw.WriteHeader(&tar.Header{Name: "mem", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 1})
		}),
		"whiteout outside a layer": build(func(tw tarWriter) {
			tw.WriteHeader(&tar.Header{Name: "egress/gone", Typeflag: tar.TypeChar})
		}),
		"hard link": build(func(tw tarWriter) {
			tw.WriteHeader(&tar.Header{Name: "l", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"})
		}),
		"absolute symlink outside a layer": build(func(tw tarWriter) {
			tw.WriteHeader(&tar.Header{Name: "egress/l", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"})
		}),
		"symlink leaving its root": build(func(tw tarWriter) {
			dir(tw, "broker")
			tw.WriteHeader(&tar.Header{Name: "broker/l", Typeflag: tar.TypeSymlink, Linkname: "../egress/vault"})
		}),
		// Security review 2, finding 2 (SR2-2): each link alone stays in
		// its root lexically, but the chain resolves outside it on disk.
		"symlink chain": build(func(tw tarWriter) {
			dir(tw, "broker")
			for _, l := range [][2]string{{"a", "."}, {"b", "a/.."}, {"c", "b/.."}, {"d", "c/.."}, {"e", "d/target"}} {
				tw.WriteHeader(&tar.Header{Name: "broker/" + l[0], Typeflag: tar.TypeSymlink, Linkname: l[1]})
			}
		}),
		"symlink with dotdot staying in": build(func(tw tarWriter) {
			dir(tw, "broker")
			file(tw, "broker/fine", "x")
			tw.WriteHeader(&tar.Header{Name: "broker/l", Typeflag: tar.TypeSymlink, Linkname: "../broker/fine"})
		}),
		"symlink through a restored link": build(func(tw tarWriter) {
			dir(tw, "broker")
			dir(tw, "broker/sub")
			tw.WriteHeader(&tar.Header{Name: "broker/a", Typeflag: tar.TypeSymlink, Linkname: "sub"})
			tw.WriteHeader(&tar.Header{Name: "broker/b", Typeflag: tar.TypeSymlink, Linkname: "a/x"})
		}),
		// L3 MUST-1 on #151: a link outside the layers that targets a
		// layer link resolves on the host through the guest's link.
		"link into a layer's absolute link": build(func(tw tarWriter) {
			layerDirs(tw)
			tw.WriteHeader(&tar.Header{Name: "broker/machines/m1/upper/abs", Typeflag: tar.TypeSymlink, Linkname: "/etc"})
			tw.WriteHeader(&tar.Header{Name: "broker/x", Typeflag: tar.TypeSymlink, Linkname: "machines/m1/upper/abs"})
		}),
		"link into a layer's dotdot link": build(func(tw tarWriter) {
			layerDirs(tw)
			tw.WriteHeader(&tar.Header{Name: "broker/machines/m1/upper/up", Typeflag: tar.TypeSymlink, Linkname: "../../../../.."})
			tw.WriteHeader(&tar.Header{Name: "broker/y", Typeflag: tar.TypeSymlink, Linkname: "machines/m1/upper/up"})
		}),
		// L3 MUST-2: a link restored after one whose target runs through
		// its name (the drive walk's order follows names D picks).
		"link made after a target runs through it": build(func(tw tarWriter) {
			layerDirs(tw)
			tw.WriteHeader(&tar.Header{Name: "broker/machines/m1/upper/abs", Typeflag: tar.TypeSymlink, Linkname: "/etc"})
			tw.WriteHeader(&tar.Header{Name: "broker/n", Typeflag: tar.TypeSymlink, Linkname: "z/m1/upper/abs/passwd"})
			tw.WriteHeader(&tar.Header{Name: "broker/z", Typeflag: tar.TypeSymlink, Linkname: "machines"})
		}),
		"link to an ancestor of a layer": build(func(tw tarWriter) {
			layerDirs(tw)
			tw.WriteHeader(&tar.Header{Name: "broker/z", Typeflag: tar.TypeSymlink, Linkname: "machines"})
		}),
		"link made after a plain target runs through it": build(func(tw tarWriter) {
			dir(tw, "broker")
			dir(tw, "broker/sub")
			tw.WriteHeader(&tar.Header{Name: "broker/b", Typeflag: tar.TypeSymlink, Linkname: "a/x"})
			tw.WriteHeader(&tar.Header{Name: "broker/a", Typeflag: tar.TypeSymlink, Linkname: "sub"})
		}),
		"dot slash": build(func(tw tarWriter) { file(tw, "./x", "x") }),
		"duplicate": build(func(tw tarWriter) { file(tw, "egress/vault", "replaced") }),
		"bad keys": seal(mk, func(tw tarWriter) {
			dir(tw, "egress")
			file(tw, "egress/vault", string(vlt))
			file(tw, "egress/vault.keys", strings.Replace(string(keys), `"slots":`, `"seed":"x","slots":`, 1))
		}),
		"vault is a symlink": seal(mk, func(tw tarWriter) {
			dir(tw, "egress")
			file(tw, "egress/vault.real", string(vlt))
			tw.WriteHeader(&tar.Header{Name: "egress/vault", Typeflag: tar.TypeSymlink, Linkname: "vault.real"})
			file(tw, "egress/vault.keys", string(keys))
		}),
		// Anyone with the backup public key can seal an archive, with a
		// genuine vault copied from the drive, but not MAC it.
		"no MAC":            seal(nil, func(tw tarWriter) { base(tw); dir(tw, "broker") }),
		"MAC under another": seal(make([]byte, 32), func(tw tarWriter) { base(tw); dir(tw, "broker") }),
		"entry after the MAC": seal(nil, func(tw tarWriter) {
			base(tw)
			file(tw, macEntry, string(make([]byte, 32)))
			dir(tw, "broker")
		}),
	}
	for name, bk := range evil {
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

// Changing any restored file, mode, owner or link after the box wrote the
// backup fails the MAC, even when it is resealed to the backup key.
func TestRestoreRefusesContentsTheBoxDidNotWrite(t *testing.T) {
	x := newBox(t)
	pub, _ := backupPublic(x.rk)
	priv, _ := backupPrivate(x.rk)
	bk := x.backup()
	// Open the backup as only the key holder could, change one header
	// field of one entry, and reseal with the original MAC entry.
	tamper := func(change func(*tar.Header)) []byte {
		var pre [4]byte
		copy(pre[:], bk[:4])
		ln := binary.BigEndian.Uint32(pre[:])
		var p prefix
		must(t, json.Unmarshal(bk[4:4+ln], &p))
		eph, _ := ecdh.X25519().NewPublicKey(p.Ephemeral)
		shared, _ := priv.ECDH(eph)
		sr, err := newSealReader(bytes.NewReader(bk[4+ln:]), contentKey(shared, p.Ephemeral, pub), p.NoncePrefix, bk[4:4+ln])
		must(t, err)
		tr := tar.NewReader(sr)
		var out bytes.Buffer
		must(t, sealTo(pub, &out, t0, func(tw *tar.Writer) error {
			for {
				hd, err := tr.Next()
				if err == io.EOF {
					return nil
				}
				must(t, err)
				if hd.Name == "broker/journal/000001.log" {
					change(hd)
				}
				body, _ := io.ReadAll(tr)
				if int64(len(body)) != hd.Size {
					body = append(body, make([]byte, hd.Size-int64(len(body)))...)
				}
				must(t, tw.WriteHeader(hd))
				tw.Write(body[:hd.Size])
			}
		}))
		return out.Bytes()
	}
	if _, _, err := x.restore(tamper(func(*tar.Header) {}), x.rk, t0); err != nil {
		t.Fatalf("control: %v", err)
	}
	for name, f := range map[string]func(*tar.Header){
		"mode":  func(h *tar.Header) { h.Mode = 0o644 },
		"owner": func(h *tar.Header) { h.Uid = 4242 },
		"size":  func(h *tar.Header) { h.Size++ },
	} {
		if _, _, err := x.restore(tamper(f), x.rk, t0); err == nil {
			t.Errorf("%s changed: restored", name)
		}
	}
}

func dir(tw tarWriter, name string) {
	tw.WriteHeader(&tar.Header{Name: name + "/", Typeflag: tar.TypeDir, Mode: 0o700})
}

func file(tw tarWriter, name, body string) {
	tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body))})
	tw.Write([]byte(body))
}

// sameTree compares a restored broker root with the original. Without
// kept owners no setuid or setgid bit comes back. The owner state differs
// by design: the restore ends its session (checked by restoredOwner).
func sameTree(t *testing.T, a, b string, keepOwners bool) {
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
		want := fa.Mode()
		if !keepOwners {
			want &^= os.ModeSetuid | os.ModeSetgid
		}
		if rel != "." && want != fb.Mode() {
			t.Errorf("%s: mode %v, restored %v", rel, want, fb.Mode())
		}
		switch {
		case rel == "owner.json":
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
	filepath.WalkDir(b, func(p string, _ fs.DirEntry, _ error) error {
		// The restore's own forget log copy or pending marker (forgetlog.go).
		if !strings.HasPrefix(filepath.Base(p), filepath.Base(lay.ForgetLog)) {
			n++
		}
		return nil
	})
	if n != seen {
		t.Errorf("restored tree has %d entries, original %d", n, seen)
	}
	restoredOwner(t, filepath.Join(b, "owner.json"))
}

// restoredOwner checks the restored owner session ended and spent grid
// cells stayed spent.
func restoredOwner(t *testing.T, p string) {
	t.Helper()
	st, err := owner.FileStore{Path: p}.Load()
	must(t, err)
	if !st.UnlockedUntil.IsZero() || len(st.GridUsed) != 1 {
		t.Errorf("restored owner state: unlocked until %v, grid used %v", st.UnlockedUntil, st.GridUsed)
	}
}

var _ = errors.Is
