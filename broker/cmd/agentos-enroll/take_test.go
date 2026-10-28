package main

// REQ: HW-1, STO-2

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// setupBox is a first boot after staging: the published certificate, the
// empty setup directory and store directory, and the -take-factors run the
// setup socket starts.
type setupBox struct {
	t  *testing.T
	s  staging
	c  config
	fp string // the published certificate's fingerprint, as a card prints it
}

func newSetupBox(t *testing.T) *setupBox {
	t.Helper()
	s := newStaging(t)
	noErr(t, s.stage())
	state := filepath.Join(t.TempDir(), "store")
	noErr(t, os.Mkdir(state, 0o700))
	return &setupBox{t: t, s: s, fp: pageca.Fingerprint(get(os.ReadFile(s.published))),
		c: config{state: state, setupDir: filepath.Dir(s.staged), pageCACert: s.published, takeFactors: true}}
}

func newCard(t *testing.T) *card.Card {
	t.Helper()
	return get(card.Generate(rand.Reader))
}

func setupRequestFor(cd *card.Card, fp string) []byte {
	v, _ := json.Marshal(map[string]any{"v": 1, "passphrase": cd.VaultPassphrase, "recovery_key": cd.RecoveryKey, "fingerprint": fp})
	return v
}

// ask runs one connection's one-shot and returns its answer and its
// journal.
func (b *setupBox) ask(req []byte) (word, journal string) {
	var out, errw bytes.Buffer
	takeFactorsMain(b.c, bytes.NewReader(req), &out, &errw)
	return strings.TrimSuffix(out.String(), "\n"), errw.String()
}

// setupFiles reads the setup directory: what enrollment would find.
func (b *setupBox) setupFiles() map[string]string {
	b.t.Helper()
	out := map[string]string{}
	for _, e := range get(os.ReadDir(b.c.setupDir)) {
		p := filepath.Join(b.c.setupDir, e.Name())
		fi := get(os.Lstat(p))
		out[e.Name()] = fi.Mode().String() + ":" + string(get(os.ReadFile(p)))
	}
	return out
}

// HW-1, STO-2: what the confirm hands over is what enrollment reads: the
// card's passphrase, and card.StoreRecoveryKey of its printed key.
func TestTakeFactorsWritesWhatEnrollmentReads(t *testing.T) {
	b := newSetupBox(t)
	cd := newCard(t)
	if w, j := b.ask(setupRequestFor(cd, b.fp)); w != "ok" {
		t.Fatalf("answer %q: %s", w, j)
	}
	c := config{passphrase: filepath.Join(b.c.setupDir, passphraseFile), recovery: filepath.Join(b.c.setupDir, recoveryFile)}
	for _, p := range []string{c.passphrase, c.recovery} {
		if m := mode(t, p); m != 0o600 {
			t.Fatalf("%s mode %v", p, m)
		}
	}
	pass, rec, err := factors(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(pass) != cd.VaultPassphrase || !bytes.Equal(rec, get(card.StoreRecoveryKey(cd.RecoveryKey))) {
		t.Fatal("enrollment reads other factors than the card's")
	}
	// The card's key as typed, spaced and in lower case, is the same key.
	b2 := newSetupBox(t)
	typed := setupRequestFor(&card.Card{VaultPassphrase: cd.VaultPassphrase, RecoveryKey: strings.ToLower(strings.ReplaceAll(cd.RecoveryKey, "-", " "))}, b2.fp)
	if w, _ := b2.ask(typed); w != "ok" || b2.setupFiles()[recoveryFile] != b.setupFiles()[recoveryFile] {
		t.Fatalf("the typed key: %q", w)
	}
}

// One case per answer. After each refusal the setup directory is as it was;
// an identical retry is ok and rewrites nothing; with a store in place, the
// answer says whether the card's passphrase opens it, and nothing is
// written.
func TestTakeFactorsAnswers(t *testing.T) {
	cd, other := newCard(t), newCard(t)
	b := newSetupBox(t)
	refused := func(want string, req []byte) {
		t.Helper()
		before := b.setupFiles()
		if w, j := b.ask(req); w != want {
			t.Errorf("answer %q, want %q: %s", w, want, j)
		}
		if !sameMap(before, b.setupFiles()) {
			t.Errorf("a %q answer changed the setup directory", want)
		}
	}
	good := map[string]any{"v": 1, "passphrase": cd.VaultPassphrase, "recovery_key": cd.RecoveryKey, "fingerprint": b.fp}
	with := func(k string, v any) []byte {
		m := map[string]any{}
		for a, x := range good {
			m[a] = x
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return get(json.Marshal(m))
	}
	ws := strings.Fields(cd.VaultPassphrase)
	mistyped := []byte(cd.RecoveryKey)
	mistyped[2] = map[bool]byte{true: 'B', false: 'A'}[mistyped[2] == 'A']
	for name, req := range map[string][]byte{
		"not JSON":           []byte("{"),
		"two values":         append(setupRequestFor(cd, b.fp), setupRequestFor(cd, b.fp)...),
		"oversize":           append(setupRequestFor(cd, b.fp), bytes.Repeat([]byte(" "), maxSetupRequest)...),
		"another version":    with("v", 2),
		"an unknown field":   with("extra", "x"),
		"no passphrase":      with("passphrase", nil),
		"six words":          with("passphrase", strings.Join(ws[:6], " ")),
		"upper case":         with("passphrase", strings.ToUpper(cd.VaultPassphrase)),
		"two spaces":         with("passphrase", strings.Join(ws, "  ")),
		"a digit":            with("passphrase", strings.Join(append(ws[:6], "word9"), " ")),
		"an escape":          with("passphrase", strings.Join(append(ws[:6], "w\"ord"), " ")),
		"a mistyped key":     with("recovery_key", string(mistyped)),
		"a short key":        with("recovery_key", cd.RecoveryKey[:len(cd.RecoveryKey)-1]),
		"a long key":         with("recovery_key", cd.RecoveryKey+"A"),
		"64 hex digits":      with("recovery_key", hex.EncodeToString(make([]byte, 32))),
		"a number for a key": with("recovery_key", 7),
	} {
		t.Run(name, func(t *testing.T) { refused("bad", req) })
	}
	refused("authority", with("fingerprint", strings.ReplaceAll(b.fp, " ", "")))
	refused("authority", with("fingerprint", pageca.Fingerprint([]byte("another certificate"))))

	if w, j := b.ask(setupRequestFor(cd, b.fp)); w != "ok" {
		t.Fatalf("answer %q: %s", w, j)
	}
	refused("ok", setupRequestFor(cd, b.fp))
	refused("taken", setupRequestFor(other, b.fp))
	// Another card's passphrase alone (a write cut before the recovery
	// file) is taken too, and so is this card's beside another's key.
	noErr(t, os.Remove(filepath.Join(b.c.setupDir, recoveryFile)))
	refused("taken", setupRequestFor(other, b.fp))
	mixed := setupRequestFor(&card.Card{VaultPassphrase: cd.VaultPassphrase, RecoveryKey: other.RecoveryKey}, b.fp)
	noErr(t, os.WriteFile(filepath.Join(b.c.setupDir, recoveryFile), []byte(hex.EncodeToString(get(card.StoreRecoveryKey(cd.RecoveryKey)))), 0o600))
	refused("taken", mixed)
	// This card's passphrase alone: the retry finishes the hand-off.
	noErr(t, os.Remove(filepath.Join(b.c.setupDir, recoveryFile)))
	if w, _ := b.ask(setupRequestFor(cd, b.fp)); w != "ok" {
		t.Fatalf("the retry after a cut write: %q", w)
	}

	// No published certificate and no store.
	n := newSetupBox(t)
	noErr(t, os.Remove(n.s.published))
	b = n
	refused("authority", setupRequestFor(cd, n.fp))

	// A store made from cd (enrollment removed the published certificate).
	b = newSetupBox(t)
	st := get(seal.Create(b.c.storePath(), seal.Recovery{Key: get(card.StoreRecoveryKey(cd.RecoveryKey))}))
	get(st.AddSlot(seal.Passphrase{Phrase: []byte(cd.VaultPassphrase)}))
	st.Close()
	noErr(t, os.Remove(b.s.published))
	refused("ok", setupRequestFor(cd, "any"))
	refused("kept", setupRequestFor(other, b.fp))
	refused("bad", with("passphrase", "not a card passphrase"))
}

// No factor, nor any part of a request, reaches the journal or the answer,
// on any path. The answer is a fixed word (checked equal); the journal is
// checked for each whole factor, and for each passphrase word and key group
// once its fixed reasons are cut out, since a short word such as "kept" or
// "open" can be both a card word and a reason's (#3556).
func TestTakeFactorsNeverLogsAFactor(t *testing.T) {
	cd, other := newCard(t), newCard(t)
	canaries := []string{cd.VaultPassphrase, card.Normalize(cd.RecoveryKey), hex.EncodeToString(get(card.StoreRecoveryKey(cd.RecoveryKey)))}
	parts := append(strings.Fields(cd.VaultPassphrase), strings.Split(cd.RecoveryKey, "-")...)
	reasons := []string{errBad.Error(), errAuthority.Error(), errTaken.Error(), errKept.Error()}
	check := func(b *setupBox, req []byte, want string, more ...string) {
		t.Helper()
		w, j := b.ask(req)
		if w != want {
			t.Fatalf("answer %q, want %q: %s", w, want, j)
		}
		j = strings.ToLower(j)
		for _, c := range canaries {
			if strings.Contains(j, strings.ToLower(c)) {
				t.Fatalf("a %q answer's journal holds the factor %q", want, c)
			}
		}
		rest := j
		for _, r := range append(reasons, more...) {
			rest = strings.ReplaceAll(rest, strings.ToLower(r), "")
		}
		for _, c := range parts {
			if strings.Contains(rest, strings.ToLower(c)) {
				t.Fatalf("a %q answer's journal holds the factor part %q: %s", want, c, j)
			}
		}
	}
	b := newSetupBox(t)
	check(b, get(json.Marshal(map[string]any{"v": 2, "passphrase": cd.VaultPassphrase, "recovery_key": cd.RecoveryKey, "fingerprint": b.fp})), "bad")
	check(b, append(setupRequestFor(cd, b.fp), '{'), "bad")
	check(b, setupRequestFor(cd, "wrong"), "authority")
	check(b, setupRequestFor(other, b.fp), "ok")
	check(b, setupRequestFor(cd, b.fp), "taken")
	// A setup directory that cannot take the files: no word, a fixed reason.
	e := newSetupBox(t)
	e.c.setupDir = filepath.Join(t.TempDir(), "missing")
	check(e, setupRequestFor(cd, e.fp), "", (&fs.PathError{Op: "open", Path: e.c.setupDir, Err: syscall.ENOENT}).Error())
	// A store that this card opens, and one it does not.
	s := newSetupBox(t)
	st := get(seal.Create(s.c.storePath(), seal.Recovery{Key: get(card.StoreRecoveryKey(other.RecoveryKey))}))
	get(st.AddSlot(seal.Passphrase{Phrase: []byte(other.VaultPassphrase)}))
	st.Close()
	check(s, setupRequestFor(cd, s.fp), "kept")
	canaries = append(canaries, other.VaultPassphrase)
	check(s, setupRequestFor(other, s.fp), "ok")
}

// The keeper's reading of the card's formats is card's own: every key, as
// printed or typed, gives card.StoreRecoveryKey's key; a mistyped group is
// refused by both; every word on card's list, and every passphrase it
// makes, has the passphrase's shape.
func TestCardFormatMatchesCard(t *testing.T) {
	if cardAlphabet != card.Alphabet || cardWords != card.PassphraseWords {
		t.Fatal("the card's alphabet or word count differs")
	}
	for i := 0; i < 200; i++ {
		var b [20]byte
		get(rand.Read(b[:]))
		text := card.RecoveryKeyText(b)
		for _, typed := range []string{text, strings.ToLower(strings.ReplaceAll(text, "-", " ")), strings.ReplaceAll(text, "-", ""), " " + text + "\t"} {
			want := get(card.StoreRecoveryKey(typed))
			if got, err := storeRecoveryKey([]byte(typed)); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%q: the keeper reads %x, card %x (%v)", typed, got, want, err)
			}
		}
		pos := (i%8)*6 + i%5
		sym := strings.IndexByte(cardAlphabet, text[pos])
		bad := text[:pos] + string(cardAlphabet[(sym+1+i%31)%32]) + text[pos+1:]
		if _, err := card.StoreRecoveryKey(bad); err == nil {
			t.Fatalf("%q: card took a mistyped key", bad)
		}
		if _, err := storeRecoveryKey([]byte(bad)); !errors.Is(err, errBad) {
			t.Fatalf("%q: the keeper took a mistyped key: %v", bad, err)
		}
		if p := get(card.Generate(rand.Reader)).VaultPassphrase; !validPassphrase([]byte(p)) {
			t.Fatalf("%q: a card passphrase is refused", p)
		}
	}
	f := get(os.Open("../../card/eff_large_wordlist.txt"))
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		w := strings.Fields(sc.Text())[1]
		if !validPassphrase([]byte(strings.TrimSpace(strings.Repeat(w+" ", cardWords)))) {
			t.Fatalf("the list's word %q is refused", w)
		}
		n++
	}
	if n != 7776 {
		t.Fatalf("read %d words of card's list", n)
	}
}
