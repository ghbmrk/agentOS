// Command agentos-a8scan is A8's at-rest check for an owner session on real
// hardware (broker/recovery/A8-SESSION.md): it opens the sealed store
// (STO-2) with the recovery key, as the unlock path does, and scans a
// drive's plaintext partitions, or any files and directories, for the
// store's data key, the keys derived from it (the log key, the head key,
// the MAC and entries keys, each clerk's sealer key) and every sealed
// secret, in raw, hex, base64 and base32 forms at every alignment. It also checks that the store holds
// only TPM, passphrase and recovery slots.
//
//	agentos-a8scan -store /var/lib/agentos-store/store [-clerk NAME]... TARGET...
//
// The recovery key as the Owner Card prints it (40 symbols in eight
// groups, read to the same key as card.StoreRecoveryKey, as the unlock path
// does) and
// optionally the passphrase are read from standard input with echo off,
// never from the command line; the store holds neither, so the scan
// learns them only from the owner. Each TARGET is a block device or file
// (scanned raw, start to end) or a directory (every regular file, no
// symlinks followed). Before scanning, it plants every needle in a scratch
// blob and stops unless the scan finds all of them, so a clean result
// means something. It prints findings by name, place and encoding, never
// values, and exits 1 on any finding.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/crypto/argon2"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
)

// shippedClerks are the clerks whose seal.Store.Sealer keys are needles
// without a -clerk flag: every clerk main the image ships
// (cmd/agentos-clerk-*). MAIL-keys (#3419) replaces Sealer with keys the
// kernel hands each clerk; the needles for that chain come with it.
var shippedClerks = []string{"mail"}

type clerkList []string

func (c *clerkList) String() string     { return strings.Join(*c, ",") }
func (c *clerkList) Set(v string) error { *c = append(*c, v); return nil }

func main() {
	log.SetFlags(0)
	sp := flag.String("store", "", "the drive's sealed store file")
	var clerks clerkList
	flag.Var(&clerks, "clerk", "a clerk whose sealer key is a needle, besides the shipped ones (repeatable)")
	flag.Parse()
	if *sp == "" || flag.NArg() == 0 {
		log.Fatal("usage: agentos-a8scan -store FILE [-clerk NAME]... TARGET... (recovery key on stdin)")
	}
	in := bufio.NewReader(os.Stdin)
	line := strings.TrimSpace(readSecret(in, "Recovery key (as on the card): "))
	rk, err := storeRecoveryKey(line)
	if err != nil {
		log.Fatal(err)
	}
	pass := strings.TrimRight(readSecret(in, "Passphrase (Enter to skip): "), "\r\n")
	n, err := run(*sp, rk, line, pass, append(clerks, shippedClerks...), flag.Args(), os.Stdout)
	clear(rk)
	if err != nil {
		log.Fatal(err)
	}
	if n > 0 {
		os.Exit(1)
	}
}

// readSecret prompts on standard error and reads one line with terminal
// echo off (when standard input is a terminal).
func readSecret(in *bufio.Reader, prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	fd := os.Stdin.Fd()
	var old syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCGETS, uintptr(unsafe.Pointer(&old))); e == 0 {
		quiet := old
		quiet.Lflag &^= syscall.ECHO
		syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&quiet)))
		defer func() {
			syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TCSETS, uintptr(unsafe.Pointer(&old)))
			fmt.Fprintln(os.Stderr)
		}()
	}
	line, _ := in.ReadString('\n')
	return line
}

// run opens the store at sp with the recovery key rk (storeRecoveryKey
// of the card text rkText), plants and checks every needle, the sealer keys
// of clerks among them, and scans targets. It returns the number of
// findings; an error means no scan result.
func run(sp string, rk []byte, rkText, passphrase string, clerks, targets []string, out io.Writer) (int, error) {
	st, err := seal.Unlock(sp, seal.Recovery{Key: rk})
	if err != nil {
		return 0, fmt.Errorf("the recovery key does not open this store: %w", err)
	}
	defer st.Close()
	for _, s := range st.Slots() {
		switch s.Kind {
		case seal.KindTPM, seal.KindPassphrase, seal.KindRecovery:
		default:
			fmt.Fprintf(out, "FAIL store slots: slot %s is of kind %q\n", s.ID, s.Kind)
			return 1, nil
		}
	}
	fmt.Fprintln(out, "ok   store slots: only TPM, passphrase and recovery")
	needles, err := storeNeedles(sp, st, rk, rkText, passphrase, clerks, out)
	defer func() {
		for _, n := range needles {
			clear(n.Value)
			for _, f := range n.Forms {
				clear(f)
			}
		}
	}()
	if err != nil {
		return 0, err
	}
	s, err := NewScanner(needles)
	if err != nil {
		return 0, err
	}
	if err := control(s, needles); err != nil {
		return 0, err
	}
	fmt.Fprintf(out, "ok   control: all %d needles found when planted\n", len(needles))
	found := 0
	for _, t := range targets {
		fi, err := os.Stat(t)
		if err != nil {
			return found, err
		}
		var got []Finding
		if fi.IsDir() {
			var skipped []string
			got, skipped, err = s.Tree(t)
			for _, p := range skipped {
				fmt.Fprintf(out, "skip %s (not a regular file)\n", p)
			}
		} else {
			var f *os.File
			if f, err = os.Open(t); err == nil {
				got, err = s.Reader(t, f)
				f.Close()
			}
		}
		if err != nil {
			return found, fmt.Errorf("%s: %w", t, err)
		}
		for _, g := range got {
			fmt.Fprintf(out, "FIND %s\n", g)
		}
		if len(got) == 0 {
			fmt.Fprintf(out, "ok   %s: nothing found\n", t)
		}
		found += len(got)
	}
	return found, nil
}

// storeNeedles lists every secret A8's scan must not find in plaintext: the
// store's data key (unwrapped from the recovery slot by this tool's own
// reading of the file format, so the scan does not take the key from the
// code it audits) and the keys derived from it (storePurposes), every
// sealed secret, and the factors the store never holds: the recovery key
// as the slot takes it, as the card prints it and as the card's 160 bits,
// and, when given, the passphrase.
func storeNeedles(sp string, st *seal.Store, rk []byte, rkText, passphrase string, clerks []string, out io.Writer) ([]Needle, error) {
	raw, err := os.ReadFile(sp)
	if err != nil {
		return nil, err
	}
	key, id, rkek, err := unwrapSlot(raw, seal.KindRecovery, recoveryKEK(rk))
	if err != nil {
		return nil, err
	}
	lk, err := st.LogKey()
	if err != nil {
		return nil, err
	}
	// The log key is derived from the data key; if this reading of the
	// format unwrapped anything else, the needle list would be wrong.
	if subtle.ConstantTimeCompare(derive(key, id, "log"), lk[:]) != 1 {
		return nil, errors.New("the store's recovery slot unwraps to a key the store does not use; refusing to scan")
	}
	hk, err := st.HeadKey()
	if err != nil {
		return nil, err
	}
	ns := []Needle{
		{Name: "store data key", Value: key},
		{Name: "store MAC key", Value: derive(key, id, "mac")},
		{Name: "store entries key", Value: derive(key, id, "entries")},
		{Name: "log key", Value: lk[:]},
		{Name: "head key", Value: hk.Seed()},
		{Name: "recovery slot key", Value: rkek},
	}
	if passphrase != "" {
		pk, pid, pkek, err := unwrapSlot(raw, seal.KindPassphrase, passphraseKEK([]byte(passphrase)))
		switch {
		case err == nil && subtle.ConstantTimeCompare(pk, key) == 1 && bytes.Equal(pid, id):
			ns = append(ns, Needle{Name: "passphrase slot key", Value: pkek})
		default:
			fmt.Fprintln(out, "skip passphrase slot key (the passphrase opens no passphrase slot of this store)")
		}
		clear(pk)
	}
	seen := map[string]bool{}
	for _, c := range clerks {
		if seen[c] {
			continue
		}
		seen[c] = true
		ns = append(ns, Needle{Name: "sealer key of clerk " + c, Value: derive(key, id, "sealer/"+c)})
	}
	for _, name := range st.Entries() {
		v, ok, err := st.Get(name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if len(v) < minPattern {
			fmt.Fprintf(out, "skip store entry %s (shorter than %d bytes)\n", name, minPattern)
			continue
		}
		// Only printable text gets the text forms; a binary secret gets
		// the raw and hex fragments instead.
		ns = append(ns, Needle{Name: "store entry " + name, Value: v, Text: printable(v)})
	}
	ns = append(ns, Needle{Name: "recovery key", Value: append([]byte(nil), rk...)})
	printed, bits, err := cardKey(rkText)
	if err != nil {
		return nil, err
	}
	ns = append(ns,
		Needle{Name: "recovery key text", Value: []byte(printed), Text: true, Forms: cardForms(printed)},
		Needle{Name: "recovery key bits", Value: bits})
	switch {
	case len(passphrase) >= minPattern:
		ns = append(ns, Needle{Name: "passphrase", Value: []byte(passphrase), Text: true, Forms: passphraseForms(passphrase)})
	case passphrase != "":
		fmt.Fprintf(out, "skip passphrase (shorter than %d bytes)\n", minPattern)
	}
	return ns, nil
}

// storePurposes names every purpose seal derives a key for under the store
// key, with the needle that covers it, or "" for the one value that is not
// secret. TestEveryStorePurposeIsANeedle fails on a purpose seal.go gains
// that this list lacks, so a new derived key cannot go unscanned.
var storePurposes = map[string]string{
	"mac":     "store MAC key",
	"entries": "store entries key",
	"log":     "log key",
	"head":    "head key",
	"sealer/": "sealer key of clerk ",
	"anchor":  "", // the TPM unlock's anchor: not secret (seal.go, anchor)
}

// The Owner Card's recovery key format (broker/card, recoverykey.go), read
// here from the format alone rather than by linking card, which would bring
// its QR encoder into this tool (tools/trusted_base_parsers.txt);
// TestCardFormatMatchesCard holds the two readings equal. 160 bits as 32
// symbols of cardAlphabet in eight groups of four, each group followed by
// one check symbol.
const (
	cardAlphabet  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	cardGroups    = 8
	cardGroup     = 5 // four key symbols and a check symbol
	cardStoreInfo = "agentos.card.store-recovery.v1"
)

// storeRecoveryKey is card.StoreRecoveryKey: the store's recovery factor,
// HKDF-SHA256 of the card's 160 bits.
func storeRecoveryKey(rkText string) ([]byte, error) {
	_, bits, err := cardKey(rkText)
	if err != nil {
		return nil, err
	}
	defer clear(bits)
	return hkdf.Key(sha256.New, bits, nil, cardStoreInfo, seal.RecoveryLen)
}

// cardKey reads the card text rkText as the card prints it (eight dashed
// groups of five, upper case) and as the 160 bits its groups carry. It
// refuses text of the wrong length, and names the group whose symbol or
// check symbol is wrong.
func cardKey(rkText string) (printed string, bits []byte, err error) {
	n := strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' {
			return -1
		}
		return r
	}, strings.ToUpper(rkText))
	if len(n) != cardGroups*cardGroup {
		return "", nil, errors.New("the recovery key is not the card's 40 symbols")
	}
	b := make([]byte, 20)
	var acc uint64
	nb, j := 0, 0
	gs := make([]string, cardGroups)
	for g := range gs {
		gs[g] = n[g*cardGroup : (g+1)*cardGroup]
		var v [cardGroup]byte
		for i := range v {
			k := strings.IndexByte(cardAlphabet, gs[g][i])
			if k < 0 {
				clear(b)
				return "", nil, fmt.Errorf("group %d of the recovery key looks mistyped; check it against the card", g+1)
			}
			v[i] = byte(k)
		}
		if cardCheck(v[:cardGroup-1]) != v[cardGroup-1] {
			clear(b)
			return "", nil, fmt.Errorf("group %d of the recovery key looks mistyped; check it against the card", g+1)
		}
		for _, x := range v[:cardGroup-1] {
			acc = acc<<5 | uint64(x)
			nb += 5
			if nb >= 8 {
				nb -= 8
				b[j] = byte(acc >> nb)
				j++
			}
		}
	}
	return strings.Join(gs, "-"), b, nil
}

// cardCheck is the card's check symbol, sum(a^(i+1) * s_i) over GF(32)
// (x^5 + x^2 + 1, a = x).
func cardCheck(grp []byte) byte {
	var c, w byte = 0, 1
	for _, v := range grp {
		w = gf32Mul(w, 2)
		c ^= gf32Mul(w, v)
	}
	return c
}

func gf32Mul(a, b byte) byte {
	var p byte
	for b > 0 {
		if b&1 != 0 {
			p ^= a
		}
		b >>= 1
		a <<= 1
		if a&32 != 0 {
			a ^= 0x25
		}
	}
	return p
}

// cardWindow is the shortest run of consecutive card groups the scan looks
// for: three groups carry 60 of the key's 160 bits, so a leak it misses
// leaves at least 100 bits to guess, or 2 groups' worth runs scattered.
const cardWindow = 3

// cardForms are the card text's forms beyond the whole printed text: the
// whole and every run of cardWindow consecutive groups, each with dashes,
// spaces or nothing between groups, in upper and lower case and as
// UTF-16, so a key typed with spaces, or written down in part, is found.
func cardForms(printed string) [][]byte {
	gs := strings.Split(printed, "-")
	var out [][]byte
	runs := [][]string{gs}
	for i := 0; i+cardWindow <= len(gs); i++ {
		runs = append(runs, gs[i:i+cardWindow])
	}
	for _, r := range runs {
		for _, sep := range []string{"-", " ", ""} {
			t := strings.Join(r, sep)
			for _, c := range []string{t, strings.ToLower(t)} {
				out = append(out, []byte(c), utf16le(c))
			}
		}
	}
	return out
}

// passphraseForms are the passphrase's forms beyond the text as typed: the
// form the store and the card read (card.NormalizePassphrase: lower case,
// single spaces), and its words joined by nothing, a dash or an underscore,
// in lower and upper case and as UTF-16.
func passphraseForms(p string) [][]byte {
	words := strings.Fields(strings.ToLower(p))
	var out [][]byte
	for _, sep := range []string{" ", "", "-", "_"} {
		t := strings.Join(words, sep)
		for _, c := range []string{t, strings.ToUpper(t)} {
			out = append(out, []byte(c), utf16le(c))
		}
	}
	return out
}

// printable reports whether v is UTF-8 text with no control characters
// other than tab and newline.
func printable(v []byte) bool {
	if !utf8.Valid(v) {
		return false
	}
	for _, r := range string(v) {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

// storeLabel is seal's HKDF and associated-data prefix (seal.go, label).
const storeLabel = "agentos-store/v1/"

func derive(key, id []byte, purpose string) []byte {
	k, err := hkdf.Key(sha256.New, key, id, storeLabel+purpose, 32)
	if err != nil {
		panic(err)
	}
	return k
}

// fileSlot is a recovery or passphrase slot as the store file holds it
// (seal.go, slot); its JSON with Wrap null is the wrap's associated data.
// Neither kind has a sealed blob or policies, and a recovery slot has no
// Argon cost, so those drop out of the JSON as they do in seal's.
type fileSlot struct {
	ID    string     `json:"id"`
	Kind  string     `json:"kind"`
	Salt  []byte     `json:"salt"`
	Argon *argonCost `json:"argon,omitempty"`
	Wrap  []byte     `json:"wrap"`
}

type argonCost struct {
	Time    uint32 `json:"time"`
	MemKiB  uint32 `json:"mem_kib"`
	Threads uint8  `json:"threads"`
}

// recoveryKEK is the recovery slot's key-wrapping key (seal.go, slotKey).
func recoveryKEK(rk []byte) func(fileSlot) ([]byte, error) {
	return func(s fileSlot) ([]byte, error) {
		return hkdf.Key(sha256.New, rk, s.Salt, storeLabel+"recovery-slot", 32)
	}
}

// passphraseKEK is the passphrase slot's key-wrapping key: Argon2id of the
// passphrase at the slot's own cost (seal.go, slotKey).
func passphraseKEK(phrase []byte) func(fileSlot) ([]byte, error) {
	return func(s fileSlot) ([]byte, error) {
		a := s.Argon
		if a == nil || a.Time < 1 || a.Time > 64 || a.MemKiB < seal.ArgonFloorKiB || a.MemKiB > 4<<20 || a.Threads < 1 {
			return nil, errors.New("the passphrase slot's Argon2id cost is out of range")
		}
		return argon2.IDKey(phrase, s.Salt, a.Time, a.MemKiB, a.Threads, 32), nil
	}
}

// unwrapRecovery opens the store's data key with the recovery key from the
// file format alone and returns it with the store's ID.
func unwrapRecovery(raw, rk []byte) (key, id []byte, err error) {
	key, id, kek, err := unwrapSlot(raw, seal.KindRecovery, recoveryKEK(rk))
	clear(kek)
	return key, id, err
}

// unwrapSlot opens the store's data key through the first slot of kind
// that kekFor's key unwraps, from the file format alone, and returns it with
// the store's ID and that slot's key-wrapping key (itself a needle: with
// the store file it unwraps the data key).
func unwrapSlot(raw []byte, kind seal.Kind, kekFor func(fileSlot) ([]byte, error)) (key, id, kek []byte, err error) {
	var f struct {
		ID    []byte            `json:"id"`
		Slots []json.RawMessage `json:"slots"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, nil, err
	}
	err = fmt.Errorf("the store has no %s slot this factor opens", kind)
	for _, m := range f.Slots {
		var s fileSlot
		if json.Unmarshal(m, &s) != nil || s.Kind != string(kind) || len(s.Wrap) < 12 {
			continue
		}
		wrap := s.Wrap
		s.Wrap = nil
		ad, merr := json.Marshal(s)
		if merr != nil {
			return nil, nil, nil, merr
		}
		ad = append(append([]byte(storeLabel+"slot\x00"), f.ID...), ad...)
		k, kerr := kekFor(s)
		if kerr != nil {
			continue
		}
		b, _ := aes.NewCipher(k)
		g, _ := cipher.NewGCM(b)
		if dk, oerr := g.Open(nil, wrap[:12], wrap[12:], ad); oerr == nil {
			return dk, f.ID, k, nil
		}
		clear(k)
	}
	return nil, nil, nil, err
}

// control plants each needle, hex-encoded and inside base64, in random
// data and requires the scanner to find every one.
func control(s *Scanner, needles []Needle) error {
	for _, n := range needles {
		for _, form := range [][]byte{n.Value, []byte(hex.EncodeToString(n.Value)), []byte(base64.StdEncoding.EncodeToString(append([]byte("x"), n.Value...)))} {
			pad := make([]byte, 4096)
			rand.Read(pad)
			got, err := s.Reader("control", bytes.NewReader(append(append(pad, form...), pad...)))
			if err != nil {
				return err
			}
			hit := false
			for _, g := range got {
				hit = hit || g.Needle == n.Name
			}
			if !hit {
				return fmt.Errorf("control: the scanner missed %s; refusing to report a clean scan", n.Name)
			}
		}
	}
	return nil
}
