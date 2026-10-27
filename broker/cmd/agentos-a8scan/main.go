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
// groups, read through card.StoreRecoveryKey as the unlock path does) and
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

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/clerk/seal"
)

// shippedClerks are the clerks whose sealer keys are needles without a
// -clerk flag: every clerk main the image ships (cmd/agentos-clerk-*).
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
	rk, err := card.StoreRecoveryKey(line)
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

// run opens the store at sp with the recovery key rk (card.StoreRecoveryKey
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
	key, id, err := unwrapRecovery(raw, rk)
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
		Needle{Name: "recovery key text", Value: []byte(printed), Text: true},
		Needle{Name: "recovery key bits", Value: bits})
	switch {
	case len(passphrase) >= minPattern:
		ns = append(ns, Needle{Name: "passphrase", Value: []byte(passphrase), Text: true})
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

// cardKey reads the card text rkText, already accepted by
// card.StoreRecoveryKey, as the card prints it (eight dashed groups of
// five, upper case) and as the 160 bits its groups carry, decoded here from
// the printed format alone, so the needle does not come from the code the
// scan audits. It refuses unless card.RecoveryKeyText prints those bits
// back as the same text.
func cardKey(rkText string) (printed string, bits []byte, err error) {
	n := card.Normalize(rkText)
	const groups, group = 8, 5
	if len(n) != groups*group {
		return "", nil, errors.New("the recovery key is not 40 symbols")
	}
	var b [20]byte
	var acc uint64
	nb, j := 0, 0
	for i := 0; i < len(n); i++ {
		if i%group == group-1 {
			continue // the group's check symbol
		}
		v := strings.IndexByte(card.Alphabet, n[i])
		if v < 0 {
			return "", nil, errors.New("the recovery key holds a symbol the card never prints")
		}
		acc = acc<<5 | uint64(v)
		nb += 5
		if nb >= 8 {
			nb -= 8
			b[j] = byte(acc >> nb)
			j++
		}
	}
	gs := make([]string, groups)
	for g := range gs {
		gs[g] = n[g*group : (g+1)*group]
	}
	printed = strings.Join(gs, "-")
	if card.RecoveryKeyText(b) != printed {
		clear(b[:])
		return "", nil, errors.New("the recovery key's bits do not print back as the card text; refusing to scan")
	}
	return printed, b[:], nil
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

// recoverySlot is a recovery slot as the store file holds it (seal.go,
// slot); its JSON with Wrap null is the wrap's associated data.
type recoverySlot struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Salt []byte `json:"salt"`
	Wrap []byte `json:"wrap"`
}

// unwrapRecovery opens the store's data key from the file format alone and
// returns it with the store's ID.
func unwrapRecovery(raw, rk []byte) (key, id []byte, err error) {
	var f struct {
		ID    []byte            `json:"id"`
		Slots []json.RawMessage `json:"slots"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, nil, err
	}
	err = errors.New("the store has no recovery slot this key opens")
	for _, m := range f.Slots {
		var s recoverySlot
		if json.Unmarshal(m, &s) != nil || s.Kind != string(seal.KindRecovery) || len(s.Wrap) < 12 {
			continue
		}
		wrap := s.Wrap
		s.Wrap = nil
		ad, merr := json.Marshal(s)
		if merr != nil {
			return nil, nil, merr
		}
		ad = append(append([]byte(storeLabel+"slot\x00"), f.ID...), ad...)
		kek, kerr := hkdf.Key(sha256.New, rk, s.Salt, storeLabel+"recovery-slot", 32)
		if kerr != nil {
			return nil, nil, kerr
		}
		b, _ := aes.NewCipher(kek)
		clear(kek)
		g, _ := cipher.NewGCM(b)
		if k, oerr := g.Open(nil, wrap[:12], wrap[12:], ad); oerr == nil {
			return k, f.ID, nil
		}
	}
	return nil, nil, err
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
