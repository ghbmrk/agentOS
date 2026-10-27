package main

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghbmrk/agentos/broker/clerk/seal"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// -take-factors is the Owner Card confirm's hand-off (HW-1, STO-2; brief
// OWN-card-flow decision 5). The keeper's setup socket runs it once per
// connection, as root, with no TPM: it reads one request on stdin from the
// owner page, checks it against the published page certificate, writes the
// card's two factors where enrollment reads them, and answers one word on
// stdout (takeWord). Writing the recovery file is what starts enrollment
// (agentos-keeper-enroll.path).

// maxSetupRequest bounds -take-factors' request (decision 5).
const maxSetupRequest = 8 << 10

const (
	passphraseFile = "passphrase"
	recoveryFile   = "recovery"
)

var (
	errBad       = errors.New("agentos-enroll: the card's factors do not read")
	errAuthority = errors.New("agentos-enroll: the card's fingerprint is not my published page certificate's")
	errTaken     = errors.New("agentos-enroll: another card's factors are already in place")
	errKept      = errors.New("agentos-enroll: my store is made, and this card's passphrase does not open it")
)

// takeWords are -take-factors' answers other than ok. Each changed nothing.
// Any other error answers nothing: the page reads that as a keeper it
// could not reach, and the confirm may be retried.
var takeWords = []struct {
	err  error
	word string
}{
	{errBad, "bad"},
	{errAuthority, "authority"},
	{errTaken, "taken"},
	{errKept, "kept"},
}

func takeWord(err error) string {
	if err == nil {
		return "ok"
	}
	for _, w := range takeWords {
		if errors.Is(err, w.err) {
			return w.word
		}
	}
	return ""
}

// setupRequest is the confirm's request. Passphrase and RecoveryKey are the
// card's text as it prints them; Fingerprint is the page certificate's, as
// the shown card printed it.
type setupRequest struct {
	V           int      `json:"v"`
	Passphrase  cardText `json:"passphrase"`
	RecoveryKey cardText `json:"recovery_key"`
	Fingerprint string   `json:"fingerprint"`
}

// cardText is a JSON string read into bytes the caller can wipe, with no
// string copy. The card prints neither factor with a character JSON
// escapes, so an escape is refused.
type cardText []byte

func (t *cardText) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' || bytes.IndexByte(b, '\\') >= 0 {
		return errBad
	}
	*t = append(cardText(nil), b[1:len(b)-1]...)
	return nil
}

func (r *setupRequest) wipe() {
	clear(r.Passphrase)
	clear(r.RecoveryKey)
}

// takeFactorsMain runs -take-factors on in and out and returns the exit
// status. The word goes to out; the reason, fixed words that never hold a
// factor or any part of the request, to errw (the unit's journal).
func takeFactorsMain(c config, in io.Reader, out, errw io.Writer) int {
	err := takeFactors(c, in)
	if w := takeWord(err); w != "" {
		fmt.Fprintln(out, w)
	}
	if err != nil {
		log.New(errw, "", 0).Print(err)
		return 1
	}
	return 0
}

// takeFactors validates the request, then: with a store in place, answers
// ok if the passphrase opens its passphrase slot (the store was made from
// this card) and kept if not, writing nothing; otherwise checks the
// fingerprint against the published certificate and writes the passphrase,
// then the recovery key (32 bytes, hex, card.StoreRecoveryKey of the text),
// each once (writeOnce). Factors already in place answer ok when they are
// this card's and taken when not.
func takeFactors(c config, in io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(in, maxSetupRequest+1))
	defer clear(raw)
	if err != nil || len(raw) > maxSetupRequest {
		return errBad
	}
	var r setupRequest
	defer r.wipe()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || dec.More() || r.V != 1 || !validPassphrase(r.Passphrase) {
		return errBad
	}
	rk, err := storeRecoveryKey(r.RecoveryKey)
	if err != nil {
		return errBad
	}
	defer clear(rk)
	if ok, err := exists(c.storePath()); err != nil {
		return err
	} else if ok {
		st, err := seal.Unlock(c.storePath(), seal.Passphrase{Phrase: r.Passphrase})
		if errors.Is(err, seal.ErrWrongFactor) || errors.Is(err, seal.ErrNoSlot) {
			return errKept
		} else if err != nil {
			return err
		}
		st.Close()
		return nil
	}
	der, err := readPublished(c.pageCACert)
	if errors.Is(err, os.ErrNotExist) {
		return errAuthority
	} else if err != nil {
		return err
	}
	if pageca.Fingerprint(der) != r.Fingerprint {
		return errAuthority
	}
	rec := make([]byte, hex.EncodedLen(len(rk)))
	defer clear(rec)
	hex.Encode(rec, rk)
	return putFactors(c.setupDir, r.Passphrase, rec)
}

// putFactors writes the passphrase, then the recovery file, each once. The
// recovery file comes last because its existence starts enrollment. Files
// already there are compared first, in constant time, so a refusal writes
// nothing: this card's (a retried confirm, or one cut between the two
// writes) are kept as they are, and another card's in either file is taken.
func putFactors(dir string, pass, rec []byte) error {
	fs := []struct {
		path string
		v    []byte
		have bool
	}{{path: filepath.Join(dir, passphraseFile), v: pass}, {path: filepath.Join(dir, recoveryFile), v: rec}}
	for i := range fs {
		f := &fs[i]
		ok, err := exists(f.path)
		if err != nil || !ok {
			if err != nil {
				return err
			}
			continue
		}
		have, err := readSecret(f.path)
		if err != nil {
			return err
		}
		same := subtle.ConstantTimeCompare(bytes.TrimRight(have, "\n"), f.v) == 1
		clear(have)
		if !same {
			return errTaken
		}
		f.have = true
	}
	for _, f := range fs {
		if f.have {
			continue
		}
		if err := writeOnce(f.path, f.v, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// The Owner Card's formats, read here from the format alone rather than by
// linking broker/card, which would bring its page, QR encoder and the
// owner's parsers into this root binary (tools/trusted_base_parsers.txt);
// TestCardFormatMatchesCard holds the readings equal to card's.
const (
	cardAlphabet   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	cardGroups     = 8
	cardGroupKey   = 4 // key symbols per group, then a check symbol
	cardKeyBytes   = 20
	cardStoreInfo  = "agentos.card.store-recovery.v1"
	cardWords      = 7 // card.PassphraseWords
	cardWordMinLen = 3 // the shortest and longest words of card's list
	cardWordMaxLen = 9
)

// validPassphrase is the card passphrase's shape, in the form the card
// prints and the store seals: cardWords words of the list's letters (a to z,
// and a hyphen inside a word), each cardWordMinLen to cardWordMaxLen long,
// single spaces between them (card.NormalizePassphrase's form).
func validPassphrase(p []byte) bool {
	words := bytes.Split(p, []byte{' '})
	if len(words) != cardWords {
		return false
	}
	for _, w := range words {
		if len(w) < cardWordMinLen || len(w) > cardWordMaxLen || w[0] == '-' || w[len(w)-1] == '-' {
			return false
		}
		for _, ch := range w {
			if (ch < 'a' || ch > 'z') && ch != '-' {
				return false
			}
		}
	}
	return true
}

// storeRecoveryKey is card.StoreRecoveryKey on the card's text: spaces,
// dashes and tabs dropped and case ignored, 40 symbols in eight groups
// whose every check symbol holds, read to the card's 160 bits, then
// HKDF-SHA256 of those to seal.RecoveryLen bytes. Nothing it reads is
// copied to a string.
func storeRecoveryKey(text []byte) ([]byte, error) {
	var n [cardGroups * (cardGroupKey + 1)]byte
	var b [cardKeyBytes]byte
	var grp [cardGroupKey + 1]byte
	var acc uint64
	defer func() { clear(n[:]); clear(b[:]); clear(grp[:]); acc = 0 }()
	k := 0
	for _, ch := range text {
		switch {
		case ch == ' ' || ch == '-' || ch == '\t':
			continue
		case k == len(n):
			return nil, errBad
		case ch >= 'a' && ch <= 'z':
			ch -= 'a' - 'A'
		}
		n[k] = ch
		k++
	}
	if k != len(n) {
		return nil, errBad
	}
	bits, j := 0, 0
	for g := 0; g < cardGroups; g++ {
		for i := range grp {
			s := strings.IndexByte(cardAlphabet, n[g*(cardGroupKey+1)+i])
			if s < 0 {
				return nil, errBad
			}
			grp[i] = byte(s)
		}
		if cardCheck(grp[:cardGroupKey]) != grp[cardGroupKey] {
			return nil, errBad
		}
		for _, v := range grp[:cardGroupKey] {
			acc = acc<<5 | uint64(v)
			bits += 5
			if bits >= 8 {
				bits -= 8
				b[j] = byte(acc >> bits)
				j++
			}
		}
	}
	return hkdf.Key(sha256.New, b[:], nil, cardStoreInfo, seal.RecoveryLen)
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
