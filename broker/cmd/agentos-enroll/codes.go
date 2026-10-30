package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/codecheck/totp"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// -codes is setup's "Add approval codes" (§12.1 step 5, CH-4;
// MIG-4-exit-c2), which comes before the Owner Card and so before the store
// exists. The keeper's codes socket runs it once per connection, as root,
// with no TPM: one request on stdin, one answer line on stdout.
//
//   - {"op":"enrol"} makes a fresh seed, stages it in the setup directory
//     (codeSeedFile, root's alone, replacing an unconfirmed one) and answers
//     its otpauth:// link: the one display copy, which nothing else outside
//     root keeps.
//   - {"op":"confirm","code":"123456"} checks the code the owner's code
//     generator shows against the staged seed, and on a match marks it
//     confirmed with the step it spent. maxConfirmWrong wrong codes drop
//     the staged seed, so the owner enrols again.
//
// Once a seed is confirmed, or a store exists, both answer closed: the seed
// enrollment keeps is the one the owner confirmed. Enrollment with
// -code-seed-file refuses until it is confirmed, then keeps it in the store
// (handoff.CheckerSeedEntry) and removes the staged file once the store is
// in place. So the box follows codes, then card, then store.

// codeSeedFile is the staged seed's name in the setup directory.
const codeSeedFile = "code-seed"

// codeSeedLen is the seed a code generator is given: 160 bits.
const codeSeedLen = 20

// maxConfirmWrong is how many wrong codes one staged seed takes.
const maxConfirmWrong = 10

// maxCodesRequest bounds -codes' request.
const maxCodesRequest = 1 << 10

var (
	errCodesBad    = errors.New("agentos-enroll: the codes request does not read")
	errCodesClosed = errors.New("agentos-enroll: approval codes are already confirmed, or my store is made; I change nothing")
	errCodesNone   = errors.New("agentos-enroll: no approval-code seed is staged; enrol first")
	errCodesWrong  = errors.New("agentos-enroll: that code is not the staged seed's")
	errCodesAgain  = errors.New("agentos-enroll: too many wrong codes; the staged seed is gone, so enrol again")
	errCodesStaged = errors.New("agentos-enroll: the staged approval-code seed does not read")
	errCodesUnconf = errors.New("agentos-enroll: approval codes are not confirmed yet; I change nothing")
)

var codesWords = []struct {
	err  error
	word string
}{
	{errCodesBad, "bad"},
	{errCodesClosed, "closed"},
	{errCodesNone, "none"},
	{errCodesWrong, "wrong"},
	{errCodesAgain, "again"},
}

type codesRequest struct {
	Op   string `json:"op"`
	Code string `json:"code,omitempty"`
}

type codesAnswer struct {
	Word string `json:"word"`
	URI  string `json:"uri,omitempty"`
}

// stagedSeed is codeSeedFile's content: a state byte, the wrong codes so
// far, then the seed in handoff.EncodeCodeSeed's form, whose step is the
// confirming code's.
type stagedSeed struct {
	confirmed bool
	wrong     int
	seed      handoff.CodeSeed
}

func (s stagedSeed) marshal() ([]byte, error) {
	v, err := handoff.EncodeCodeSeed(s.seed)
	if err != nil {
		return nil, err
	}
	defer clear(v)
	state := byte('u')
	if s.confirmed {
		state = 'c'
	}
	return append([]byte{state, byte(s.wrong)}, v...), nil
}

func parseStaged(b []byte) (stagedSeed, error) {
	if len(b) < 2 || (b[0] != 'u' && b[0] != 'c') || int(b[1]) >= maxConfirmWrong {
		return stagedSeed{}, errCodesStaged
	}
	s, err := handoff.ParseCodeSeed(b[2:])
	if err != nil {
		return stagedSeed{}, errCodesStaged
	}
	return stagedSeed{confirmed: b[0] == 'c', wrong: int(b[1]), seed: s}, nil
}

// readStagedSeed reads the staged seed at path, a file only root reads.
func readStagedSeed(path string) (stagedSeed, error) {
	b, err := readSecretMax(path, 2+64+handoff.MaxCodeSeed)
	if err != nil {
		return stagedSeed{}, err
	}
	defer clear(b)
	return parseStaged(b)
}

func writeStagedSeed(dir string, s stagedSeed) error {
	b, err := s.marshal()
	if err != nil {
		return err
	}
	defer clear(b)
	return privfile.WriteAtomic(dir, codeSeedFile, b, nil)
}

// codesMain runs -codes on in and out and returns the exit status. The
// answer goes to out; the reason, fixed words that hold no part of the seed
// or the code, to errw (the unit's journal).
func codesMain(c config, in io.Reader, out, errw io.Writer, now time.Time) int {
	uri, err := codes(c, in, now)
	a := codesAnswer{Word: "ok", URI: uri}
	if err != nil {
		a = codesAnswer{}
		for _, w := range codesWords {
			if errors.Is(err, w.err) {
				a.Word = w.word
			}
		}
	}
	if a.Word != "" {
		json.NewEncoder(out).Encode(a)
	}
	if err != nil {
		log.New(errw, "", 0).Print(err)
		return 1
	}
	return 0
}

// codes serves one request; it returns the link for enrol.
func codes(c config, in io.Reader, now time.Time) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(in, maxCodesRequest+1))
	if err != nil || len(raw) > maxCodesRequest {
		return "", errCodesBad
	}
	var r codesRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || dec.More() || (r.Op != "enrol" && r.Op != "confirm") || (r.Op == "enrol") != (r.Code == "") {
		return "", errCodesBad
	}
	if ok, err := exists(c.storePath()); err != nil {
		return "", err
	} else if ok {
		return "", errCodesClosed
	}
	path := filepath.Join(c.setupDir, codeSeedFile)
	s, err := readStagedSeed(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if r.Op == "confirm" {
			return "", errCodesNone
		}
	case err != nil:
		return "", err
	case s.confirmed:
		s.seed.Wipe()
		return "", errCodesClosed
	}
	if r.Op == "enrol" {
		s.seed.Wipe()
		return enrolCodes(c.setupDir)
	}
	defer s.seed.Wipe()
	step, ok := totp.Match(s.seed.Seed, r.Code, now, 0)
	if !ok {
		s.wrong++
		if s.wrong >= maxConfirmWrong {
			if err := os.Remove(path); err != nil {
				return "", err
			}
			return "", errCodesAgain
		}
		if err := writeStagedSeed(c.setupDir, s); err != nil {
			return "", err
		}
		return "", errCodesWrong
	}
	s.confirmed, s.wrong, s.seed.Step = true, 0, step
	return "", writeStagedSeed(c.setupDir, s)
}

// enrolCodes stages a fresh seed and returns its link.
func enrolCodes(dir string) (string, error) {
	seed := make([]byte, codeSeedLen)
	defer clear(seed)
	if _, err := rand.Read(seed); err != nil {
		return "", err
	}
	if err := writeStagedSeed(dir, stagedSeed{seed: handoff.CodeSeed{Seed: seed}}); err != nil {
		return "", err
	}
	return otpauthURI(seed), nil
}

// otpauthURI is the link the owner's code generator scans (ONB-6): SHA-1,
// 6 digits, 30-second steps, as totp.Match checks.
func otpauthURI(seed []byte) string {
	q := url.Values{}
	q.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed))
	q.Set("issuer", "agentOS")
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/agentOS:box?" + q.Encode()
}

// confirmedSeed is the confirmed staged seed enrollment keeps, read before
// anything changes: none staged, or one not confirmed, refuses.
func confirmedSeed(path string) (handoff.CodeSeed, error) {
	s, err := readStagedSeed(path)
	if errors.Is(err, os.ErrNotExist) {
		return handoff.CodeSeed{}, errCodesUnconf
	}
	if err != nil {
		return handoff.CodeSeed{}, fmt.Errorf("%w: %w", errCodesStaged, err)
	}
	if !s.confirmed {
		s.seed.Wipe()
		return handoff.CodeSeed{}, errCodesUnconf
	}
	return s.seed, nil
}
