package main

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/codecheck/totp"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
)

// REQ: CH-4, STO-2, ONB-6

// codesCall runs one -codes request and returns its answer.
func codesCall(t *testing.T, c config, req string, now time.Time) codesAnswer {
	t.Helper()
	var out bytes.Buffer
	codesMain(c, strings.NewReader(req), &out, io.Discard, now)
	var a codesAnswer
	if out.Len() > 0 {
		noErr(t, json.Unmarshal(out.Bytes(), &a))
	}
	return a
}

// seedOf reads the seed back out of an otpauth link, as a code generator
// does.
func seedOf(t *testing.T, uri string) []byte {
	t.Helper()
	u, err := url.Parse(uri)
	noErr(t, err)
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("not an otpauth link: %s", uri)
	}
	s, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	noErr(t, err)
	return s
}

func codesConfig(t *testing.T) config {
	dir := t.TempDir()
	setup, state := filepath.Join(dir, "setup"), filepath.Join(dir, "store")
	noErr(t, os.Mkdir(setup, 0o700))
	noErr(t, os.Mkdir(state, 0o700))
	return config{codes: true, setupDir: setup, state: state}
}

// Setup's code step before the card: enrol stages a seed root's alone and
// shows it once, as a link; a wrong code confirms nothing; the right code
// confirms it; after that, and once a store exists, nothing re-enrols or
// shows a seed again; too many wrong codes drop the staged seed.
func TestCodesStepStagesConfirmsAndCloses(t *testing.T) {
	c := codesConfig(t)
	now := time.Unix(1_800_000_000, 0)
	if a := codesCall(t, c, `{"op":"confirm","code":"123456"}`, now); a.Word != "none" {
		t.Fatalf("confirm with nothing staged: %+v", a)
	}
	a := codesCall(t, c, `{"op":"enrol"}`, now)
	if a.Word != "ok" || !strings.HasPrefix(a.URI, "otpauth://totp/") {
		t.Fatalf("enrol: %+v", a)
	}
	seed := seedOf(t, a.URI)
	path := filepath.Join(c.setupDir, codeSeedFile)
	fi, err := os.Stat(path)
	noErr(t, err)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("the staged seed is %v", fi.Mode())
	}
	// Enrolling again before a confirm replaces the seed: the owner rescans.
	b := codesCall(t, c, `{"op":"enrol"}`, now)
	if b.Word != "ok" || bytes.Equal(seedOf(t, b.URI), seed) {
		t.Fatalf("re-enrol: %+v", b)
	}
	seed = seedOf(t, b.URI)
	wrong := "000000"
	if wrong == totp.At(seed, now) {
		wrong = "000001"
	}
	if a := codesCall(t, c, `{"op":"confirm","code":"`+wrong+`"}`, now); a.Word != "wrong" {
		t.Fatalf("a wrong code: %+v", a)
	}
	if _, err := confirmedSeed(path); !errors.Is(err, errCodesUnconf) {
		t.Fatalf("a wrong code confirmed: %v", err)
	}
	if a := codesCall(t, c, `{"op":"confirm","code":"`+totp.At(seed, now)+`"}`, now); a.Word != "ok" || a.URI != "" {
		t.Fatalf("the right code: %+v", a)
	}
	s, err := confirmedSeed(path)
	if err != nil || !bytes.Equal(s.Seed, seed) || s.Step != now.Unix()/30 {
		t.Fatalf("confirmed: %+v %v", s, err)
	}
	for _, req := range []string{`{"op":"enrol"}`, `{"op":"confirm","code":"` + totp.At(seed, now) + `"}`} {
		if a := codesCall(t, c, req, now); a.Word != "closed" || a.URI != "" {
			t.Fatalf("after the confirm, %s: %+v", req, a)
		}
	}
	for _, req := range []string{`{}`, `{"op":"enrol","code":"1"}`, `{"op":"confirm"}`, `{"op":"show"}`, `{"op":"enrol"} {}`} {
		if a := codesCall(t, c, req, now); a.Word != "bad" {
			t.Errorf("%s: %+v", req, a)
		}
	}

	// Too many wrong codes drop the staged seed.
	d := codesConfig(t)
	seed = seedOf(t, codesCall(t, d, `{"op":"enrol"}`, now).URI)
	if wrong == totp.At(seed, now) {
		wrong = "000002"
	}
	for i := 1; i < maxConfirmWrong; i++ {
		if a := codesCall(t, d, `{"op":"confirm","code":"`+wrong+`"}`, now); a.Word != "wrong" {
			t.Fatalf("wrong code %d: %+v", i, a)
		}
	}
	if a := codesCall(t, d, `{"op":"confirm","code":"`+wrong+`"}`, now); a.Word != "again" {
		t.Fatalf("the last wrong code: %+v", a)
	}
	if a := codesCall(t, d, `{"op":"confirm","code":"`+totp.At(seed, now)+`"}`, now); a.Word != "none" {
		t.Fatalf("the dropped seed confirmed: %+v", a)
	}

	// A store in place closes the step.
	e := codesConfig(t)
	noErr(t, os.WriteFile(e.storePath(), []byte("x"), 0o600))
	if a := codesCall(t, e, `{"op":"enrol"}`, now); a.Word != "closed" {
		t.Fatalf("enrol over a store: %+v", a)
	}
}

// Acceptance (brief MIG-4-exit c2): the box follows codes, then card, then
// store. Enrollment refuses, changing nothing, until the staged seed is
// confirmed; then the store holds the confirmed seed and its spent step,
// the staged file is gone, and the seed was shown only in enrol's one
// answer. Fails if a store could be made without confirmed codes, or if
// the seed outlived setup outside the store.
func TestCodeSeedLandsInTheStoreAndIsShownOnce(t *testing.T) {
	b := newBox(t)
	setup := t.TempDir()
	b.c.codeSeed = filepath.Join(setup, codeSeedFile)
	before := nv(t, b.sw.TPM())
	if err := enroll(b.c, b.sw.TPM()); !errors.Is(err, errCodesUnconf) {
		t.Fatalf("enrollment with no codes: %v", err)
	}
	cc := config{codes: true, setupDir: setup, state: b.c.state}
	now := time.Now()
	a := codesCall(t, cc, `{"op":"enrol"}`, now)
	seed := seedOf(t, a.URI)
	if err := enroll(b.c, b.sw.TPM()); !errors.Is(err, errCodesUnconf) {
		t.Fatalf("enrollment with unconfirmed codes: %v", err)
	}
	if !sameMap(before, nv(t, b.sw.TPM())) {
		t.Fatal("a refused enrollment changed the TPM")
	}
	if ok, _ := exists(b.c.storePath()); ok {
		t.Fatal("a refused enrollment made a store")
	}
	if a := codesCall(t, cc, `{"op":"confirm","code":"`+totp.At(seed, now)+`"}`, now); a.Word != "ok" {
		t.Fatalf("confirm: %+v", a)
	}
	noErr(t, enroll(b.c, b.sw.TPM()))
	v, ok, err := b.enrolled().Get(handoff.CheckerSeedEntry)
	if err != nil || !ok {
		t.Fatalf("no code seed in the store: %v", err)
	}
	s, err := handoff.ParseCodeSeed(v)
	if err != nil || !bytes.Equal(s.Seed, seed) || s.Step != now.Unix()/30 {
		t.Fatalf("the store's seed: %+v %v", s, err)
	}
	gone(t, b.c.codeSeed)
	if a := codesCall(t, cc, `{"op":"enrol"}`, now); a.Word != "closed" || a.URI != "" {
		t.Fatalf("the seed was shown again after the store: %+v", a)
	}
}
