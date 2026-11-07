package main

// REQ: CH-4, ONB-6

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/codecheck/totp"
)

// REV-CHK-save (#4192): a staged-seed write that stops before its rename,
// as a crash would, answers no ok and leaves the staged seed as it was: a
// stopped re-enrol keeps the seed the owner scanned, a stopped wrong code
// leaves the count unchanged, and a stopped confirm confirms nothing, so the
// same code confirms once the write goes through.
func TestStoppedSeedWriteKeepsTheStagedSeed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for step := 0; step < 4; step++ {
		c := codesConfig(t)
		a := codesCall(t, c, `{"op":"enrol"}`, now)
		if a.Word != "ok" {
			t.Fatalf("enrol: %+v", a)
		}
		seed := seedOf(t, a.URI)
		path := filepath.Join(c.setupDir, codeSeedFile)
		before, err := os.ReadFile(path)
		noErr(t, err)
		wrong := "000000"
		if wrong == totp.At(seed, now) {
			wrong = "111111"
		}
		stopped := c
		stopped.seedStop = func(i int) bool { return i == step }
		for _, req := range []string{`{"op":"enrol"}`, `{"op":"confirm","code":"` + wrong + `"}`, `{"op":"confirm","code":"` + totp.At(seed, now) + `"}`} {
			if a := codesCall(t, stopped, req, now); a.Word == "ok" || a.Word == "wrong" || a.URI != "" {
				t.Fatalf("step %d: %s on a stopped write answered %+v", step, req, a)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
				t.Fatalf("step %d: %s moved the staged seed on a stopped write: %v", step, req, err)
			}
		}
		if a := codesCall(t, c, `{"op":"confirm","code":"`+totp.At(seed, now)+`"}`, now); a.Word != "ok" {
			t.Fatalf("step %d: confirm after the stopped writes: %+v", step, a)
		}
	}
}
