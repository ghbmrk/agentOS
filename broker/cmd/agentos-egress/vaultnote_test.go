package main

import (
	"errors"
	"strings"
	"testing"
)

// REQ: CH-12

// The texts giveBack and restoreDA send when the chip's lockout can't be
// given back yet or the vault can't forget an entry. The call sites use
// these constants, so the test checks the shipped wording.
func TestAVaultErrorDoesNotReachTheOwner(t *testing.T) {
	canary := "/var/lib/agentos/vault/db"
	for _, sentence := range []string{lockoutReleaseFailed, lockoutForgetFailed, daForgetFailed} {
		var got []string
		h := &tpmHost{notify: func(s string) { got = append(got, s) }}
		h.sayErr(sentence, errors.New("unlink "+canary+": permission denied"))
		if len(got) != 1 || got[0] != sentence {
			t.Fatalf("told %q, want exactly %q", got, sentence)
		}
		text := strings.ToLower(got[0])
		for _, internal := range []string{canary, "unlink", "/var/", "vault", "tpm"} {
			if strings.Contains(text, internal) {
				t.Errorf("%q names %q", got[0], internal)
			}
		}
		if !strings.Contains(got[0], "Nothing to do") {
			t.Errorf("%q doesn't say that nothing is needed", got[0])
		}
	}
}
