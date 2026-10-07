package main

import (
	"errors"
	"strings"
	"testing"
)

// REQ: CH-12, HOST-1f

func TestAVaultErrorDoesNotReachTheOwner(t *testing.T) {
	var got []string
	h := &tpmHost{notify: func(s string) { got = append(got, s) }}
	canary := "/var/lib/agentos/vault/db"
	h.sayErr("couldn't remove the box's copy of the TPM lockout from the vault; I'll try again at the next restart",
		errors.New("unlink "+canary+": permission denied"))
	if len(got) != 1 || strings.Contains(got[0], canary) || strings.Contains(got[0], "unlink") || strings.Contains(got[0], "/var/") {
		t.Fatalf("told %q", got)
	}
}
