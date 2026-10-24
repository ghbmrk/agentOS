package main

import (
	"os"
	"testing"

	"github.com/ghbmrk/agentos/broker/localsrv/accountsock"
)

// REQ: CLK-9, CLK-1

// #3006: -mail-owner serves the Connect page's Gmail sign-in on the mail
// clerk's owner socket, only under a uid of the mail process's own.
func TestPageAccountsCallTheMailClerkOnItsOwnUID(t *testing.T) {
	if a, err := pageAccounts("", -1, 982, 981); a != nil || err != nil {
		t.Fatalf("no socket: %v %v", a, err)
	}
	a, err := pageAccounts("/run/agentos-mail/owner.sock", 984, 982, 981)
	if err != nil || len(a) != 1 || a["gmail"] != (accountsock.Gmail{Socket: "/run/agentos-mail/owner.sock", UID: 984}) {
		t.Fatalf("accounts %v %v", a, err)
	}
	for name, c := range map[string]struct {
		sock string
		uid  int
	}{
		"socket alone":   {"/run/agentos-mail/owner.sock", -1},
		"uid alone":      {"", 984},
		"the local UI":   {"/run/agentos-mail/owner.sock", 982},
		"the bridge":     {"/run/agentos-mail/owner.sock", 981},
		"agentosd's own": {"/run/agentos-mail/owner.sock", os.Getuid()},
	} {
		if a, err := pageAccounts(c.sock, c.uid, 982, 981); err == nil || a != nil {
			t.Errorf("%s: %v", name, a)
		}
	}
}
