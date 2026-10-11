package mailsock_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/mail/mailsock"
	"github.com/ghbmrk/agentos/broker/mail/mailtest"
)

// REQ: CRED-1, M1

// TestAddressNamesOnlyTheAccountsAddress: agentosd learns the owner's
// address over the socket, to bind the adapter (SR3-mail-w2 W2-b). The
// reply carries the address and nothing of the Store; with no account or
// a locked vault it carries only the error code.
func TestAddressNamesOnlyTheAccountsAddress(t *testing.T) {
	srv := mailtest.Start(t)
	path, f := serve(t, account(t, srv))
	got, err := mailsock.NewClient(path).Address(ctx)
	if err != nil || got != me {
		t.Fatalf("address %q %v", got, err)
	}
	if reps := f.replies(); len(reps) != 1 || strings.TrimSpace(reps[0]) != `{"address":"`+me+`"}` {
		t.Fatalf("replies %q", reps)
	}
	if len(srv.Logins()) != 0 {
		t.Fatal("the address op logged in to the mailbox")
	}
	for _, want := range []error{mailsock.ErrNotConnected, mailsock.ErrLocked} {
		path, f := serve(t, func() (mailsock.Account, error) { return mailsock.Account{}, want })
		if got, err := mailsock.NewClient(path).Address(ctx); got != "" || !errors.Is(err, want) {
			t.Fatalf("%v: %q %v", want, got, err)
		}
		if reps := f.replies(); len(reps) != 1 || reps[0] == "" || len(reps[0]) > 32 {
			t.Fatalf("%v: replies %q", want, reps)
		}
	}
	// An account with no address is not one the adapter can bind.
	path, _ = serve(t, func() (mailsock.Account, error) { return mailsock.Account{Store: nil}, nil })
	if got, err := mailsock.NewClient(path).Address(ctx); got != "" || !errors.Is(err, mailsock.ErrNotConnected) {
		t.Fatalf("no address: %q %v", got, err)
	}
}
