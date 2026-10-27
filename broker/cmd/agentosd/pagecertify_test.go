package main

import (
	"context"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner/kernelsock"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// REQ: CH-9

type certKernel struct {
	leaf, ca []byte
	err      error
}

func (k certKernel) Certify(context.Context, []byte) ([]byte, []byte, error) {
	return k.leaf, k.ca, k.err
}

// MIG-4-recovery-f2: the page's certify reaches the kernel, and only the
// page's fixed codes come back from it.
func TestPageCertifyMapsTheKernel(t *testing.T) {
	ctx := context.Background()
	leaf, ca, err := pageCertify{certKernel{leaf: []byte("leaf"), ca: []byte("ca")}}.Certify(ctx, []byte("pub"))
	if err != nil || string(leaf) != "leaf" || string(ca) != "ca" {
		t.Fatalf("certify: %q %q %v", leaf, ca, err)
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{kernelsock.ErrNoAuthority, localapi.ErrNoAuthority},
		{kernelsock.ErrPageRestore, localapi.ErrRestore},
		{kernelsock.Refused{Text: pageca.ErrKey.Error()}, localapi.ErrBadArgs},
		{kernelsock.Refused{Text: pageca.ErrExpired.Error()}, localapi.ErrFailed},
		{kernelsock.ErrSetupOnly, localapi.ErrFailed},
		{errors.New("dial /run/agentos/owner.sock: no such file"), localapi.ErrFailed},
	} {
		leaf, ca, err := pageCertify{certKernel{leaf: []byte("x"), ca: []byte("y"), err: c.err}}.Certify(ctx, []byte("pub"))
		if err == nil || err.Error() != c.want || leaf != nil || ca != nil {
			t.Errorf("%v: got %q %q %v, want %s", c.err, leaf, ca, err, c.want)
		}
	}
	if keyRefusedText != pageca.ErrKey.Error() {
		t.Fatal("keyRefusedText is not pageca.ErrKey's")
	}
}
