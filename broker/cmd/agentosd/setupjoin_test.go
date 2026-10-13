package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/netjoin"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ONB-3, CRED-1

const joinCanary = "CANARY-agentosd-psk-4e7"

// P2-2w c3: setup's join goes to the helper's socket. Joined and saved
// are success; every other code, a helper that answers nothing, and no
// socket at all are the one refusal, which carries no password.
func TestSetupJoinGoesThroughTheHelper(t *testing.T) {
	if joiner("", nil) != nil {
		t.Fatal("a join with no -netjoin-sock")
	}
	var code netjoin.Code
	var got netjoin.Request
	dir := filepath.Join(t.TempDir(), "run")
	srv := &sockets.Server{Dir: dir}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); srv.Wait() }()
	if err := srv.Start(ctx, sockets.Endpoint{Name: netjoin.Socket, Peer: sockets.Peer{Kind: "agentosd"},
		Ops: map[string]sockets.Handler{netjoin.OpJoin: func(_ context.Context, _ sockets.Peer, b json.RawMessage) (any, error) {
			if err := json.Unmarshal(b, &got); err != nil {
				return nil, err
			}
			if code == "" {
				return "not an answer", nil
			}
			return netjoin.Answer{Code: code}, nil
		}}}); err != nil {
		t.Fatal(err)
	}
	join := joiner(filepath.Join(dir, netjoin.Socket), nil)
	for _, c := range []netjoin.Code{netjoin.Joined, netjoin.Saved, netjoin.NotJoined, netjoin.Refused, netjoin.Busy, netjoin.Failed, ""} {
		code = c
		err := join(context.Background(), "home", joinCanary)
		if ok := c == netjoin.Joined || c == netjoin.Saved; ok != (err == nil) {
			t.Fatalf("%q gave %v", c, err)
		}
		if err != nil && strings.Contains(err.Error(), joinCanary) {
			t.Fatal("the password is in the error")
		}
		if got != (netjoin.Request{SSID: "home", PSK: joinCanary}) {
			t.Fatalf("helper got %+v", got)
		}
	}
	if err := joiner(filepath.Join(dir, "none.sock"), nil)(context.Background(), "home", joinCanary); err == nil || strings.Contains(err.Error(), joinCanary) {
		t.Fatalf("no helper gave %v", err)
	}
	// Security L8.4: agentosd's call ends before the page's.
	if netjoin.CallTimeout >= localapi.JoinTimeout {
		t.Fatalf("CallTimeout %v is not inside JoinTimeout %v", netjoin.CallTimeout, localapi.JoinTimeout)
	}
}
