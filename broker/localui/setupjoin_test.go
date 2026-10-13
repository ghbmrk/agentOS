package localui

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ONB-3, CRED-1

const joinCanary = "CANARY-localui-psk-8c2"

// P2-2w c3: the page's network step goes to agentosd's OpSetupJoin with
// the typed name and password, and waits up to localapi.JoinTimeout.
func TestJoinNetworkCallsAgentosd(t *testing.T) {
	var got localapi.Join
	var left time.Duration
	a := AgentosdSetup{Owner: InProcess{localapi.OpSetupJoin: func(ctx context.Context, _ sockets.Peer, b json.RawMessage) (any, error) {
		d, _ := ctx.Deadline()
		left = time.Until(d)
		return struct{}{}, json.Unmarshal(b, &got)
	}}}
	if err := a.JoinNetwork("home", joinCanary); err != nil {
		t.Fatal(err)
	}
	if got != (localapi.Join{SSID: "home", Password: joinCanary}) {
		t.Fatalf("sent %+v", got)
	}
	if left <= localapi.JoinTimeout-5*time.Second || left > localapi.JoinTimeout {
		t.Fatalf("call deadline %v, want about %v", left, localapi.JoinTimeout)
	}
	// Security L8.4: the page waits less than the bridge would for it.
	if localapi.JoinTimeout >= bridgeproto.OutboxWait+10*time.Second {
		t.Fatalf("JoinTimeout %v is not inside the bridge's %v", localapi.JoinTimeout, bridgeproto.OutboxWait+10*time.Second)
	}
}

// A refusal is an error the page shows as its one network error, and
// carries no password.
func TestJoinNetworkRefusalIsAnError(t *testing.T) {
	a := AgentosdSetup{Owner: InProcess{localapi.OpSetupJoin: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		return nil, sockets.Code(localapi.ErrNotJoined)
	}}}
	err := a.JoinNetwork("home", joinCanary)
	var r Refused
	if !errors.As(err, &r) || !refused(err, localapi.ErrNotJoined) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), joinCanary) {
		t.Fatal("the password is in the error")
	}
	if err := (AgentosdSetup{Owner: InProcess{}}).JoinNetwork("home", joinCanary); err == nil || strings.Contains(err.Error(), joinCanary) {
		t.Fatalf("an agentosd without the op gave %v", err)
	}
}
