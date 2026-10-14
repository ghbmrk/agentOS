package localui

// REQ: HW-1, CH-7

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// #1185: the page reports the card's network to agentosd before it
// provisions, so the network agentos-ap serves at the confirm is on the
// box before the latch. A report that fails fails the provision: the card
// stays shown and nothing latches, so the phone never loses the box's
// Wi-Fi at a confirm with no network to rejoin.
func TestServeCardNetReportsBeforeProvision(t *testing.T) {
	c, err := card.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	var got localapi.SetupAPNet
	refuse := false
	a := AgentosdSetup{Owner: InProcess{localapi.OpSetupAPNet: func(_ context.Context, _ sockets.Peer, args json.RawMessage) (any, error) {
		calls = append(calls, "report")
		if err := json.Unmarshal(args, &got); err != nil {
			return nil, err
		}
		if refuse {
			return nil, sockets.Code(localapi.ErrFailed)
		}
		return struct{}{}, nil
	}}}
	prov := ServeCardNet(func(*card.Card) error {
		calls = append(calls, "provision")
		return nil
	}, a)
	if err := prov(c); err != nil || fmt.Sprint(calls) != "[report provision]" {
		t.Fatalf("%v, calls %v", err, calls)
	}
	if got.SSID != c.WiFiName || got.Password != c.WiFiPassword {
		t.Fatal("the report did not carry the card's network")
	}
	refuse, calls = true, nil
	if err := prov(c); err == nil || fmt.Sprint(calls) != "[report]" {
		t.Fatalf("a refused report: %v, calls %v", err, calls)
	}
	refuse, calls = false, nil
	failed := errors.New("vault down")
	prov = ServeCardNet(func(*card.Card) error { calls = append(calls, "provision"); return failed }, a)
	if err := prov(c); !errors.Is(err, failed) {
		t.Fatalf("provision's error lost: %v", err)
	}
}
