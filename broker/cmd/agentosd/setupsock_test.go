package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/apnet"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: HW-1, ARC-2, ARC-1, CH-7

// HW-1, #1115, #1330: in production the card step runs in
// agentos-localui, so setup mode's card is the page's hold over
// localui.sock: finish answers "card pending" until a finish carries the
// page's report that the card is confirmed, and finishes with it, in one
// call. page_setup_card is not served.
func TestFinishTakesThePageCard(t *testing.T) {
	m := newBareSetupMode(t)
	m.Card = pageCardStep
	done := start(context.Background(), m)
	call := setupCall(t, m)
	var l localapi.EnrollLink
	if err := call(localapi.OpSetupEnroll, nil, &l); err != nil {
		t.Fatal(err)
	}
	var ok localapi.Confirmed
	if err := call(localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, &ok); err != nil || !ok.OK {
		t.Fatalf("confirm %v %v", err, ok)
	}
	finish := func(card bool) error {
		return call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100", Card: card}, nil)
	}
	if err := finish(false); err == nil || !strings.Contains(err.Error(), localapi.ErrCardPending) {
		t.Fatalf("finish without the card: %v", err)
	}
	if err := call("page_setup_card", map[string]bool{"confirmed": true}, nil); err == nil || !strings.Contains(err.Error(), string(sockets.ErrUnknownOp)) {
		t.Fatalf("page_setup_card served: %v", err)
	}
	if err := finish(false); err == nil || !strings.Contains(err.Error(), localapi.ErrCardPending) {
		t.Fatalf("finish after the old report op: %v", err)
	}
	finish(true)
	select {
	case r := <-done:
		if r.err != nil || r.owner != "+15550100100" {
			t.Fatalf("run %q %v", r.owner, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not end at finish")
	}
}

// A card step handed in by a test or another builder takes no report:
// finish's card is ignored and its own hold decides.
func TestOnlyThePagesHoldTakesReports(t *testing.T) {
	m, f := newCardSetup(t)
	done := start(context.Background(), m)
	f.step(t)
	call := setupCall(t, m)
	var l localapi.EnrollLink
	if err := call(localapi.OpSetupEnroll, nil, &l); err != nil {
		t.Fatal(err)
	}
	var ok localapi.Confirmed
	if err := call(localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, &ok); err != nil || !ok.OK {
		t.Fatalf("confirm %v %v", err, ok)
	}
	err := call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100", Card: true}, nil)
	if err == nil || !strings.Contains(err.Error(), localapi.ErrCardPending) {
		t.Fatalf("a report was taken for a step the page does not hold: %v", err)
	}
	_ = done
}

// #1185: the page reports the card's network before the confirm latches,
// and agentosd writes it root-only (ARC-1) for agentos-ap to serve at the
// confirm. Only a network the card prints is taken (not the setup name, a
// bare password, or the card's four symbols without the prefix); a new
// card's report replaces the last. The op is served for the whole setup
// session until finish, not only while the card is shown.
func TestThePageReportsTheCardsNetwork(t *testing.T) {
	m := newBareSetupMode(t)
	m.Card = pageCardStep
	m.APNet = filepath.Join(t.TempDir(), "ap-net.json")
	start(context.Background(), m)
	call := setupCall(t, m)
	for _, bad := range []localapi.SetupAPNet{{}, {SSID: "AgentOS-Setup-AB2C", Password: "ABCD-EFGH-JKLM-NP23"},
		{SSID: "AgentOS-AB2C", Password: "password"}, {SSID: "AB2C", Password: "ABCD-EFGH-JKLM-NP23"}} {
		if err := call(localapi.OpSetupAPNet, bad, nil); err == nil || !strings.Contains(err.Error(), localapi.ErrBadArgs) {
			t.Fatalf("took %q: %v", bad.SSID, err)
		}
	}
	if _, err := os.Lstat(m.APNet); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused report wrote the file: %v", err)
	}
	for _, n := range []apnet.Network{{SSID: "AgentOS-AB2C", Password: "ABCD-EFGH-JKLM-NP23"},
		{SSID: "AgentOS-ZZ99", Password: "ZZZZ-YYYY-XXXX-WWWW"}} {
		if err := call(localapi.OpSetupAPNet, localapi.SetupAPNet{SSID: n.SSID, Password: n.Password}, nil); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(m.APNet)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := apnet.Parse(b); err != nil || got != n {
			t.Fatalf("file holds %v, %v", got, err)
		}
		fi, _ := os.Stat(m.APNet)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", fi.Mode())
		}
	}
}

// With no -ap-net path, or a card step the page does not hold, the op is
// not served.
func TestNoAPNetPathServesNoAPNetOp(t *testing.T) {
	m := newBareSetupMode(t)
	m.Card = pageCardStep
	start(context.Background(), m)
	call := setupCall(t, m)
	if err := call(localapi.OpSetupAPNet, localapi.SetupAPNet{SSID: "AgentOS-AB2C", Password: "ABCD-EFGH-JKLM-NP23"}, nil); err == nil {
		t.Fatal("served with no path")
	}

	m2, f := newCardSetup(t)
	m2.APNet = filepath.Join(t.TempDir(), "ap-net.json")
	start(context.Background(), m2)
	f.step(t)
	if err := setupCall(t, m2)(localapi.OpSetupAPNet, localapi.SetupAPNet{SSID: "AgentOS-AB2C", Password: "ABCD-EFGH-JKLM-NP23"}, nil); err == nil {
		t.Fatal("served for a card step the page does not hold")
	}
	if _, err := os.Lstat(m2.APNet); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrote the file: %v", err)
	}
}

func TestSetupAPNetKeepsThePasswordOutOfLogs(t *testing.T) {
	n := localapi.SetupAPNet{SSID: "AgentOS-AB2C", Password: "CANA-RYCA-NARY-CANA"}
	if s := fmt.Sprintf("%v %+v %#v %s", n, n, n, n); strings.Contains(s, "CANA") {
		t.Fatal(s)
	}
}
