package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-9, ONB-5, HW-10, HW-1

// D-178 (WIFI-del-a, #3234): the core joins no Wi-Fi and runs no setup
// network, so setup mode, page card step included, serves no op that
// lists or joins a home network or rotates the setup network's password.
// Slice a2: nor does it take the card's Wi-Fi network for an access point
// (page_setup_ap_net).
func TestSetupServesNoWiFiOp(t *testing.T) {
	m := newSetupMode(t)
	m.Card = pageCardStep
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.run(ctx)
	c := bridgeclient.Client{Path: filepath.Join(m.Dir, localapi.Socket)}
	call := func(op string) error {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer ccancel()
		return c.Call(cctx, op, nil, nil)
	}
	deadline := time.Now().Add(5 * time.Second)
	for call(localapi.OpSetupProgress) != nil {
		if time.Now().After(deadline) {
			t.Fatal("setup never served")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, op := range []string{"page_setup_join", "page_setup_networks", "page_setup_wifi_name", "page_setup_wifi", "page_setup_ap_net"} {
		// Only the unknown-op refusal proves the op is gone: a served op
		// also refuses these nil args (bad args, no setup wifi).
		if err := call(op); err == nil || !strings.HasSuffix(err.Error(), ": "+string(sockets.ErrUnknownOp)) {
			t.Errorf("%s: %v, want %q", op, err, sockets.ErrUnknownOp)
		}
	}
	for _, op := range localapi.SetupOps {
		if op == "page_setup_join" || op == "page_setup_networks" {
			t.Errorf("%s is still a setup op", op)
		}
	}
}

// D-178 (WIFI-del-a2, #3234): agentosd keeps no access point's network.
// It takes no -ap-net file, runs no watch or reconcile of one, and the
// page socket has no op that puts a rotated card's Wi-Fi network on the
// air. It catches an access point lifecycle left in agentosd.
func TestAgentosdRunsNoAccessPoint(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"ap-net"`, "watchAPUp", "watchCommittedWiFi", "RotateAPNet"} {
		if strings.Contains(string(src), s) {
			t.Errorf("main.go still has %s", s)
		}
	}
	for _, op := range append(append([]string{}, localapi.Ops...), localapi.SetupOps...) {
		if op == "page_rotate_ap_net" || op == "page_setup_ap_net" {
			t.Errorf("%s is still a page op", op)
		}
	}
}
