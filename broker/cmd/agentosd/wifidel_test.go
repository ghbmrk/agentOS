package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CH-9, ONB-5, HW-10

// D-178 (WIFI-del-a, #3234): the core joins no Wi-Fi and runs no setup
// network, so setup mode, page card step included, serves no op that
// lists or joins a home network or rotates the setup network's password.
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
	for _, op := range []string{"page_setup_join", "page_setup_networks", "page_setup_wifi_name", "page_setup_wifi"} {
		if call(op) == nil {
			t.Errorf("%s is served", op)
		}
	}
	for _, op := range localapi.SetupOps {
		if op == "page_setup_join" || op == "page_setup_networks" {
			t.Errorf("%s is still a setup op", op)
		}
	}
}
