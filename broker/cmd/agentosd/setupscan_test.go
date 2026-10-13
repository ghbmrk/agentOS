package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/netjoin"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ONB-3, CRED-1

// P2-2w c4b: setup mode serves the helper's network list on the page's
// socket; with no -netjoin-sock there is no list to ask for.
func TestSetupListsTheHelpersNetworks(t *testing.T) {
	if scanner("") != nil {
		t.Fatal("a scan with no -netjoin-sock")
	}
	dir := filepath.Join(t.TempDir(), "nj")
	helper := &sockets.Server{Dir: dir}
	hctx, hcancel := context.WithCancel(context.Background())
	defer func() { hcancel(); helper.Wait() }()
	if err := helper.Start(hctx, sockets.Endpoint{Name: netjoin.Socket, Peer: sockets.Peer{Kind: "agentosd"},
		Ops: map[string]sockets.Handler{netjoin.OpScan: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return netjoin.Networks{SSIDs: []string{"Neighbor", "Home Net"}}, nil
		}}}); err != nil {
		t.Fatal(err)
	}

	m := newSetupMode(t)
	m.NetJoin = filepath.Join(dir, netjoin.Socket)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.run(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("setup did not stop")
		}
	}()
	c := bridgeclient.Client{Path: filepath.Join(m.Dir, localapi.Socket)}
	var n localapi.Networks
	deadline := time.Now().Add(5 * time.Second)
	for {
		cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := c.Call(cctx, localapi.OpSetupNetworks, nil, &n)
		ccancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("setup never served the list: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !reflect.DeepEqual(n.SSIDs, []string{"Neighbor", "Home Net"}) {
		t.Fatalf("networks %q", n.SSIDs)
	}
	if netjoin.ScanTimeout >= 10*time.Second {
		t.Fatalf("ScanTimeout %v is not inside the page's call", netjoin.ScanTimeout)
	}
}
