package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// REQ: CH-1, CH-12

// P2-2w c4c: with no owner, agentosd serves the modem bridge's ops on
// owner.sock to the bridge's uid while setup runs, so the page reads the
// box's number and takes PAIR texts; finish stops owner.sock with setup.
func TestSetupServesTheModemLineUntilFinish(t *testing.T) {
	m := newSetupMode(t)
	var recorded []string
	m.Line = modemlink.NewSetup(modemlink.SetupConfig{Record: func(iccid string) error {
		recorded = append(recorded, iccid)
		return nil
	}})
	uid, gid := os.Getuid(), os.Getgid()
	m.ModemUID, m.ModemGID = &uid, &gid
	done := make(chan error, 1)
	go func() { _, err := m.run(context.Background()); done <- err }()
	page := bridgeclient.Client{Path: filepath.Join(m.Dir, localapi.Socket)}
	bridge := bridgeclient.Client{Path: filepath.Join(m.Dir, daemon.OwnerSocket)}
	call := func(c bridgeclient.Client, op string, args, out any) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return c.Call(ctx, op, args, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for call(page, localapi.OpSetupProgress, nil, nil) != nil || call(bridge, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateUnbound, ICCID: "8944500102198304826"}, nil) != nil {
		if time.Now().After(deadline) {
			t.Fatal("setup never served both sockets")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(recorded) != 1 {
		t.Fatalf("the box's SIM was recorded %d times", len(recorded))
	}
	var l localapi.SetupLine
	if err := call(page, localapi.OpSetupLine, nil, &l); err != nil || l.Ready {
		t.Fatalf("an unbound line read ready: %v %+v", err, l)
	}
	if err := call(bridge, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK, Number: "+15550100777"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := call(page, localapi.OpSetupLine, nil, &l); err != nil || !l.Ready || l.Number != "+15550100777" {
		t.Fatalf("line %v %+v", err, l)
	}
	for _, in := range []bridgeproto.Inbound{
		{Line: bridgeproto.LineOwner, From: "+15550100555", Text: "hello", ID: "a"},
		{Line: bridgeproto.LineOwner, From: "+15550100100", Text: "PAIR 4821", ID: "b"},
	} {
		if err := call(bridge, bridgeproto.OpInbound, in, nil); err != nil {
			t.Fatal(err)
		}
	}
	var in localapi.SetupInbound
	if err := call(page, localapi.OpSetupInbound, nil, &in); err != nil || in.From != "+15550100100" || in.Text != "PAIR 4821" {
		t.Fatalf("inbound %v %+v", err, in)
	}
	if err := call(page, localapi.OpSetupEnroll, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := call(page, localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, nil); err != nil {
		t.Fatal(err)
	}
	call(page, localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not end at finish")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, daemon.OwnerSocket)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owner.sock left serving setup's line: %v", err)
	}
}

// A modem line with no bridge uid fails closed: owner.sock is never
// served to just anyone.
func TestSetupLineNeedsTheModemUID(t *testing.T) {
	m := newSetupMode(t)
	m.Line = modemlink.NewSetup(modemlink.SetupConfig{})
	_, err := m.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "modem-uid") {
		t.Fatalf("run %v", err)
	}
}
