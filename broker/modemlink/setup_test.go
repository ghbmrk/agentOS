package modemlink_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-1, CH-12

const (
	setupBox   = "+15550000100"
	setupPhone = "+15550000101"
	setupSIM   = "89010000000000000001"
)

func setupCall(t *testing.T, s *modemlink.SetupLine, op string, args, out any) error {
	t.Helper()
	b, _ := json.Marshal(args)
	res, err := s.Ops()[op](context.Background(), sockets.Peer{Kind: "owner"}, b)
	if err != nil {
		return err
	}
	if out != nil {
		raw, _ := json.Marshal(res)
		return json.Unmarshal(raw, out)
	}
	return nil
}

func okLine(t *testing.T, s *modemlink.SetupLine) {
	t.Helper()
	if err := setupCall(t, s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateOK, Number: setupBox}, nil); err != nil {
		t.Fatal(err)
	}
}

// The box's number and readiness come only from an ok line (CH-1); a line
// that is down, unbound or silent is not ready, so the page can say so
// (CH-12).
func TestSetupLineIsReadyOnlyWhileTheBridgeSaysOK(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := modemlink.NewSetup(modemlink.SetupConfig{Now: clock})
	if s.Ready() || s.Number() != "" {
		t.Fatal("ready before any report")
	}
	okLine(t, s)
	if !s.Ready() || s.Number() != setupBox {
		t.Fatalf("ok line: ready %v number %q", s.Ready(), s.Number())
	}
	mu.Lock()
	now = now.Add(modemlink.Silent + time.Second)
	mu.Unlock()
	if s.Ready() || s.Number() != "" {
		t.Fatal("ready after the bridge went silent")
	}
	okLine(t, s)
	setupCall(t, s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateDown}, nil)
	if s.Ready() || s.Number() != "" {
		t.Fatal("ready while down")
	}
	for _, bad := range []bridgeproto.State{{OwnerLine: "ok", Number: "12345"}, {OwnerLine: "maybe"}, {OwnerLine: "unbound", ICCID: "zz"}} {
		if err := setupCall(t, s, bridgeproto.OpState, bad, nil); err == nil {
			t.Errorf("state %+v taken", bad)
		}
	}
}

// Setup binds the box's own SIM, found with none recorded, once; a later
// SIM is not recorded over it.
func TestSetupRecordsTheBoxsSIMOnce(t *testing.T) {
	var got []string
	s := modemlink.NewSetup(modemlink.SetupConfig{Record: func(iccid string) error { got = append(got, iccid); return nil }})
	setupCall(t, s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateUnbound}, nil)
	setupCall(t, s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateUnbound, ICCID: setupSIM}, nil)
	setupCall(t, s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateUnbound, ICCID: "89010000000000000002"}, nil)
	setupCall(t, s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateSwapped, ICCID: "89010000000000000003"}, nil)
	if len(got) != 1 || got[0] != setupSIM {
		t.Fatalf("recorded %q", got)
	}
	if s.Ready() {
		t.Fatal("ready while unbound")
	}
}

func TestASetupRecordThatFailsIsTriedAgain(t *testing.T) {
	n := 0
	s := modemlink.NewSetup(modemlink.SetupConfig{Record: func(string) error {
		n++
		if n == 1 {
			return errors.New("disk")
		}
		return nil
	}})
	for range 3 {
		setupCall(t, s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateUnbound, ICCID: setupSIM}, nil)
	}
	if n != 2 {
		t.Fatalf("%d records", n)
	}
}

// Only PAIR texts from a number reach setup, once each; anyone's other
// texts are taken and dropped, never shown (privacy), and nothing passes
// while the line is not ok.
func TestOnlyPairTextsReachSetup(t *testing.T) {
	s := modemlink.NewSetup(modemlink.SetupConfig{})
	in := func(id, from, text string, named bool) error {
		return setupCall(t, s, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, ID: id, From: from, Text: text, Named: named}, nil)
	}
	if err := in("0", setupPhone, "PAIR ABCD", false); err == nil {
		t.Fatal("a text taken before the line is ok")
	}
	okLine(t, s)
	for i, c := range []struct {
		from, text string
		named      bool
	}{
		{setupPhone, "hello", false},
		{"BANK", "PAIR ABCD", true},
		{setupPhone, "PAIR ABCD", true}, // a sender name that reads as a number
		{"12345", "PAIR ABCD", false},
		{setupPhone, "PAIRING", false},
		{setupPhone, "pair abcd-12", false},
		{setupPhone, "pair abcd-12", false}, // a new text: passed again
	} {
		if err := in(string(rune('a'+i)), c.from, c.text, c.named); err != nil {
			t.Fatalf("%+v refused: %v", c, err)
		}
	}
	in("f", setupPhone, "pair abcd-12", false) // a retried ID: not again
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	for range 2 {
		from, text, ok := s.Next(ctx)
		if !ok || from != setupPhone || text != "pair abcd-12" {
			t.Fatalf("next: %q %q %v", from, text, ok)
		}
	}
	if _, _, ok := s.Next(ctx); ok {
		t.Fatal("a third text passed")
	}
}

func TestSetupInboundIsBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := modemlink.NewSetup(modemlink.SetupConfig{Now: clock})
	okLine(t, s)
	for i := range modemlink.MaxSetupInbound + 5 {
		if i > 0 && i%modemlink.SetupInboundPerMinute == 0 { // a new minute's texts
			mu.Lock()
			now = now.Add(time.Minute)
			mu.Unlock()
			okLine(t, s)
		}
		if err := setupCall(t, s, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, ID: string(rune('A' + i)), From: setupPhone, Text: "PAIR ABCD"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	n := 0
	for {
		if _, _, ok := s.Next(ctx); !ok {
			break
		}
		n++
	}
	if n != modemlink.MaxSetupInbound {
		t.Fatalf("%d texts waited", n)
	}
}

// Only an unbound line's serial is recorded: a SIM the bridge reports
// swapped, down or ok is not the box's unclaimed SIM (ST4).
func TestSetupRecordsOnlyAnUnboundSIM(t *testing.T) {
	var got []string
	s := modemlink.NewSetup(modemlink.SetupConfig{Record: func(iccid string) error { got = append(got, iccid); return nil }})
	for _, st := range []string{bridgeproto.StateSwapped, bridgeproto.StateDown, bridgeproto.StateOK} {
		setupCall(t, s, bridgeproto.OpState, bridgeproto.State{OwnerLine: st, ICCID: setupSIM}, nil)
	}
	if len(got) != 0 {
		t.Fatalf("recorded %q from a line that was not unbound", got)
	}
	setupCall(t, s, bridgeproto.OpState, bridgeproto.State{OwnerLine: bridgeproto.StateUnbound, ICCID: setupSIM}, nil)
	if len(got) != 1 {
		t.Fatalf("recorded %q", got)
	}
}

// At most SetupInboundPerMinute PAIR texts are kept a minute, even when
// the page takes each at once (ST2); the next minute takes more.
func TestSetupInboundIsCappedPerMinute(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := modemlink.NewSetup(modemlink.SetupConfig{Now: clock})
	okLine(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	kept := func(id int) bool {
		t.Helper()
		if err := setupCall(t, s, bridgeproto.OpInbound, bridgeproto.Inbound{Line: bridgeproto.LineOwner, ID: fmt.Sprint(id), From: setupPhone, Text: "PAIR ABCD"}, nil); err != nil {
			t.Fatal(err)
		}
		short, stop := context.WithTimeout(ctx, 20*time.Millisecond)
		defer stop()
		_, _, ok := s.Next(short)
		return ok
	}
	n := 0
	for i := range modemlink.SetupInboundPerMinute + 3 {
		if kept(i) {
			n++
		}
	}
	if n != modemlink.SetupInboundPerMinute || modemlink.SetupInboundPerMinute != 5 {
		t.Fatalf("%d texts kept in a minute, cap %d", n, modemlink.SetupInboundPerMinute)
	}
	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	okLine(t, s)
	if !kept(100) {
		t.Fatal("no text kept the next minute")
	}
}

// A setup text goes through the bridge's outbox and succeeds only on its
// ok result; with no usable line, or a failed result, it is not sent.
func TestSetupSendWaitsForTheBridgesResult(t *testing.T) {
	s := modemlink.NewSetup(modemlink.SetupConfig{PollWait: 20 * time.Millisecond, SendWait: time.Second})
	if err := s.Send(context.Background(), setupPhone, "x"); !errors.Is(err, modemlink.ErrNotSent) {
		t.Fatalf("send with no line: %v", err)
	}
	okLine(t, s)
	for _, code := range []string{bridgeproto.CodeOK, bridgeproto.CodeUnreachable} {
		done := make(chan error, 1)
		go func() {
			done <- s.Send(context.Background(), setupPhone, "agentOS setup code: 123456. Type it on the setup page.")
		}()
		var out struct{ Item *bridgeproto.Item }
		for out.Item == nil {
			if err := setupCall(t, s, bridgeproto.OpOutbox, struct{}{}, &out); err != nil {
				t.Fatal(err)
			}
		}
		if out.Item.To != setupPhone || out.Item.Line != bridgeproto.LineOwner {
			t.Fatalf("item %+v", out.Item)
		}
		setupCall(t, s, bridgeproto.OpSent, bridgeproto.Sent{ID: out.Item.ID, Code: code}, nil)
		err := <-done
		if (code == bridgeproto.CodeOK) != (err == nil) {
			t.Fatalf("%s: %v", code, err)
		}
	}
	short := modemlink.NewSetup(modemlink.SetupConfig{SendWait: 20 * time.Millisecond})
	okLine(t, short)
	if err := short.Send(context.Background(), setupPhone, "x"); !errors.Is(err, modemlink.ErrNotSent) {
		t.Fatalf("send with no result: %v", err)
	}
}
