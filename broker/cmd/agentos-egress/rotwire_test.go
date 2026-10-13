package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localui"
	"github.com/ghbmrk/agentos/broker/recovery"
)

// REQ: REC-4, CRED-1

// wireRig is the local page's rotation (localui.Rotation) over the real
// unlock socket of a vault process holding an Owner Card.
type wireRig struct {
	*cardRig
	r   *localui.Rotation
	gen *card.Card
}

func newWireRig(t *testing.T) *wireRig {
	t.Helper()
	x := &wireRig{cardRig: newCardRig(t)}
	x.open(t)
	run := filepath.Join(t.TempDir(), "run")
	srvs, err := serve(run, x.c, testRouter(t), nil, nil, os.Getuid(), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, s := range srvs {
			s.Close()
		}
	})
	x.r = localui.NewRotation(localui.NewUnlockClient(filepath.Join(run, UnlockSocket)))
	x.r.Generate = func(rd io.Reader) (*card.Card, error) {
		c, err := card.Generate(rd)
		if err == nil {
			cp := *c
			x.gen = &cp
		}
		return c, err
	}
	return x
}

// wifiCheck is the confirm a Wi-Fi rotation asks for: the new password's
// last four symbols.
func (x *wireRig) wifiCheck() card.Answers {
	w := card.Normalize(x.gen.WiFiPassword)
	return card.Answers{Check: w[len(w)-4:]}
}

func (x *wireRig) recoveryGroup() card.Answers {
	_, g := x.r.Display().Asks()
	return card.Answers{Group: strings.Split(x.gen.RecoveryKey, "-")[g-1]}
}

// REC-4: the page's display commits the confirmed parts through the real
// socket op, and the drive then holds them.
func TestTheLocalPageRotatesOverTheUnlockSocket(t *testing.T) {
	x := newWireRig(t)
	ctx := context.Background()
	if err := x.r.Start(ctx, localui.RotationBegin{Code: x.next(), Parts: card.Parts{WiFi: true}}); err != nil {
		t.Fatal(err)
	}
	if err := x.r.Display().ConfirmAnswers(x.wifiCheck()); err != nil {
		t.Fatal(err)
	}
	if got := x.stored(t, x.rk); got.WiFiPassword != x.gen.WiFiPassword || got.WiFiName != x.card.WiFiName {
		t.Fatal("the drive does not hold the confirmed Wi-Fi password")
	}
}

// #1090 review R1, against the real socket op: a lapsed rotation
// (ErrPendingLapsed) reaches the display as card.ErrDiscard, and a commit
// that stopped after a slot was rewritten (ErrCardNotStored) as
// card.ErrInEffect, which the display then refuses to cancel.
func TestTheLocalPagesProvisionerMapsTheSocketsRefusals(t *testing.T) {
	x := newWireRig(t)
	ctx := context.Background()
	if err := x.r.Start(ctx, localui.RotationBegin{Code: x.next(), Parts: card.Parts{WiFi: true}}); err != nil {
		t.Fatal(err)
	}
	x.clk.add(recovery.PendingTTL + time.Second)
	if err := x.r.Display().ConfirmAnswers(x.wifiCheck()); !errors.Is(err, card.ErrDiscard) {
		t.Fatalf("lapsed: %v", err)
	}
	if _, err := x.r.Display().Page(); err == nil {
		t.Fatal("a lapsed rotation kept its card")
	}
	if got := x.stored(t, x.rk); got.WiFiPassword != x.card.WiFiPassword {
		t.Fatal("a lapsed rotation changed the card")
	}

	if err := x.r.Start(ctx, localui.RotationBegin{Recovery: x.rk.Text(), Parts: card.Parts{Recovery: true}}); err != nil {
		t.Fatal(err)
	}
	x.c.mu.Lock()
	x.c.host = failReencrypt{nil, errors.New("tpm: synthetic failure")}
	x.c.mu.Unlock()
	if err := x.r.Display().ConfirmAnswers(x.recoveryGroup()); !errors.Is(err, card.ErrInEffect) {
		t.Fatalf("part way: %v", err)
	}
	if err := x.r.Display().Discard(); !errors.Is(err, card.ErrInEffect) {
		t.Fatal("a card in effect could be cancelled")
	}
}

// #1090 review R2, CRED-1: the page's cancel reaches the vault process
// over the socket, so the Pending and the passphrase it holds go at once.
func TestTheLocalPagesCancelDropsThePendingRotation(t *testing.T) {
	x := newWireRig(t)
	ctx := context.Background()
	if err := x.r.Start(ctx, localui.RotationBegin{Code: x.next(), Parts: card.Parts{WiFi: true}}); err != nil {
		t.Fatal(err)
	}
	if x.c.rot.p == nil {
		t.Fatal("no pending rotation")
	}
	if err := x.r.Display().Discard(); err != nil {
		t.Fatal(err)
	}
	x.c.rot.mu.Lock()
	p := x.c.rot.p
	x.c.rot.mu.Unlock()
	if p != nil {
		t.Fatal("the page's cancel left the rotation pending")
	}
}
