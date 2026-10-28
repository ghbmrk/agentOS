package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localui"
	"github.com/ghbmrk/agentos/broker/pageca"
	"github.com/ghbmrk/agentos/broker/recovery"
)

// REQ: REC-4, CRED-1

// wireRig is the local page's rotation (localui.Rotation) over the real
// unlock socket of a vault process holding an Owner Card.
type wireRig struct {
	*cardRig
	r   *localui.Rotation
	u   *localui.UnlockClient
	ids *idTap
	gen *card.Card
}

// idTap is the real unlock client, noting each begin's rotation ID.
type idTap struct {
	*localui.UnlockClient
	mu  sync.Mutex
	ids []string
}

func (t *idTap) BeginRotation(ctx context.Context, b localui.RotationBegin) (localui.RotationStarted, error) {
	t.mu.Lock()
	t.ids = append(t.ids, b.ID)
	t.mu.Unlock()
	return t.UnlockClient.BeginRotation(ctx, b)
}

func (t *idTap) last() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ids[len(t.ids)-1]
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
	x.u = localui.NewUnlockClient(filepath.Join(run, UnlockSocket))
	x.ids = &idTap{UnlockClient: x.u}
	x.r = localui.NewRotation(x.ids)
	auth := cardAuthority(t)
	x.r.Authority = func() []byte { return auth }
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

// setupCheck is the confirm a setup rotation asks for: the new setup
// code.
func (x *wireRig) setupCheck() card.Answers {
	return card.Answers{Check: x.gen.SetupCode}
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
	if err := x.r.Start(ctx, localui.RotationBegin{Code: x.next(), Parts: card.Parts{Setup: true}}); err != nil {
		t.Fatal(err)
	}
	if err := x.r.Display().ConfirmAnswers(x.setupCheck()); err != nil {
		t.Fatal(err)
	}
	if got := x.stored(t, x.rk); got.SetupSecret != x.gen.SetupSecret || got.SetupCode != x.gen.SetupCode {
		t.Fatal("the drive does not hold the confirmed setup secret")
	}
}

// #1090 review R1, against the real socket op: a lapsed rotation
// (ErrPendingLapsed) reaches the display as card.ErrDiscard, and a commit
// that stopped after a slot was rewritten (ErrCardNotStored) as
// card.ErrInEffect, which the display then refuses to cancel.
func TestTheLocalPagesProvisionerMapsTheSocketsRefusals(t *testing.T) {
	x := newWireRig(t)
	ctx := context.Background()
	if err := x.r.Start(ctx, localui.RotationBegin{Code: x.next(), Parts: card.Parts{Setup: true}}); err != nil {
		t.Fatal(err)
	}
	x.clk.add(recovery.PendingTTL + time.Second)
	if err := x.r.Display().ConfirmAnswers(x.setupCheck()); !errors.Is(err, card.ErrDiscard) {
		t.Fatalf("lapsed: %v", err)
	}
	if _, err := x.r.Display().Page(); err == nil {
		t.Fatal("a lapsed rotation kept its card")
	}
	if got := x.stored(t, x.rk); got.SetupSecret != x.card.SetupSecret {
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
	if err := x.r.Start(ctx, localui.RotationBegin{Code: x.next(), Parts: card.Parts{Setup: true}}); err != nil {
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

// pendingID is the vault process's waiting rotation's ID, "" for none.
func (x *wireRig) pendingID() string {
	x.c.rot.mu.Lock()
	defer x.c.rot.mu.Unlock()
	if x.c.rot.p == nil {
		return ""
	}
	return x.c.rot.id
}

func gone(err error) bool {
	var ve *localui.VaultError
	return errors.As(err, &ve) && ve.Status == http.StatusGone
}

// #1175 security S-R1, over the real socket: once a newer rotation has
// begun, a late commit or a stale cancel of the older one answers 410 and
// the newer rotation stays waiting with its own values to commit.
func TestAStaleRotationsOpsCannotTouchTheNewerOne(t *testing.T) {
	x := newWireRig(t)
	ctx := context.Background()
	if err := x.r.Start(ctx, localui.RotationBegin{Code: x.next(), Parts: card.Parts{Setup: true}}); err != nil {
		t.Fatal(err)
	}
	a := x.ids.last()
	if err := x.r.Start(ctx, localui.RotationBegin{Code: x.next(), Parts: card.Parts{Setup: true}}); err != nil {
		t.Fatal(err)
	}
	b := x.ids.last()
	if x.pendingID() != b || a == b {
		t.Fatal("the newer rotation is not the one waiting")
	}
	if _, err := x.u.CommitRotation(ctx, a, card.Card{SetupSecret: synthetic(t, "setup-late-"), SetupCode: "LATE-CODE"}); !gone(err) {
		t.Fatalf("late commit: %v", err)
	}
	if err := x.u.CancelRotation(ctx, a); !gone(err) {
		t.Fatalf("stale cancel: %v", err)
	}
	if x.pendingID() != b {
		t.Fatal("a stale op dropped the newer rotation")
	}
	if got := x.stored(t, x.rk); got.SetupSecret != x.card.SetupSecret {
		t.Fatal("a late commit changed the card")
	}
	if err := x.r.Display().ConfirmAnswers(x.setupCheck()); err != nil {
		t.Fatal(err)
	}
	if got := x.stored(t, x.rk); got.SetupSecret != x.gen.SetupSecret {
		t.Fatal("the newer rotation's commit did not land")
	}
}

// #1175 security S-R1, over the real socket: a begin that got no answer
// is cancelled by its ID; the vault process then refuses that begin if
// it arrives late, so it cannot drop the rotation waiting meanwhile.
func TestABeginWithNoAnswerIsCancelledByItsID(t *testing.T) {
	x := newWireRig(t)
	if _, err := x.u.BeginRotation(context.Background(), localui.RotationBegin{ID: newRotationID(), Code: x.next(), Parts: card.Parts{Setup: true}}); err != nil {
		t.Fatal(err)
	}
	waiting := x.pendingID()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the begin gets no answer
	if err := x.r.Start(ctx, localui.RotationBegin{Code: x.next(), Parts: card.Parts{Setup: true}}); err == nil {
		t.Fatal("a begin with no answer started")
	}
	lost := x.ids.last()
	if x.pendingID() != waiting {
		t.Fatal("the cancel of a lost begin dropped the waiting rotation")
	}
	_, err := x.u.BeginRotation(context.Background(), localui.RotationBegin{ID: lost, Code: x.next(), Parts: card.Parts{Setup: true}})
	if !gone(err) {
		t.Fatalf("the lost begin, arriving late: %v", err)
	}
	if x.pendingID() != waiting {
		t.Fatal("a cancelled begin dropped the waiting rotation")
	}
}

// #1175 UX U-R1, over the real socket: the status op reports a replaced
// code generator not yet confirmed.
func TestTheLocalPageSeesAnUnconfirmedCodeGenerator(t *testing.T) {
	x := newWireRig(t)
	ctx := context.Background()
	if p, err := x.u.EnrollmentPending(ctx); err != nil || p {
		t.Fatalf("before: %v %v", p, err)
	}
	if err := x.r.Start(ctx, localui.RotationBegin{Recovery: x.rk.Text(), Parts: card.Parts{Recovery: true}}); err != nil {
		t.Fatal(err)
	}
	if err := x.r.Display().ConfirmAnswers(x.recoveryGroup()); err != nil {
		t.Fatal(err)
	}
	if p, err := x.u.EnrollmentPending(ctx); err != nil || !p {
		t.Fatalf("after: %v %v", p, err)
	}
}

// cardAuthority is a page authority's certificate for the Owner Cards
// this test makes, which print its fingerprint (HW-1, OWN-card-ca).
func cardAuthority(t testing.TB) []byte {
	t.Helper()
	a, err := pageca.New(pageca.DefaultName, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return a.Certificate()
}
