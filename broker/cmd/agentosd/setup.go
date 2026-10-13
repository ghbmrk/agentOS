package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/netjoin"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// setupMode is agentosd on a box with no owner yet (P2-2w c2; Security L6
// on the P2-2w plan). It serves only setup's ops on localui.sock until
// setup's finish is recorded, then stops serving them and returns the
// owner's number, with which agentosd starts the owner channel. A box
// whose record says finished never serves them again.
type setupMode struct {
	Dir        string // socket directory
	Page       *daemon.PageSocket
	Record     localsrv.RecordStore
	OwnerState string // the owner channel's state file
	Enroll     localsrv.Enroller
	Progress   func() localapi.SetupProgress
	// NetJoin is the netjoin helper's socket (P2-2w c3; Security L8);
	// empty, the page's network step answers its one error.
	NetJoin string
	// Seen is told each join's answer (the uplink's never-online wait,
	// P2-2w c4); nil is told nothing.
	Seen func(netjoin.Code)

	// Card starts the first-boot Owner Card step (HW-1) and returns its
	// hold: setup does not finish while Hold reports the card unconfirmed.
	// agentosd links no card code (ARC-2: the card's page is served over
	// net/http), so the step is built with the page and handed in here; a
	// nil Card fails closed.
	Card func() (cardHold, error)
}

// cardHold is the Owner Card step as setup's finish sees it
// (firstboot.CardStep): Hold is nil once the owner has confirmed the card.
type cardHold interface{ Hold() error }

// errCardPending is setup finish's refusal while the Owner Card is
// unconfirmed.
const errCardPending = "card pending"

// errOwnedWithoutRecord: the owner channel has state but setup's record is
// missing; setup stays closed rather than letting the page pick an owner.
var errOwnedWithoutRecord = errors.New("setup: the owner channel has state but the setup record says setup never finished; recover the record rather than reopen setup")

// run returns the owner's number: at once if finish is recorded, or once
// the page finishes setup.
func (m setupMode) run(ctx context.Context) (string, error) {
	rec, err := m.Record.Load()
	if err != nil {
		return "", fmt.Errorf("setup record: %w", err)
	}
	if rec.Finished {
		return rec.Owner, nil
	}
	if _, err := os.Lstat(m.OwnerState); !errors.Is(err, os.ErrNotExist) {
		return "", errOwnedWithoutRecord
	}
	if m.Page == nil {
		return "", errors.New("setup: no -owner and no -localui-uid: nothing can run setup")
	}
	if m.Enroll == nil {
		return "", errors.New("setup: no -owner and no -owner-verify: the code generator cannot be enrolled")
	}
	step, err := m.cardStep()
	if err != nil {
		return "", err
	}
	finished := make(chan string, 1)
	s := localsrv.NewSetup(localsrv.SetupConfig{Record: m.Record, Enroll: m.Enroll, Progress: m.Progress,
		Join:     joiner(m.NetJoin, m.Seen),
		Networks: scanner(m.NetJoin),
		Finished: func(owner string) { finished <- owner }})
	ops := s.Ops()
	finish := ops[localapi.OpSetupFinish]
	ops[localapi.OpSetupFinish] = func(ctx context.Context, p sockets.Peer, args json.RawMessage) (any, error) {
		if step.Hold() != nil {
			return nil, sockets.Code(errCardPending)
		}
		return finish(ctx, p, args)
	}
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	srv := &sockets.Server{Dir: m.Dir}
	uid := m.Page.UID
	if err := srv.Start(sctx, sockets.Endpoint{
		Name:        localapi.Socket,
		Peer:        sockets.Peer{Kind: "localui"},
		PeerUID:     &uid,
		PeerGID:     m.Page.GID,
		MaxConns:    8,
		IdleTimeout: 30 * time.Second,
		Ops:         ops,
	}); err != nil {
		return "", err
	}
	var owner string
	select {
	case owner = <-finished:
	case <-ctx.Done():
		err = ctx.Err()
	}
	stop()
	srv.Wait()
	return owner, err
}

// cardStep starts the Owner Card step on a box with no owner.
func (m setupMode) cardStep() (cardHold, error) {
	if m.Card == nil {
		return nil, errors.New("setup: no Owner Card step: setup cannot finish without the owner's card")
	}
	step, err := m.Card()
	if err != nil {
		return nil, err
	}
	if step == nil {
		return nil, errors.New("setup: the Owner Card step did not start")
	}
	return step, nil
}

// enroller is the vault process's enrollment (egress K17) as setup sees
// it: its refusals mapped to localsrv's.
type enroller struct{ v *modelroute.Verifier }

func (e enroller) Enroll() (string, error) {
	uri, err := e.v.Enroll()
	return uri, enrollErr(err)
}

func (e enroller) ConfirmEnroll(code string) (bool, error) {
	ok, err := e.v.ConfirmEnroll(code)
	return ok, enrollErr(err)
}

func (e enroller) SealEnroll() error {
	return enrollErr(e.v.SealEnroll())
}

func enrollErr(err error) error {
	var ve *modelroute.VerifyError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, modelroute.ErrEnrolled):
		return localsrv.EnrollClosed
	case errors.Is(err, modelroute.ErrEnrollNotOpen):
		return localsrv.EnrollNotOpen
	case errors.Is(err, modelroute.ErrNoEnrollment):
		return localsrv.EnrollNone
	case errors.As(err, &ve) && ve.Kind == modelroute.VerifyPaused:
		return localsrv.EnrollPaused
	}
	return err
}

// errNotJoined is every join that did not end joined or saved. It
// carries nothing of the request (CRED-1).
var errNotJoined = errors.New("setup: the home network was not joined")

// scanner is setup's list of home networks from the netjoin helper's
// socket (P2-2w c4b); nil with no socket.
func scanner(path string) func(context.Context) ([]string, error) {
	if path == "" {
		return nil
	}
	return netjoin.Client{Path: path}.Networks
}

// joiner is setup's join through the netjoin helper's socket: joined and
// saved succeed, every other answer or no answer is errNotJoined. With no
// socket it is nil, and localsrv answers not joined. seen, if set, is
// told each answer.
func joiner(path string, seen func(netjoin.Code)) func(context.Context, string, string) error {
	if path == "" {
		return nil
	}
	c := netjoin.Client{Path: path}
	return func(ctx context.Context, ssid, password string) error {
		code, err := c.Join(ctx, ssid, password)
		if err == nil && seen != nil {
			seen(code)
		}
		if err == nil && (code == netjoin.Joined || code == netjoin.Saved) {
			return nil
		}
		return errNotJoined
	}
}
