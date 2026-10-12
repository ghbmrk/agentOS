package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modelroute"
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

	// The first-boot Owner Card step (HW-1): setup does not finish until
	// the owner has confirmed the card. Card makes the vault from it;
	// CardStore keeps the step's latch; CardDisplay configures the card
	// (its Provision is Card's); Show hands the step to the setup page.
	Card        cardProvisioner
	CardStore   firstboot.Store
	CardDisplay card.DisplayConfig
	Show        func(*firstboot.CardStep)
}

// cardProvisioner makes what the box keeps of the Owner Card (vault slots
// and stored values, recovery.Provision). Provision accepts a retry with
// the same card; Reset removes what a provision left from a card whose
// confirm never latched (firstboot ASSUMPTIONS F10).
type cardProvisioner interface {
	Provision(*card.Card) error
	Reset() error
}

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

// cardStep starts the Owner Card step on a box with no owner. A vault a
// start made from a card whose confirm never latched is removed first, so
// the new card this start shows never meets it.
func (m setupMode) cardStep() (*firstboot.CardStep, error) {
	if m.Card == nil || m.CardStore == nil || m.Show == nil {
		return nil, errors.New("setup: no Owner Card provisioner: setup cannot finish without the owner's card")
	}
	if err := firstboot.ResetUnlatched(m.CardStore, m.Card.Reset); err != nil {
		return nil, err
	}
	cfg := m.CardDisplay
	cfg.Provision = m.Card.Provision
	step, err := firstboot.NewCardStep(m.CardStore, cfg)
	if err != nil {
		return nil, err
	}
	m.Show(step)
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

// setupProgress is what setup's pages show while agentosd runs setup: the
// box is up. The first-boot update and uplink checks are not wired yet.
func setupProgress() localapi.SetupProgress {
	return localapi.SetupProgress{Phase: "ready", Updated: true, Online: true}
}
