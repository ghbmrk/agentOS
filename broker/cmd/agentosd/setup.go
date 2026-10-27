package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/modemlink"
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
	// Line is the owner line's modem bridge while setup runs (P2-2w c4c;
	// §8.1 pairing, CH-12): setup serves its ops on owner.sock to the
	// bridge's uid (ModemUID, ModemGID) only, and only until finish, so
	// the page can read the box's number, send setup's fixed texts and
	// take PAIR texts. Nil serves no owner.sock: setup cannot text.
	Line     *modemlink.SetupLine
	ModemUID *int
	ModemGID *int
	// ModemEnv is agentos-modem's environment file (P2-2w c4c r1): once
	// setup is finished, on this start and every later one, it is made to
	// name the owner (OWNER_NUMBER), so the bridge, restarted by the image
	// when the file changes, knows whose texts are the owner's. Set only
	// with a modem line; empty writes nothing.
	ModemEnv string
	// Logf logs ModemEnv's outcome, never the number; nil is log.Printf.
	Logf func(string, ...any)

	// Card starts the first-boot Owner Card step (HW-1) and returns its
	// hold: setup does not finish while Hold reports the card unconfirmed.
	// agentosd links no card code (ARC-2: the card's page is served over
	// net/http), so the step is built with the page and handed in here; a
	// nil Card fails closed.
	Card func() (cardHold, error)
	// SignIn starts a plan route's device-code sign-in at setup (c4e2b,
	// ONB-3); nil offers no plan sign-in.
	SignIn localsrv.SignIn
}

// cardHold is the Owner Card step as setup's finish sees it
// (firstboot.CardStep): Hold is nil once the owner has confirmed the card.
type cardHold interface{ Hold() error }

// errCardPending is setup finish's refusal while the Owner Card is
// unconfirmed.
const errCardPending = localapi.ErrCardPending

// pageCard is the Owner Card step's hold when the step runs in
// agentos-localui (#1115): the page builds, shows and latches the card and
// reports it confirmed in the finish call (localapi.Finish.Card). The
// report holds for this process only; the page reports it in each finish.
type pageCard struct {
	mu        sync.Mutex
	confirmed bool
}

func pageCardStep() (cardHold, error) { return &pageCard{}, nil }

func (c *pageCard) Hold() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.confirmed {
		return errors.New("setup: the page has not reported the Owner Card confirmed")
	}
	return nil
}

// report takes the finish call's report of a confirmed card.
func (c *pageCard) report() {
	c.mu.Lock()
	c.confirmed = true
	c.mu.Unlock()
}

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
		m.toBridge(rec.Owner)
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
	m.bridgeDir()
	finished := make(chan string, 1)
	cfg := localsrv.SetupConfig{Record: m.Record, Enroll: m.Enroll, Progress: m.Progress,
		Providers: providersOf(m.Enroll),
		SignIn:    m.SignIn,
		Finished:  func(owner string) { finished <- owner }}
	if m.Line != nil {
		cfg.Line = m.Line // a nil *SetupLine would be a non-nil interface
	}
	s := localsrv.NewSetup(cfg)
	ops := s.Ops()
	finish := ops[localapi.OpSetupFinish]
	pc, page := step.(*pageCard)
	ops[localapi.OpSetupFinish] = func(ctx context.Context, p sockets.Peer, args json.RawMessage) (any, error) {
		var f localapi.Finish
		if page && json.Unmarshal(args, &f) == nil && f.Card {
			pc.report()
		}
		if step.Hold() != nil {
			return nil, sockets.Code(errCardPending)
		}
		return finish(ctx, p, args)
	}
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	srv := &sockets.Server{Dir: m.Dir}
	uid := m.Page.UID
	eps := []sockets.Endpoint{{
		Name:        localapi.Socket,
		Peer:        sockets.Peer{Kind: "localui"},
		PeerUID:     &uid,
		PeerGID:     m.Page.GID,
		MaxConns:    8,
		IdleTimeout: 30 * time.Second,
		Ops:         ops,
		HangupOps:   map[string]bool{localapi.OpSetupInbound: true},
	}}
	if m.Line != nil {
		if m.ModemUID == nil {
			return "", errors.New("setup: a modem line with no -modem-uid: nothing may serve owner.sock")
		}
		eps = append(eps, sockets.Endpoint{
			Name:        daemon.OwnerSocket,
			Peer:        sockets.Peer{Kind: "owner"},
			PeerUID:     m.ModemUID,
			PeerGID:     m.ModemGID,
			MaxConns:    8,
			IdleTimeout: heldIdle,
			Ops:         m.Line.Ops(),
			HangupOps:   map[string]bool{bridgeproto.OpOutbox: true},
		})
	}
	if err := srv.Start(sctx, eps...); err != nil {
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
	if err == nil {
		m.toBridge(owner)
	}
	return owner, err
}

// bridgeDir makes ModemEnv's directory while setup runs, well before
// finish writes the file: agentos-modem-env.path watches the file, and a
// directory made just before the file could be missed while systemd moves
// its watch into it.
func (m setupMode) bridgeDir() {
	if m.ModemEnv == "" {
		return
	}
	if err := ensureDir(filepath.Dir(m.ModemEnv)); err != nil {
		m.logf()("setup: %v", err)
	}
}

func (m setupMode) logf() func(string, ...any) {
	if m.Logf == nil {
		return log.Printf
	}
	return m.Logf
}

// toBridge gives the owner's number to the modem bridge through ModemEnv.
func (m setupMode) toBridge(owner string) {
	if m.ModemEnv == "" {
		return
	}
	writeOwnerEnv(m.ModemEnv, owner, m.logf())
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
	case errors.Is(err, modelroute.ErrCardRequired):
		return localsrv.EnrollCardRequired
	case errors.Is(err, modelroute.ErrNoEnrollment):
		return localsrv.EnrollNone
	case errors.As(err, &ve) && ve.Kind == modelroute.VerifyPaused:
		return localsrv.EnrollPaused
	}
	return err
}

// providersOf is the vault process's provider setup when the enroller
// also serves it (P2-2w c4e); otherwise nil, and setup lists none.
func providersOf(e localsrv.Enroller) localsrv.Providers {
	p, _ := e.(localsrv.Providers)
	return p
}

// Providers lists the vault's built-in providers. An adapter takes an API
// key at setup; a plan route takes a device-code sign-in instead (c4e2b),
// which the page offers only while setup's SignIn is ready for it.
func (e enroller) Providers() ([]localapi.SetupProvider, error) {
	ps, err := e.v.SetupProviders()
	if err != nil {
		return nil, providerErr(err)
	}
	out := make([]localapi.SetupProvider, 0, len(ps))
	for _, p := range ps {
		out = append(out, localapi.SetupProvider{ID: p.ID, Name: p.Name, APIKey: !p.Plan, DeviceCode: p.Plan, Connected: p.Connected, PrivateOK: p.PrivateOK, PrivateByConfig: p.PrivateByConfig})
	}
	return out, nil
}

// PutAPIKey passes key to the vault process and keeps nothing (CRED-1).
func (e enroller) PutAPIKey(provider, key string) error {
	return providerErr(e.v.SetupAPIKey(provider, key))
}

func (e enroller) SetPrivateOK(provider string, ok bool) error {
	return providerErr(e.v.SetupPrivateOK(provider, ok))
}

func providerErr(err error) error {
	switch {
	case errors.Is(err, modelroute.ErrKeyRefused):
		return localsrv.KeyRefused
	case errors.Is(err, modelroute.ErrKeyUnchecked):
		return localsrv.KeyUnchecked
	}
	if errors.Is(err, modelroute.ErrSetupRefused) {
		return localsrv.ProviderRefused
	}
	return enrollErr(err)
}
