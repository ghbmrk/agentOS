package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeclient"
	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/firstboot"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// REQ: HW-1, ONB-7

// cardVault stands in for the store the card's passphrase seals
// (recovery.Provision): it writes a store file and a key file that records
// the passphrase, so a test can tell which card made it; a retry with the
// same card is a no-op. Reset removes a store made from a card nobody
// confirmed.
type cardVault struct {
	dir    string
	made   *card.Card
	resets int
}

func (v *cardVault) paths() (string, string) {
	return filepath.Join(v.dir, "vault"), filepath.Join(v.dir, "vault.keys")
}

func (v *cardVault) Provision(c *card.Card) error {
	if c == v.made {
		return nil
	}
	vp, kp := v.paths()
	if err := os.WriteFile(vp, []byte("sealed"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(kp, []byte(c.VaultPassphrase), 0o600); err != nil {
		return err
	}
	v.made = c
	return nil
}

// madeFrom reports whether the store on disk was made from passphrase.
func (v *cardVault) madeFrom(passphrase string) bool {
	vp, kp := v.paths()
	k, err := os.ReadFile(kp)
	if err != nil {
		return false
	}
	_, err = os.Stat(vp)
	return err == nil && string(k) == passphrase
}

func (v *cardVault) Reset() error {
	v.resets++
	vp, kp := v.paths()
	for _, p := range []string{kp, vp} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// cardFixture is what a test sees of one start: the step handed to the
// page and a copy of the card it shows (strings only, for the answers).
type cardFixture struct {
	vault *cardVault
	steps chan *firstboot.CardStep
	shown card.Card
}

// newCardSetup is a setup mode whose card step uses a vault in its own
// directory and an in-memory latch.
func newCardSetup(t *testing.T) (setupMode, *cardFixture) {
	t.Helper()
	m := newBareSetupMode(t)
	f := &cardFixture{vault: &cardVault{dir: filepath.Dir(m.OwnerState)}, steps: make(chan *firstboot.CardStep, 1)}
	m.withCard(f, &change.MemStore{})
	return m, f
}

// withCard hands setup a card step built as the page's process builds it:
// a vault left by a confirm that never latched is reset first (firstboot
// ASSUMPTIONS F10), then the step starts and goes to the page.
func (m *setupMode) withCard(f *cardFixture, st firstboot.Store) {
	m.Card = func() (cardHold, error) {
		if err := firstboot.ResetUnlatched(st, f.vault.Reset); err != nil {
			return nil, err
		}
		s, err := firstboot.NewCardStep(st, card.DisplayConfig{Authority: cardAuthority(), Provision: f.vault.Provision,
			Generate: func(r io.Reader) (*card.Card, error) {
				c, err := card.Generate(r)
				if err == nil {
					f.shown = *c
				}
				return c, err
			}})
		if err != nil {
			return nil, err
		}
		f.steps <- s
		return s, nil
	}
}

// confirm answers the step's display from the copy of the shown card.
func (f *cardFixture) confirm(t *testing.T, s *firstboot.CardStep) error {
	t.Helper()
	d := s.Display()
	if d == nil {
		t.Fatal("no card shown")
	}
	w, g := d.Asks()
	return d.Confirm(strings.Fields(f.shown.VaultPassphrase)[w-1], strings.Split(f.shown.RecoveryKey, "-")[g-1])
}

func (f *cardFixture) step(t *testing.T) *firstboot.CardStep {
	t.Helper()
	select {
	case s := <-f.steps:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("setup never showed the card step")
	}
	return nil
}

type runResult struct {
	owner string
	err   error
}

func start(ctx context.Context, m setupMode) chan runResult {
	done := make(chan runResult, 1)
	go func() { o, err := m.run(ctx); done <- runResult{o, err} }()
	return done
}

func setupCall(t *testing.T, m setupMode) func(op string, args, out any) error {
	t.Helper()
	c := bridgeclient.Client{Path: filepath.Join(m.Dir, localapi.Socket)}
	call := func(op string, args, out any) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return c.Call(ctx, op, args, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for call(localapi.OpSetupProgress, nil, nil) != nil {
		if time.Now().After(deadline) {
			t.Fatal("setup never served")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return call
}

// HW-1: setup's finish is refused while the Owner Card is unconfirmed,
// even with approval codes enrolled; after the confirm it finishes.
func TestFinishWaitsForTheOwnerCard(t *testing.T) {
	m, f := newCardSetup(t)
	done := start(context.Background(), m)
	s := f.step(t)
	call := setupCall(t, m)
	var l localapi.EnrollLink
	if err := call(localapi.OpSetupEnroll, nil, &l); err != nil {
		t.Fatal(err)
	}
	var ok localapi.Confirmed
	if err := call(localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, &ok); err != nil || !ok.OK {
		t.Fatalf("confirm %v %v", err, ok)
	}
	if err := call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil); err == nil || !strings.Contains(err.Error(), errCardPending) {
		t.Fatalf("finish before the card: %v", err)
	}
	if rec, err := m.Record.Load(); err != nil || rec.Finished {
		t.Fatalf("record finished before the card: %+v %v", rec, err)
	}
	select {
	case r := <-done:
		t.Fatalf("setup ended before the card: %+v", r)
	default:
	}
	if err := f.confirm(t, s); err != nil {
		t.Fatal(err)
	}
	if s.Hold() != nil {
		t.Fatal("card still held after the confirm")
	}
	call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil)
	select {
	case r := <-done:
		if r.err != nil || r.owner != "+15550100100" {
			t.Fatalf("run %q %v", r.owner, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not end at finish")
	}
}

// HW-1, ONB-7: a start killed between provisioning and saving the latch
// leaves a vault from a card nobody holds; the next start removes it and
// shows a new card, from which the vault is made afresh.
func TestARestartAfterAKilledConfirmShowsANewCard(t *testing.T) {
	m, f := newCardSetup(t)
	latch := &change.MemStore{Fail: errors.New("killed")}
	m.withCard(f, latch)
	ctx, cancel := context.WithCancel(context.Background())
	done := start(ctx, m)
	s := f.step(t)
	if err := f.confirm(t, s); err == nil {
		t.Fatal("confirm succeeded without saving the latch")
	}
	vp, kp := f.vault.paths()
	if _, err := os.Stat(kp); err != nil {
		t.Fatalf("the kill should come after the vault was made: %v", err)
	}
	first := f.shown.VaultPassphrase
	cancel()
	<-done

	latch.Fail = nil
	f2 := &cardFixture{vault: &cardVault{dir: f.vault.dir}, steps: make(chan *firstboot.CardStep, 1)}
	m.withCard(f2, latch)
	done = start(context.Background(), m)
	s = f2.step(t)
	if f2.vault.resets != 1 {
		t.Fatalf("resets %d", f2.vault.resets)
	}
	for _, p := range []string{vp, kp} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("half-made vault left: %s %v", p, err)
		}
	}
	if f2.shown.VaultPassphrase == first {
		t.Fatal("the restart showed the old card")
	}
	if err := f2.confirm(t, s); err != nil {
		t.Fatalf("new card: %v", err)
	}
	if !f2.vault.madeFrom(f2.shown.VaultPassphrase) {
		t.Fatal("vault not made from the new card")
	}
	if s.Hold() != nil {
		t.Fatal("held after the confirm")
	}
	call := setupCall(t, m)
	var l localapi.EnrollLink
	call(localapi.OpSetupEnroll, nil, &l)
	var ok localapi.Confirmed
	call(localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, &ok)
	call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil)
	if r := <-done; r.err != nil || r.owner != "+15550100100" {
		t.Fatalf("run %+v", r)
	}
}

// A confirmed latch is never reset and shows no card: a restart after the
// confirm but before finish goes straight to finishing.
func TestAConfirmedCardIsKeptAcrossARestart(t *testing.T) {
	m, f := newCardSetup(t)
	latch := &change.MemStore{}
	if err := latch.Save([]byte(`{"card_confirmed":true}`)); err != nil {
		t.Fatal(err)
	}
	m.withCard(f, latch)
	done := start(context.Background(), m)
	s := f.step(t)
	if f.vault.resets != 0 || s.Display() != nil || s.Hold() != nil {
		t.Fatalf("resets %d display %v hold %v", f.vault.resets, s.Display(), s.Hold())
	}
	call := setupCall(t, m)
	var l localapi.EnrollLink
	call(localapi.OpSetupEnroll, nil, &l)
	var ok localapi.Confirmed
	call(localapi.OpSetupConfirm, localapi.Confirm{Code: "123456"}, &ok)
	call(localapi.OpSetupFinish, localapi.Finish{Owner: "+15550100100"}, nil)
	if r := <-done; r.err != nil || r.owner != "+15550100100" {
		t.Fatalf("run %+v", r)
	}
}

// An owned box (finished record, or owner state) never resets the vault
// or shows a card, whatever the latch says.
func TestAnOwnedBoxNeverResetsTheVault(t *testing.T) {
	m, f := newCardSetup(t)
	if err := os.WriteFile(m.Record.(localsrv.FileRecord).Path, []byte(`{"finished":true,"owner":"+15550100100"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if o, err := m.run(context.Background()); err != nil || o != "+15550100100" {
		t.Fatalf("finished %q %v", o, err)
	}
	m2, f2 := newCardSetup(t)
	if err := os.WriteFile(m2.OwnerState, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := m2.run(context.Background()); !errors.Is(err, errOwnedWithoutRecord) {
		t.Fatal(err)
	}
	if f.vault.resets+f2.vault.resets != 0 || len(f.steps)+len(f2.steps) != 0 {
		t.Fatal("an owned box reset its vault or showed a card")
	}
}

// Setup without the card step refuses to start, and a step that cannot
// start (here a latch that cannot be read, which resets nothing) stops
// setup before it serves.
func TestSetupWithoutTheCardFailsClosed(t *testing.T) {
	for name, edit := range map[string]func(*setupMode, *cardFixture){
		"no card step": func(m *setupMode, f *cardFixture) { m.Card = nil },
		"no step":      func(m *setupMode, f *cardFixture) { m.Card = func() (cardHold, error) { return nil, nil } },
		"corrupt latch": func(m *setupMode, f *cardFixture) {
			st := &change.MemStore{}
			st.Save([]byte("{"))
			m.withCard(f, st)
		},
	} {
		m, f := newCardSetup(t)
		edit(&m, f)
		if _, err := m.run(context.Background()); err == nil {
			t.Fatalf("%s: setup started", name)
		}
		if f.vault.resets != 0 {
			t.Fatalf("%s: reset", name)
		}
		if _, err := os.Stat(filepath.Join(m.Dir, localapi.Socket)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: served setup", name)
		}
	}
}

// cardAuthority is a page authority's certificate for the Owner Cards
// these tests make, which print its fingerprint (HW-1, OWN-card-ca).
var cardAuthority = sync.OnceValue(func() []byte {
	a, err := pageca.New(pageca.DefaultName, time.Now(), nil)
	if err != nil {
		panic(err)
	}
	return a.Certificate()
})
