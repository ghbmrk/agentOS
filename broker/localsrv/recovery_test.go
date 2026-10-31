package localsrv

// REQ: REC-4, BAK-1, STO-2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// fakeRecovery records what reached the owner side.
type fakeRecovery struct {
	calls []string
	err   error
	card  []byte                          // LostCard's answer, when set
	begun *localapi.RecoveryLostBegun     // LostBegin's answer, when set
	shown *localapi.RecoveryLostCardBegun // LostCardBegin's answer, when set
	gave  []byte                          // the bits LostCard last answered
}

func (f *fakeRecovery) Begin(_ context.Context, next []byte) (localapi.RecoveryBegun, error) {
	f.calls = append(f.calls, fmt.Sprintf("begin %x", next[:2]))
	return localapi.RecoveryBegun{Next: strings.Repeat("b", 32), Challenge: make([]byte, 32)}, f.err
}

func (f *fakeRecovery) Rotate(_ context.Context, factor string, secret, next, ad, cd, sig []byte) (localapi.RecoveryDone, error) {
	f.calls = append(f.calls, fmt.Sprintf("rotate %s %d %x %x %x %x", factor, len(secret), next[:2], ad, cd, sig))
	return localapi.RecoveryDone{Switched: true}, f.err
}

func (f *fakeRecovery) LostBegin(context.Context) (localapi.RecoveryLostBegun, error) {
	f.calls = append(f.calls, "lostbegin")
	if f.begun != nil {
		return *f.begun, f.err
	}
	return localapi.RecoveryLostBegun{Old: strings.Repeat("a", 32), Challenge: make([]byte, 32)}, f.err
}

func (f *fakeRecovery) Lost(_ context.Context, ad, cd, sig []byte) error {
	f.calls = append(f.calls, fmt.Sprintf("lost %x %x %x", ad, cd, sig))
	return f.err
}

func (f *fakeRecovery) LostState(context.Context) (localapi.RecoveryLostState, error) {
	f.calls = append(f.calls, "loststate")
	return localapi.RecoveryLostState{Filed: true}, f.err
}

func (f *fakeRecovery) LostWithdraw(context.Context) error {
	f.calls = append(f.calls, "withdraw")
	return f.err
}

func (f *fakeRecovery) Restart(context.Context) error {
	f.calls = append(f.calls, "restart")
	return f.err
}

func (f *fakeRecovery) LostCardBegin(context.Context) (localapi.RecoveryLostCardBegun, error) {
	f.calls = append(f.calls, "lostcardbegin")
	if f.shown != nil {
		return *f.shown, f.err
	}
	return localapi.RecoveryLostCardBegun{ID: strings.Repeat("c", 32), Challenge: make([]byte, 32)}, f.err
}

func (f *fakeRecovery) LostCard(_ context.Context, ad, cd, sig []byte) (localapi.RecoveryLostCard, error) {
	f.calls = append(f.calls, fmt.Sprintf("lostcard %x %x %x", ad, cd, sig))
	f.gave = bytes.Repeat([]byte{9}, localapi.RecoveryCardLen)
	if f.card != nil {
		f.gave = bytes.Clone(f.card)
	}
	return localapi.RecoveryLostCard{Card: f.gave, ID: strings.Repeat("c", 32)}, f.err
}

func (f *fakeRecovery) LostDone(context.Context) error {
	f.calls = append(f.calls, "lostdone")
	return f.err
}

func recoveryRig(t *testing.T) (*rig, *fakeRecovery) {
	r, _ := passkeyRig(t)
	f := &fakeRecovery{}
	r.srv.cfg.Recovery = f
	r.ops = r.srv.Ops()
	return r, f
}

var testNext = bytes.Repeat([]byte{7}, localapi.RecoveryKeyLen)

func recoveryArgs(tok string) map[string]any {
	return map[string]any{
		localapi.OpRecoveryBegin: localapi.RecoveryBegin{Token: tok, Next: testNext},
		localapi.OpRecoveryRotate: localapi.RecoveryRotate{Token: tok, Factor: localapi.RecoveryFactorPassphrase,
			Secret: []byte("alpha bravo"), Next: testNext, AuthenticatorData: []byte{1}, ClientDataJSON: []byte{2}, Signature: []byte{3}},
		localapi.OpRecoveryLostBegin:     localapi.RecoverySession{Token: tok},
		localapi.OpRecoveryLost:          localapi.RecoveryLost{Token: tok, AuthenticatorData: []byte{4}, ClientDataJSON: []byte{5}, Signature: []byte{6}},
		localapi.OpRecoveryLostState:     localapi.RecoverySession{Token: tok},
		localapi.OpRecoveryLostWithdraw:  localapi.RecoverySession{Token: tok},
		localapi.OpRecoveryRestart:       localapi.RecoverySession{Token: tok},
		localapi.OpRecoveryLostCardBegin: localapi.RecoverySession{Token: tok},
		localapi.OpRecoveryLostCard:      localapi.RecoveryLost{Token: tok, AuthenticatorData: []byte{7}, ClientDataJSON: []byte{8}, Signature: []byte{9}},
		localapi.OpRecoveryLostDone:      localapi.RecoverySession{Token: tok},
	}
}

// Every recovery-key op is refused without a live session and reaches
// nothing; with one, each reaches the owner side.
func TestRecoveryOpsNeedALiveSession(t *testing.T) {
	r, f := recoveryRig(t)
	for _, op := range localapi.RecoveryOps {
		for _, tok := range []string{"", strings.Repeat("0", 2*localapi.TokenBytes), "made-up"} {
			if _, err := r.call(op, recoveryArgs(tok)[op]); code(err) != localapi.ErrUnauthorized {
				t.Errorf("%s with %q: %v", op, tok, err)
			}
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("reached the owner side: %v", f.calls)
	}
	tok := r.signIn()
	for _, op := range localapi.RecoveryOps {
		r.srv.recoveryRotates = nil // four ops share the bound of three a minute
		if _, err := r.call(op, recoveryArgs(tok)[op]); err != nil {
			t.Errorf("%s: %v", op, err)
		}
	}
	want := []string{"begin 0707", "rotate passphrase 11 0707 01 02 03", "lostbegin", "lost 04 05 06", "loststate",
		"withdraw", "restart", "lostcardbegin", "lostcard 07 08 09", "lostdone"}
	if fmt.Sprint(f.calls) != fmt.Sprint(want) {
		t.Fatalf("calls %v", f.calls)
	}
}

// The frames are bounded before anything reaches the owner side, and
// rotations are counted.
func TestRecoveryFramesAreBounded(t *testing.T) {
	r, f := recoveryRig(t)
	tok := r.signIn()
	one := []byte{1}
	big := make([]byte, localapi.MaxPasskeyAssertion+1)
	rot := func(factor string, secret, next, sig []byte) localapi.RecoveryRotate {
		return localapi.RecoveryRotate{Token: tok, Factor: factor, Secret: secret, Next: next, AuthenticatorData: one, ClientDataJSON: one, Signature: sig}
	}
	for i, c := range []struct {
		op   string
		args any
	}{
		{localapi.OpRecoveryBegin, localapi.RecoveryBegin{Token: tok}},
		{localapi.OpRecoveryBegin, localapi.RecoveryBegin{Token: tok, Next: testNext[:31]}},
		{localapi.OpRecoveryRotate, rot("pin", []byte("x"), testNext, one)},
		{localapi.OpRecoveryRotate, rot(localapi.RecoveryFactorPassphrase, nil, testNext, one)},
		{localapi.OpRecoveryRotate, rot(localapi.RecoveryFactorPassphrase, make([]byte, localapi.MaxRecoveryPassphrase+1), testNext, one)},
		{localapi.OpRecoveryRotate, rot(localapi.RecoveryFactorRecovery, make([]byte, 20), testNext, one)},
		{localapi.OpRecoveryRotate, rot(localapi.RecoveryFactorRecovery, testNext, testNext[:16], one)},
		{localapi.OpRecoveryRotate, rot(localapi.RecoveryFactorRecovery, testNext, testNext, nil)},
		{localapi.OpRecoveryRotate, rot(localapi.RecoveryFactorRecovery, testNext, testNext, big)},
	} {
		if _, err := r.call(c.op, c.args); code(err) != localapi.ErrBadArgs {
			t.Errorf("case %d (%s): %v", i, c.op, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("reached the owner side: %v", f.calls)
	}
	f.err = sockets.Code(localapi.ErrRecoveryFactor)
	for i := range RecoveryRotatesPerMinute + 1 {
		_, err := r.call(localapi.OpRecoveryRotate, recoveryArgs(tok)[localapi.OpRecoveryRotate])
		if want := i == RecoveryRotatesPerMinute; (code(err) == localapi.ErrLimited) != want {
			t.Fatalf("rotate %d: %v", i, err)
		}
	}
}

// The ops are served only with Recovery and Passkeys both: the tap needs
// the passkey page's name.
func TestRecoveryOpsNeedPasskeys(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Recovery = &fakeRecovery{}
	for _, op := range localapi.RecoveryOps {
		if r.srv.Ops()[op] != nil {
			t.Fatalf("%s served without passkeys", op)
		}
	}
	p, _ := passkeyRig(t)
	for _, op := range localapi.RecoveryOps {
		if p.ops[op] != nil {
			t.Fatalf("%s served without Recovery", op)
		}
	}
}

// Only the closed set of codes reaches the page, and a begin answer out of
// shape is unavailable.
func TestRecoveryRefusalsAreTheClosedSet(t *testing.T) {
	r, f := recoveryRig(t)
	tok := r.signIn()
	for _, c := range localapi.RecoveryCodes {
		f.err = sockets.Code(c)
		if _, err := r.call(localapi.OpRecoveryBegin, recoveryArgs(tok)[localapi.OpRecoveryBegin]); code(err) != c {
			t.Errorf("%s: %v", c, err)
		}
	}
	for _, e := range []error{errors.New("agentos-enroll: the factor does not open my store"),
		sockets.Code(localapi.ErrBackupStale), sockets.Code("keeper text")} {
		f.err = e
		if _, err := r.call(localapi.OpRecoveryBegin, recoveryArgs(tok)[localapi.OpRecoveryBegin]); code(err) != localapi.ErrRecoveryUnavailable {
			t.Errorf("begin with %v: %v", e, err)
		}
	}
}

// REQ: REC-4
// The lost-card frames (r4b) are bounded before anything reaches the owner
// side; taps and restarts share the rotations' bound; a card of any other
// length than a card's bits is unavailable, so the page never prints a
// wrong card.
func TestRecoveryLostFramesAreBounded(t *testing.T) {
	r, f := recoveryRig(t)
	tok := r.signIn()
	one := []byte{1}
	big := make([]byte, localapi.MaxPasskeyAssertion+1)
	for i, a := range []localapi.RecoveryLost{
		{Token: tok, ClientDataJSON: one, Signature: one},
		{Token: tok, AuthenticatorData: one, ClientDataJSON: one},
		{Token: tok, AuthenticatorData: one, ClientDataJSON: big, Signature: one},
	} {
		if _, err := r.call(localapi.OpRecoveryLost, a); code(err) != localapi.ErrBadArgs {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("reached the owner side: %v", f.calls)
	}
	card := recoveryArgs(tok)[localapi.OpRecoveryLostCard]
	for i, a := range []localapi.RecoveryLost{
		{Token: tok, ClientDataJSON: one, Signature: one},
		{Token: tok, AuthenticatorData: one, ClientDataJSON: big, Signature: one},
	} {
		if _, err := r.call(localapi.OpRecoveryLostCard, a); code(err) != localapi.ErrBadArgs {
			t.Errorf("card tap %d: %v", i, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("reached the owner side: %v", f.calls)
	}
	for _, n := range []int{0, localapi.RecoveryCardLen - 1, localapi.RecoveryKeyLen} {
		f.card = make([]byte, n)
		r.srv.recoveryRotates = nil
		if _, err := r.call(localapi.OpRecoveryLostCard, card); code(err) != localapi.ErrRecoveryUnavailable {
			t.Errorf("a card of %d bytes: %v", n, err)
		}
	}
	f.card = nil
	// MIG-4-recovery-r4c (#4128): the bits are cleared once the frame is
	// encoded, so the owner side keeps no copy.
	v, err := r.call(localapi.OpRecoveryLostCard, card)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(v)
	var got localapi.RecoveryLostCard
	if err != nil || json.Unmarshal(raw, &got) != nil || !bytes.Equal(got.Card, bytes.Repeat([]byte{9}, localapi.RecoveryCardLen)) {
		t.Fatalf("card %x, %v", got.Card, err)
	}
	if !bytes.Equal(f.gave, make([]byte, localapi.RecoveryCardLen)) {
		t.Fatal("the encoded bits stay in memory")
	}
	f.err = sockets.Code(localapi.ErrRecoveryNoCard)
	r.srv.recoveryRotates = nil
	if _, err := r.call(localapi.OpRecoveryLostCard, card); code(err) != localapi.ErrRecoveryNoCard {
		t.Fatalf("no card: %v", err)
	}
	if _, err := r.call(localapi.OpRecoveryLostCardBegin, localapi.RecoverySession{Token: tok}); code(err) != localapi.ErrRecoveryNoCard {
		t.Fatalf("no card to begin: %v", err)
	}
	r.srv.recoveryRotates = nil
	f.err = nil
	for i := range RecoveryRotatesPerMinute + 1 {
		op, args := localapi.OpRecoveryLost, recoveryArgs(tok)[localapi.OpRecoveryLost]
		if i%2 == 1 {
			op, args = localapi.OpRecoveryRestart, recoveryArgs(tok)[localapi.OpRecoveryRestart]
		}
		_, err := r.call(op, args)
		if want := i == RecoveryRotatesPerMinute; (code(err) == localapi.ErrLimited) != want {
			t.Fatalf("%s %d: %v", op, i, err)
		}
	}
}

// A lost-card begin answer out of shape (a challenge of another length, or
// a recipient ID that is neither none nor RecoveryIDLen) is unavailable,
// so the page never asks a tap over it; one from a box with no recipient
// passes.
func TestRecoveryLostBeginShape(t *testing.T) {
	r, f := recoveryRig(t)
	tok := r.signIn()
	for i, b := range []localapi.RecoveryLostBegun{
		{Old: strings.Repeat("a", 32), Challenge: make([]byte, 31)},
		{Old: strings.Repeat("a", 31), Challenge: make([]byte, 32)},
	} {
		f.begun = &b
		if _, err := r.call(localapi.OpRecoveryLostBegin, localapi.RecoverySession{Token: tok}); code(err) != localapi.ErrRecoveryUnavailable {
			t.Errorf("case %d: %v", i, err)
		}
	}
	f.begun = &localapi.RecoveryLostBegun{Challenge: make([]byte, 32)}
	if _, err := r.call(localapi.OpRecoveryLostBegin, localapi.RecoverySession{Token: tok}); err != nil {
		t.Fatalf("no recipient yet: %v", err)
	}
}

// A card begin answer out of shape (a challenge or an ID of another
// length) is unavailable, so the page never asks a tap over it nor prints
// a wrong mark.
func TestRecoveryLostCardBeginShape(t *testing.T) {
	r, f := recoveryRig(t)
	tok := r.signIn()
	for i, b := range []localapi.RecoveryLostCardBegun{
		{ID: strings.Repeat("a", 32), Challenge: make([]byte, 31)},
		{ID: strings.Repeat("a", 31), Challenge: make([]byte, 32)},
		{Challenge: make([]byte, 32)},
	} {
		f.shown = &b
		if _, err := r.call(localapi.OpRecoveryLostCardBegin, localapi.RecoverySession{Token: tok}); code(err) != localapi.ErrRecoveryUnavailable {
			t.Errorf("case %d: %v", i, err)
		}
	}
}
