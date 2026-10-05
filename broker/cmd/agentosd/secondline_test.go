package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: ADP-12, CH-12

// Potency R1 on #139: while the second line waits on the owner, STATUS
// and the digest say so with the fix, in owner wording; otherwise they say
// nothing. A locked vault clears the line (the unlock has its own), and a
// vault process that does not answer keeps the last state.
func TestStatusAndDigestSayWhenTheSecondLineWaitsOnTheOwner(t *testing.T) {
	var mu sync.Mutex
	st, fail := modelroute.SecondLineOK, error(nil)
	set := func(s modelroute.SecondLineState, err error) { mu.Lock(); st, fail = s, err; mu.Unlock() }
	sl := &secondLine{get: func(context.Context) (modelroute.SecondLineState, error) {
		mu.Lock()
		defer mu.Unlock()
		return st, fail
	}}
	ctx := context.Background()
	check := func(step, want string) {
		t.Helper()
		sl.refresh(ctx)
		if got := sl.Note(); got != want {
			t.Fatalf("%s: STATUS %q, want %q", step, got, want)
		}
		d := sl.Digest()
		if want == "" && len(d) != 0 || want != "" && (len(d) != 1 || d[0] != want) {
			t.Fatalf("%s: digest %q", step, d)
		}
		if strings.Contains(want, "vault") || strings.Contains(want, "realm") {
			t.Fatalf("%s: internal wording %q", step, want)
		}
	}
	check("nothing set", "")
	set(modelroute.SecondLineConfirm, nil)
	check("realm to confirm", secondLineConfirmLine)
	if !strings.Contains(secondLineConfirmLine, "Wi-Fi page") || !strings.Contains(secondLineUnreachedLine, "server name and password") {
		t.Fatal("a line without its fix")
	}
	set("", errors.New("dial unix: connection refused"))
	check("vault process down", secondLineConfirmLine)
	set(modelroute.SecondLineUnreached, nil)
	check("provider unreached", secondLineUnreachedLine)
	set("", modelroute.ErrVaultLocked)
	check("vault locked", "")
	set(modelroute.SecondLineOK, nil)
	check("confirmed", "")
}

// UX-159-1: when the texting account's polls keep failing, STATUS and the
// digest say whether to check the account or to wait, beside the calling
// account's line; the next good poll clears it.
func TestStatusAndDigestSayWhenTextsStopArriving(t *testing.T) {
	var mu sync.Mutex
	tx, fail := modelroute.TextsOK, error(nil)
	set := func(s modelroute.TextsState, err error) { mu.Lock(); tx, fail = s, err; mu.Unlock() }
	sl := &secondLine{
		get: func(context.Context) (modelroute.SecondLineState, error) { return modelroute.SecondLineConfirm, nil },
		texts: func(context.Context) (modelroute.TextsState, error) {
			mu.Lock()
			defer mu.Unlock()
			return tx, fail
		},
	}
	ctx := context.Background()
	sl.refresh(ctx)
	check := func(step, want string) {
		t.Helper()
		sl.refreshTexts(ctx)
		if got := sl.TextsNote(); got != want {
			t.Fatalf("%s: STATUS %q, want %q", step, got, want)
		}
		d := sl.Digest()
		if want == "" && len(d) != 1 || want != "" && (len(d) != 2 || d[0] != secondLineConfirmLine || d[1] != want) {
			t.Fatalf("%s: digest %q", step, d)
		}
	}
	check("texts arriving", "")
	set(modelroute.TextsSignIn, nil)
	check("refused", textsSignInLine)
	set("", errors.New("dial unix: connection refused"))
	check("vault process down", textsSignInLine)
	set(modelroute.TextsUnreached, nil)
	check("unreached", textsUnreachedLine)
	set("", modelroute.ErrVaultLocked)
	check("vault locked", "")
	set(modelroute.TextsUnreached, nil)
	check("unreached again", textsUnreachedLine)
	set(modelroute.TextsOK, nil)
	check("a good poll", "")
	for _, l := range []string{textsSignInLine, textsUnreachedLine} {
		if !strings.Contains(l, "Wi-Fi page") || strings.Contains(l, "poll") || strings.Contains(l, "vault") {
			t.Fatalf("wording %q", l)
		}
	}
	if !strings.Contains(textsSignInLine, "account ID and auth token") {
		t.Fatal("sign-in line without its fix")
	}
}
