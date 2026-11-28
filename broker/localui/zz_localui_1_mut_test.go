package localui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
)

// REQ: REC-4

// localui1Kills runs, as subtests of TestRecoveryKeyWithCRLFOpensTheSlot
// (through recoveryEdges), the checks that kill MUT-kill-localui-1's
// mutgate survivors (#6765) in recovery.go, agent.go and card.go. They
// are subtests for the reason recoveryEdges gives.
func localui1Kills(t *testing.T) {
	t.Run("ExpiredReplacementIsDroppedAndWiped", expiredReplacementIsDroppedAndWiped)
	t.Run("ExpiredConfirmedReplacementIsDropped", expiredConfirmedReplacementIsDropped)
	t.Run("UnmadeCardWipesTheFactor", unmadeCardWipesTheFactor)
	t.Run("LostPagesAnswerOnce", lostPagesAnswerOnce)
	t.Run("CallForNeedsAnOwner", callForNeedsAnOwner)
	t.Run("VoidCodesConfirmAnswersOnce", voidCodesConfirmAnswersOnce)
	t.Run("KeeperNoteConfirmAnswersOnce", keeperNoteConfirmAnswersOnce)
}

// A replacement past RecoveryPendingFor is no longer pending, and its
// factor and card are erased when a page first finds it expired.
func expiredReplacementIsDroppedAndWiped(t *testing.T) {
	r := newRecoveryRig(t)
	cards := keepCards(r)
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	p := r.srv.recovery.p
	if p == nil || len(*cards) != 1 || zeroed(p.secret) {
		t.Fatal("the factor started no replacement")
	}
	r.advance(RecoveryPendingFor)
	r.get("/recovery/")
	if c := (*cards)[0]; !zeroed(p.secret) || p.display != nil || c.RecoveryKey != "" || c.VaultPassphrase != "" {
		t.Fatalf("an expired replacement kept its factor or card: %q %q", p.secret, c.RecoveryKey)
	}
}

// A replacement that expires after its card was confirmed, whose display
// no longer discards, is no longer pending either.
func expiredConfirmedReplacementIsDropped(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	r.factor(map[string]string{"passphrase": "alpha bravo charlie delta"})
	r.confirm(false)
	p := r.srv.recovery.p
	if p == nil || p.begun == nil {
		t.Fatal("the confirm left no replacement waiting on its tap")
	}
	r.advance(RecoveryPendingFor)
	r.get("/recovery/")
	if r.srv.recovery.p != nil || !zeroed(p.next) {
		t.Fatalf("an expired confirmed replacement stayed pending: %v", r.srv.recovery.p != nil)
	}
}

// A card the display cannot make wipes the factor it would have carried.
func unmadeCardWipesTheFactor(t *testing.T) {
	r := newRecoveryRig(t)
	r.srv.cfg.RecoveryCard = func(io.Reader) (*card.Card, error) { return nil, errors.New("no card") }
	secret := []byte("canary-factor-secret")
	if err := r.srv.recoveryStart("tok", "passphrase", secret); err == nil || !zeroed(secret) || r.srv.recovery.p != nil {
		t.Fatalf("an unmade card: err %v, factor %q", err, secret)
	}
}

// onePage fails unless w holds exactly one response: a redirect with no
// page after it, or one page.
func onePage(t *testing.T, path string, code int, body string) {
	t.Helper()
	n := strings.Count(strings.ToLower(body), "<!doctype html>")
	if (code == http.StatusSeeOther && n != 0) || (code != http.StatusSeeOther && n != 1) {
		t.Fatalf("GET %s answered %d with %d pages:\n%s", path, code, n, body)
	}
}

// The lost-card pages answer alone: the recovery page does not follow them.
func lostPagesAnswerOnce(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	for _, path := range []string{"/recovery/lost", "/recovery/new"} {
		w := r.do("GET", path, nil)
		onePage(t, path, w.Code, w.Body.String())
	}
}

// callFor without an owner refuses rather than calling a nil one.
func callForNeedsAnOwner(t *testing.T) {
	if err := (&Server{}).callFor(context.Background(), "status", struct{}{}, nil); !errors.Is(err, errNoOwner) {
		t.Fatalf("callFor with no owner: %v", err)
	}
}

// The confirm whose provision voided the codes redirects with no body:
// the display's own reply is not written after the redirect.
func voidCodesConfirmAnswersOnce(t *testing.T) {
	vr := newVoidRig(t)
	vr.toCard()
	vr.get("/setup/card")
	w, g := vr.answers()
	vr.refuse = true
	rec := vr.do("POST", "/setup/card", map[string][]string{"word": {w}, "group": {g}})
	if rec.Code != http.StatusSeeOther || rec.Body.Len() != 0 {
		t.Fatalf("void confirm: %d\n%s", rec.Code, rec.Body)
	}
}

// The confirm the keeper refused redirects with no body.
func keeperNoteConfirmAnswersOnce(t *testing.T) {
	kr := newKeeperRig(t)
	kr.toCard()
	kr.get("/setup/card")
	kr.keeper.set(KeeperTaken, nil)
	w, g := kr.answers()
	rec := kr.do("POST", "/setup/card", map[string][]string{"word": {w}, "group": {g}})
	if rec.Code != http.StatusSeeOther || rec.Body.Len() != 0 {
		t.Fatalf("refused confirm: %d\n%s", rec.Code, rec.Body)
	}
}
