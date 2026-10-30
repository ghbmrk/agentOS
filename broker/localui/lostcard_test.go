package localui

// REQ: REC-4

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localapi"
)

var testLostBegun = localapi.RecoveryLostBegun{Old: strings.Repeat("c3", 16), Challenge: []byte("fedcba9876543210fedcba9876543210")}

func (f *fakeRecoveryOps) RecoveryLostBegin(context.Context, string) (localapi.RecoveryLostBegun, error) {
	f.lost = append(f.lost, "begin")
	return testLostBegun, f.lostErr
}

func (f *fakeRecoveryOps) RecoveryLost(_ context.Context, _ string, ad, cd, sig []byte) error {
	f.lost = append(f.lost, fmt.Sprintf("lost %s %s %s", ad, cd, sig))
	if f.lostErr == nil {
		f.lostState.Filed = true
	}
	return f.lostErr
}

func (f *fakeRecoveryOps) RecoveryLostState(context.Context, string) (localapi.RecoveryLostState, error) {
	return f.lostState, nil
}

func (f *fakeRecoveryOps) RecoveryLostWithdraw(context.Context, string) error {
	f.lost = append(f.lost, "withdraw")
	f.lostState.Filed = false
	return nil
}

func (f *fakeRecoveryOps) RecoveryRestart(context.Context, string) error {
	f.lost = append(f.lost, "restart")
	return f.lostErr
}

func (f *fakeRecoveryOps) RecoveryLostCard(context.Context, string) ([]byte, error) {
	f.lost = append(f.lost, "card")
	if f.lostCard == nil {
		return nil, Refused(localapi.ErrRecoveryNoCard)
	}
	return bytes.Clone(f.lostCard), nil
}

func (f *fakeRecoveryOps) RecoveryLostDone(context.Context, string) error {
	f.lost = append(f.lost, "done")
	f.lostCard, f.lostState.Ready = nil, false
	return f.doneErr
}

var lostTap = url.Values{"step": {"lost"}, "ad": {base64.StdEncoding.EncodeToString([]byte("ad"))},
	"cd": {base64.StdEncoding.EncodeToString([]byte("cd"))}, "sig": {base64.StdEncoding.EncodeToString([]byte("sig"))}}

// Brief matrix, r4b: no request without the tap. The first step offers the
// lost-card route; its tap step shows the change and carries agentosd's
// challenge; a post without a tap files nothing, and with one files the
// request once, after which the page offers the restart and a withdraw.
func TestLostCardNeedsTheTap(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	if p := r.get("/recovery/"); !strings.Contains(p, `href="/recovery/lost"`) {
		t.Fatal("the first step does not offer the lost-card route")
	}
	p := html.UnescapeString(r.get("/recovery/lost"))
	ch := base64.StdEncoding.EncodeToString(testLostBegun.Challenge)
	for _, s := range []string{`id="pk-finish"`, `value="lost"`, `data-challenge="` + ch + `"`, `id="pk-tap"`, testLostBegun.Old, "a new key I make when I restart"} {
		if !strings.Contains(p, s) {
			t.Errorf("lost tap step lacks %q", s)
		}
	}
	if p := html.UnescapeString(r.post("/recovery/", url.Values{"step": {"lost"}}).Body.String()); !strings.Contains(p, lostNoTapText) {
		t.Fatal("no line for a post without a tap")
	}
	if fmt.Sprint(r.f.lost) != "[begin]" {
		t.Fatalf("filed without a tap: %v", r.f.lost)
	}
	p = html.UnescapeString(r.post("/recovery/", lostTap).Body.String())
	if !strings.Contains(p, lostFiledText) || !strings.Contains(p, `value="restart"`) || !strings.Contains(p, `value="withdraw"`) {
		t.Fatalf("after the tap:\n%s", p)
	}
	if fmt.Sprint(r.f.lost) != "[begin lost ad cd sig]" {
		t.Fatalf("calls %v", r.f.lost)
	}
	if p := html.UnescapeString(r.post("/recovery/", url.Values{"step": {"restart"}}).Body.String()); !strings.Contains(p, lostRestartText) {
		t.Fatal("no restart line")
	}
	if p := html.UnescapeString(r.post("/recovery/", url.Values{"step": {"withdraw"}}).Body.String()); !strings.Contains(p, lostWithdrawText) {
		t.Fatal("no withdraw line")
	}
	r.f.lostErr = Refused(localapi.ErrRecoveryNotAnchor)
	if p := html.UnescapeString(r.post("/recovery/", lostTap).Body.String()); !strings.Contains(p, "phone passkey") {
		t.Fatal("a phone passkey's tap is not named")
	}
	r.f.lostState = localapi.RecoveryLostState{Filed: true, Ignored: true}
	if p := r.get("/recovery/"); strings.Contains(p, `value="restart"`) || !strings.Contains(p, "did not make your new card") {
		t.Fatalf("an ignored request:\n%s", p)
	}
}

// Brief matrix, r4b: after the restart the page shows the card the box
// made, with no cancel (it is already in effect), and the confirm wipes
// the kernel's copy. The card the page prints is the kernel's bits.
func TestLostCardShownThenConfirmWipes(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	bits := bytes.Repeat([]byte{0x6b}, localapi.RecoveryCardLen)
	r.f.lostCard, r.f.lostState = bytes.Clone(bits), localapi.RecoveryLostState{Ready: true}
	if p := r.get("/recovery/"); !strings.Contains(p, `href="/recovery/new"`) {
		t.Fatal("a ready card is not offered")
	}
	text := card.RecoveryKeyText([localapi.RecoveryCardLen]byte(bits))
	p := r.get("/recovery/new")
	if !strings.Contains(p, text) || strings.Contains(p, `name="cancel"`) || !strings.Contains(p, "recovery key already opens my store") {
		t.Fatalf("the made card's page:\n%s", p)
	}
	// Another visit shows the same display; the kernel is read once.
	r.get("/recovery/new")
	if fmt.Sprint(r.f.lost) != "[card]" {
		t.Fatalf("calls %v", r.f.lost)
	}
	_, g := r.srv.lost.display.Asks()
	res := r.post("/recovery/new", url.Values{"group": {strings.Split(text, "-")[g-1]}}).Result()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/recovery/?lost=done" {
		t.Fatalf("confirm: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if fmt.Sprint(r.f.lost) != "[card done]" || r.srv.lost.display != nil {
		t.Fatalf("calls %v", r.f.lost)
	}
	if p := html.UnescapeString(r.get("/recovery/?lost=done")); !strings.Contains(p, lostDoneText) {
		t.Fatal("no done line")
	}
}

// Brief matrix, r4b: a box restart before the confirm leaves no card, and
// the page tells the owner to keep the card if they printed or saved it,
// and to ask again if not.
func TestLostCardGoneTellsTheOwnerToAskAgain(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	p := html.UnescapeString(r.get("/recovery/new"))
	if !strings.Contains(p, lostGoneText) || !strings.Contains(p, "ask for a new card again") {
		t.Fatalf("no card:\n%s", p)
	}
	if r.srv.lost.display != nil {
		t.Fatal("a display with no card")
	}
	if p := html.UnescapeString(r.get("/recovery/")); !strings.Contains(p, "if not, ask again") {
		t.Fatal("the first step does not say to ask again")
	}
}

// The made card is served only to the session that opened it: another
// session's visit wipes that display and reads the kernel's copy again.
func TestLostCardOnlyToItsSession(t *testing.T) {
	r := newRecoveryRig(t)
	if w := r.do("GET", "/recovery/new", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("before sign-in: %d", w.Code)
	}
	r.signIn()
	r.f.lostCard = bytes.Repeat([]byte{0x6b}, localapi.RecoveryCardLen)
	r.get("/recovery/new")
	d := r.srv.lost.display
	r.srv.lost.mu.Lock()
	r.srv.lost.starter = "another session"
	r.srv.lost.mu.Unlock()
	// Another session's visit replaces the display with its own; the old
	// one is gone.
	r.get("/recovery/new")
	if r.srv.lost.display == d {
		t.Fatal("another session was served this session's display")
	}
	if _, err := d.Page(); err == nil {
		t.Fatal("the replaced display still holds the card")
	}
}

// A kernel that restarted after the page read the card answers the
// confirm with no card: the card the owner confirmed still opens the
// store, so the confirm is done; any other refusal keeps the card shown.
func TestLostCardConfirmAfterAKernelRestart(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	bits := bytes.Repeat([]byte{0x6b}, localapi.RecoveryCardLen)
	text := card.RecoveryKeyText([localapi.RecoveryCardLen]byte(bits))
	group := func() url.Values {
		_, g := r.srv.lost.display.Asks()
		return url.Values{"group": {strings.Split(text, "-")[g-1]}}
	}
	r.f.lostCard = bytes.Clone(bits)
	r.get("/recovery/new")
	r.f.doneErr = Refused(localapi.ErrRecoveryUnavailable)
	if w := r.post("/recovery/new", group()); w.Code == http.StatusSeeOther || r.srv.lost.display == nil {
		t.Fatalf("an unavailable kernel finished the confirm: %d", w.Code)
	}
	r.f.doneErr = Refused(localapi.ErrRecoveryNoCard)
	if w := r.post("/recovery/new", group()); w.Code != http.StatusSeeOther || r.srv.lost.display != nil {
		t.Fatalf("no card at the confirm: %d", w.Code)
	}
}

// Losing the page's process before the confirm loses only its display:
// the kernel still holds the card, so the reopened page shows the same
// card. A box restart then loses the kernel's copy too, and the page
// says the card already printed is in effect and the old passphrase
// still opens the store.
func TestLostCardPageRestartBeforeConfirm(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	bits := bytes.Repeat([]byte{0x6b}, localapi.RecoveryCardLen)
	text := card.RecoveryKeyText([localapi.RecoveryCardLen]byte(bits))
	r.f.lostCard, r.f.lostState = bytes.Clone(bits), localapi.RecoveryLostState{Ready: true}
	if p := r.get("/recovery/new"); !strings.Contains(p, text) {
		t.Fatal("the card is not shown")
	}
	// The page's process ends with no confirm: its in-memory state is gone.
	r.srv.lost.mu.Lock()
	r.srv.lost.display, r.srv.lost.starter, r.srv.lost.until = nil, "", time.Time{}
	r.srv.lost.mu.Unlock()
	if p := r.get("/recovery/new"); !strings.Contains(p, text) {
		t.Fatal("the reopened page does not show the kernel's card")
	}
	if fmt.Sprint(r.f.lost) != "[card card]" {
		t.Fatalf("calls %v", r.f.lost)
	}
	// The whole box restarts with no confirm: the kernel's copy is gone.
	r.srv.lost.mu.Lock()
	r.srv.lost.display, r.srv.lost.starter, r.srv.lost.until = nil, "", time.Time{}
	r.srv.lost.mu.Unlock()
	r.f.lostCard, r.f.lostState = nil, localapi.RecoveryLostState{}
	p := html.UnescapeString(r.get("/recovery/new"))
	for _, s := range []string{"If you printed or saved it, it is in effect", "so keep it", "If not, ask for a new card again", "Your old card's passphrase still opens my store"} {
		if !strings.Contains(p, s) {
			t.Errorf("after a box restart the page lacks %q", s)
		}
	}
}
