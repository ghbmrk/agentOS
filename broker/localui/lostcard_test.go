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
	"github.com/ghbmrk/agentos/broker/card/words"
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

// testLostID is the made card's ID, testLostMark its mark.
var (
	testLostID   = "9f3a" + "c41e" + strings.Repeat("0d", 12)
	testLostMark = "9F3A-C41E"
	testCardCh   = []byte("0123456789fedcba0123456789fedcba")
)

func (f *fakeRecoveryOps) id() string {
	if f.lostID == "" {
		return testLostID
	}
	return f.lostID
}

func (f *fakeRecoveryOps) RecoveryLostCardBegin(context.Context, string) (localapi.RecoveryLostCardBegun, error) {
	f.lost = append(f.lost, "cardbegin")
	if f.lostCard == nil {
		return localapi.RecoveryLostCardBegun{}, Refused(localapi.ErrRecoveryNoCard)
	}
	return localapi.RecoveryLostCardBegun{ID: f.id(), Challenge: testCardCh}, nil
}

func (f *fakeRecoveryOps) RecoveryLostCard(_ context.Context, _ string, ad, cd, sig []byte) (localapi.RecoveryLostCard, error) {
	f.lost = append(f.lost, fmt.Sprintf("card %s %s %s", ad, cd, sig))
	if f.cardErr != nil {
		return localapi.RecoveryLostCard{}, f.cardErr
	}
	if f.lostCard == nil {
		return localapi.RecoveryLostCard{}, Refused(localapi.ErrRecoveryNoCard)
	}
	return localapi.RecoveryLostCard{Card: bytes.Clone(f.lostCard), ID: f.id()}, nil
}

func (f *fakeRecoveryOps) RecoveryLostDone(context.Context, string) error {
	f.lost = append(f.lost, "done")
	f.lostCard, f.lostState.Ready = nil, false
	return f.doneErr
}

var lostTap = url.Values{"step": {"lost"}, "ad": {base64.StdEncoding.EncodeToString([]byte("ad"))},
	"cd": {base64.StdEncoding.EncodeToString([]byte("cd"))}, "sig": {base64.StdEncoding.EncodeToString([]byte("sig"))}}

// showTap is a hardware key's tap posted to see the card.
var showTap = url.Values{"step": {"show"}, "ad": {base64.StdEncoding.EncodeToString([]byte("ad"))},
	"cd": {base64.StdEncoding.EncodeToString([]byte("cd"))}, "sig": {base64.StdEncoding.EncodeToString([]byte("sig"))}}

// show posts the tap to see the card and follows the redirect to it.
func (r *recoveryRig) show() string {
	r.t.Helper()
	if w := r.post("/recovery/new", showTap); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/recovery/new" {
		r.t.Fatalf("the tap to see the card: %d\n%s", w.Code, w.Body)
	}
	return r.get("/recovery/new")
}

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
// MIG-4-recovery-r4c (#4128): the page first asks a hardware key's tap
// over the card, naming its mark, and reads no bits for that; the card
// printed carries the same mark (#4160). MIG-4-recovery-r4d (#4130): the
// card also prints the passphrase the unlock step derived from the same
// bits (words.FromCardKey), the confirm asks a word of it, and the done
// line says the old card's passphrase no longer opens the store and how to
// replace it. Revert mutants: the display without the passphrase (the
// page lacks it); lostDoneText saying the old passphrase still works.
func TestLostCardShownThenConfirmWipes(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	bits := bytes.Repeat([]byte{0x6b}, localapi.RecoveryCardLen)
	r.f.lostCard, r.f.lostState = bytes.Clone(bits), localapi.RecoveryLostState{Ready: true}
	if p := r.get("/recovery/"); !strings.Contains(p, `href="/recovery/new"`) {
		t.Fatal("a ready card is not offered")
	}
	text := card.RecoveryKeyText([localapi.RecoveryCardLen]byte(bits))
	pass, err := words.FromCardKey(bits)
	if err != nil {
		t.Fatal(err)
	}
	p := html.UnescapeString(r.get("/recovery/new"))
	ch := base64.StdEncoding.EncodeToString(testCardCh)
	for _, s := range []string{`id="pk-finish"`, `action="/recovery/new"`, `value="show"`, `data-challenge="` + ch + `"`, `id="pk-tap"`, testLostMark} {
		if !strings.Contains(p, s) {
			t.Errorf("the tap to see the card lacks %q", s)
		}
	}
	if strings.Contains(p, text) || strings.Contains(p, string(pass)) || fmt.Sprint(r.f.lost) != "[cardbegin]" || r.srv.lost.display != nil {
		t.Fatalf("the card's bits before the tap: %v\n%s", r.f.lost, p)
	}
	p = r.show()
	if !strings.Contains(p, text) || !strings.Contains(p, string(pass)) || strings.Contains(p, `name="cancel"`) ||
		!strings.Contains(p, "passphrase and recovery key already open my store, and your old card's no longer do") ||
		!strings.Contains(p, "Card mark: <span class=\"mono\">"+testLostMark) {
		t.Fatalf("the made card's page:\n%s", p)
	}
	// Another visit shows the same display; the kernel is read once.
	r.get("/recovery/new")
	if fmt.Sprint(r.f.lost) != "[cardbegin card ad cd sig]" {
		t.Fatalf("calls %v", r.f.lost)
	}
	w, g := r.srv.lost.display.Asks()
	res := r.post("/recovery/new", url.Values{"word": {strings.Fields(string(pass))[w-1]}, "group": {strings.Split(text, "-")[g-1]}}).Result()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/recovery/?lost=done" {
		t.Fatalf("confirm: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	if fmt.Sprint(r.f.lost) != "[cardbegin card ad cd sig done]" || r.srv.lost.display != nil {
		t.Fatalf("calls %v", r.f.lost)
	}
	p = html.UnescapeString(r.get("/recovery/?lost=done"))
	if !strings.Contains(p, lostDoneText) {
		t.Fatal("no done line")
	}
	for _, s := range []string{"Your old card's passphrase and recovery key no longer open my store", "put the new card's passphrase there in its place"} {
		if !strings.Contains(lostDoneText, s) {
			t.Errorf("the done line lacks %q", s)
		}
	}
	if strings.Contains(p, "still opens") {
		t.Error("the done page says an old secret still opens the store")
	}
}

// MIG-4-recovery-r4c (#4128), done-when: a session whose tap is a phone
// passkey's gets no card bits, and says so; a post with no tap asks
// nothing of agentosd; a hardware key's tap then shows the card. Revert
// mutant: lostCardPage serving the display without lostShow (the GET shows
// the bits).
func TestLostCardPhonePasskeySessionGetsNoBits(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	bits := bytes.Repeat([]byte{0x6b}, localapi.RecoveryCardLen)
	text := card.RecoveryKeyText([localapi.RecoveryCardLen]byte(bits))
	r.f.lostCard = bytes.Clone(bits)
	p := html.UnescapeString(r.post("/recovery/new", url.Values{"step": {"show"}}).Body.String())
	if !strings.Contains(p, lostNoShowText) || strings.Contains(p, text) || fmt.Sprint(r.f.lost) != "[cardbegin]" {
		t.Fatalf("a post with no tap: %v\n%s", r.f.lost, p)
	}
	r.f.cardErr = Refused(localapi.ErrRecoveryNotAnchor)
	w := r.post("/recovery/new", showTap)
	p = html.UnescapeString(w.Body.String())
	if w.Code != http.StatusOK || !strings.Contains(p, lostPhoneText) || strings.Contains(p, text) || r.srv.lost.display != nil {
		t.Fatalf("a phone passkey's tap: %d\n%s", w.Code, p)
	}
	if p := r.get("/recovery/new"); strings.Contains(p, text) || !strings.Contains(p, `value="show"`) {
		t.Fatalf("after a phone passkey's tap:\n%s", p)
	}
	r.f.cardErr = nil
	if p := r.show(); !strings.Contains(p, text) {
		t.Fatal("a hardware key's tap shows no card")
	}
}

// MIG-4-recovery-r4e (#4160), done-when: once the kernel holds no card,
// the page names the card in effect by its mark after a restart before the
// confirm, and a superseded card is told apart: the line names it as no
// longer in effect. A card another session confirmed, and nothing ever
// shown, each have their own line. The first step carries the same line.
func TestLostCardNoCardNamesTheCardInEffect(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	for name, c := range map[string]struct {
		st   localapi.RecoveryLostState
		want []string
	}{
		"restarted before the confirm": {localapi.RecoveryLostState{Shown: testLostID, InEffect: true},
			[]string{"I restarted before you confirmed", "The card in effect is marked " + testLostMark, "a card with another mark does not", "ask for a new card again"}},
		"superseded": {localapi.RecoveryLostState{Shown: testLostID},
			[]string{"marked " + testLostMark + ", is no longer in effect", "neither its passphrase nor its recovery key opens my store"}},
		"confirmed elsewhere": {localapi.RecoveryLostState{Shown: testLostID, Confirmed: true, InEffect: true},
			[]string{"marked " + testLostMark + ", is confirmed and in effect"}},
		"nothing shown": {localapi.RecoveryLostState{}, []string{lostNoCardText}},
	} {
		r.f.lostState = c.st
		p := html.UnescapeString(r.get("/recovery/new"))
		for _, s := range c.want {
			if !strings.Contains(p, s) {
				t.Errorf("%s: the card's page lacks %q", name, s)
			}
		}
		if r.srv.lost.display != nil {
			t.Fatalf("%s: a display with no card", name)
		}
		first := html.UnescapeString(r.get("/recovery/"))
		if c.st.Shown != "" && !strings.Contains(first, c.want[0]) {
			t.Errorf("%s: the first step lacks %q", name, c.want[0])
		}
	}
	// Two cards' lines differ by their marks.
	other := localapi.RecoveryLostState{Shown: "77aa" + "01bc" + strings.Repeat("0d", 12)}
	if a, b := lostNoCard(localapi.RecoveryLostState{Shown: testLostID}), lostNoCard(other); a == b || !strings.Contains(b, "77AA-01BC") {
		t.Fatalf("two superseded cards read the same: %q", b)
	}
}

// The made card is served only to the session that opened it: another
// session's visit wipes that display and is asked its own tap.
func TestLostCardOnlyToItsSession(t *testing.T) {
	r := newRecoveryRig(t)
	if w := r.do("GET", "/recovery/new", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("before sign-in: %d", w.Code)
	}
	r.signIn()
	r.f.lostCard = bytes.Repeat([]byte{0x6b}, localapi.RecoveryCardLen)
	r.show()
	d := r.srv.lost.display
	r.srv.lost.mu.Lock()
	r.srv.lost.starter = "another session"
	r.srv.lost.mu.Unlock()
	// Another session's visit gets the tap step, not this display; the
	// old one is gone.
	if p := r.get("/recovery/new"); !strings.Contains(p, `value="show"`) || r.srv.lost.display != nil {
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
	pass, err := words.FromCardKey(bits)
	if err != nil {
		t.Fatal(err)
	}
	group := func() url.Values {
		w, g := r.srv.lost.display.Asks()
		return url.Values{"word": {strings.Fields(string(pass))[w-1]}, "group": {strings.Split(text, "-")[g-1]}}
	}
	r.f.lostCard = bytes.Clone(bits)
	r.show()
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
// card after another tap. A box restart then loses the kernel's copy too,
// and the page names the card already printed as in effect, whose
// passphrase and recovery key open the store (#4130: not the old card's).
func TestLostCardPageRestartBeforeConfirm(t *testing.T) {
	r := newRecoveryRig(t)
	r.signIn()
	bits := bytes.Repeat([]byte{0x6b}, localapi.RecoveryCardLen)
	text := card.RecoveryKeyText([localapi.RecoveryCardLen]byte(bits))
	r.f.lostCard, r.f.lostState = bytes.Clone(bits), localapi.RecoveryLostState{Ready: true}
	if p := r.show(); !strings.Contains(p, text) {
		t.Fatal("the card is not shown")
	}
	// The page's process ends with no confirm: its in-memory state is gone.
	r.srv.lost.mu.Lock()
	r.srv.lost.display, r.srv.lost.starter, r.srv.lost.until = nil, "", time.Time{}
	r.srv.lost.mu.Unlock()
	if p := r.get("/recovery/new"); strings.Contains(p, text) {
		t.Fatal("the reopened page shows the card without a tap")
	}
	if p := r.show(); !strings.Contains(p, text) {
		t.Fatal("the reopened page does not show the kernel's card")
	}
	if fmt.Sprint(r.f.lost) != "[card ad cd sig cardbegin card ad cd sig]" {
		t.Fatalf("calls %v", r.f.lost)
	}
	// The whole box restarts with no confirm: the kernel's copy is gone.
	r.srv.lost.mu.Lock()
	r.srv.lost.display, r.srv.lost.starter, r.srv.lost.until = nil, "", time.Time{}
	r.srv.lost.mu.Unlock()
	r.f.lostCard, r.f.lostState = nil, localapi.RecoveryLostState{Shown: testLostID, InEffect: true}
	p := html.UnescapeString(r.get("/recovery/new"))
	for _, s := range []string{"The card in effect is marked " + testLostMark, "keep it, as its passphrase and recovery key open my store", "ask for a new card again"} {
		if !strings.Contains(p, s) {
			t.Errorf("after a box restart the page lacks %q", s)
		}
	}
	if strings.Contains(p, "passphrase still opens") {
		t.Error("after a box restart the page says the old passphrase still opens the store")
	}
}
