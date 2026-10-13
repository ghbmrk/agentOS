package localui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: REC-4, CRED-1

// fakeRotVault is the vault process's rotation ops as the page sees them.
type fakeRotVault struct {
	mu        sync.Mutex
	begun     []RotationBegin
	committed []card.Card
	cancels   int
	enrolled  []string
	shown     []string
	beginErr  error
	commitErr error
	result    RotationResult
}

func (f *fakeRotVault) BeginRotation(_ context.Context, b RotationBegin) (RotationStarted, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begun = append(f.begun, b)
	if f.beginErr != nil {
		return RotationStarted{}, f.beginErr
	}
	return RotationStarted{Parts: b.Parts, WiFiName: "AgentOS-TEST"}, nil
}

func (f *fakeRotVault) CommitRotation(_ context.Context, c card.Card) (RotationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.committed = append(f.committed, c)
	if f.commitErr != nil {
		return RotationResult{}, f.commitErr
	}
	return f.result, nil
}

func (f *fakeRotVault) CancelRotation(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancels++
	return nil
}

func (f *fakeRotVault) ConfirmEnrollment(_ context.Context, code string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enrolled = append(f.enrolled, code)
	return code == "123456", nil
}

func (f *fakeRotVault) ShowEnrollment(_ context.Context, rk string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shown = append(f.shown, rk)
	return "otpauth://totp/AgentOS?secret=CANARYSEEDAAAAAA", nil
}

func (f *fakeRotVault) n() (begun, committed, cancels int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.begun), len(f.committed), f.cancels
}

// wireRig is a set-up, signed-in box whose card rotation is the real
// Rotation over a fake vault process.
type wireRig struct {
	*rig
	v   *fakeRotVault
	r   *Rotation
	gen *card.Card
}

func newWireRig(t *testing.T) *wireRig {
	t.Helper()
	x := &wireRig{rig: newRig(t), v: &fakeRotVault{}}
	x.r = NewRotation(x.v)
	x.r.Generate = func(rd io.Reader) (*card.Card, error) {
		c, err := card.Generate(rd)
		if err == nil {
			cp := *c
			x.gen = &cp
		}
		return c, err
	}
	x.rot = x.r
	x.srv = x.open(&MemStore{})
	x.runSetup()
	x.startChannel(modem.NewCarrier().Line(boxNum))
	x.signIn()
	return x
}

// start begins a rotation of the recovery key from the page.
func (x *wireRig) start(t *testing.T, form url.Values) {
	t.Helper()
	w := x.post("/rotate/", form)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/rotate/card" {
		t.Fatalf("start: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
}

func (x *wireRig) group() url.Values {
	_, g := x.r.Display().Asks()
	return url.Values{"group": {strings.Split(x.gen.RecoveryKey, "-")[g-1]}}
}

// REC-4: the box page starts a rotation in the vault process with the
// owner's proof, shows the new parts, and the confirm commits exactly the
// shown parts; the result's notes and the new code generator's QR are
// shown once, and a code from it confirms it.
func TestRotationStartsOnTheBoxPageAndCommitsTheShownParts(t *testing.T) {
	x := newWireRig(t)
	if p := x.get("/rotate/"); !strings.Contains(p, `name="parts"`) || !strings.Contains(p, `name="recovery"`) {
		t.Fatal("no start form")
	}
	rk := "SYNTH-RECOVERY-CANARY"
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {rk}})
	if len(x.v.begun) != 1 || x.v.begun[0].Recovery != rk || x.v.begun[0].Parts != (card.Parts{Recovery: true}) {
		t.Fatalf("begin: %+v", x.v.begun)
	}
	if !strings.Contains(x.get("/rotate/card"), x.gen.RecoveryKey) {
		t.Fatal("the new key is not shown")
	}
	x.v.result = RotationResult{Notes: []string{"Your old recovery key no longer opens the drive."},
		Enrollment: "otpauth://totp/AgentOS?secret=CANARYSEEDBBBBBB"}
	w := x.post("/rotate/card", x.group())
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/rotate/done" {
		t.Fatalf("confirm: %d %s", w.Code, w.Header().Get("Location"))
	}
	if len(x.v.committed) != 1 {
		t.Fatal("not committed once")
	}
	got := x.v.committed[0]
	if got.RecoveryKey != x.gen.RecoveryKey || got.WiFiPassword != "" || got.VaultPassphrase != "" || got.SetupSecret != "" || got.GridSeed != nil {
		t.Fatal("the commit carried other than the shown parts")
	}
	done := x.get("/rotate/done")
	if !strings.Contains(done, "no longer opens") || !strings.Contains(done, "<svg") || !strings.Contains(done, `name="code"`) {
		t.Fatalf("done page: %s", done)
	}
	if w := x.do("GET", "/rotate/done", nil); w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), "CANARYSEED") {
		t.Fatalf("the result was shown twice: %d", w.Code)
	}
	if w := x.post("/rotate/enroll", url.Values{"code": {"000000"}}); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong enrollment code: %d", w.Code)
	}
	if p := x.post("/rotate/enroll", url.Values{"code": {"123456"}}); p.Code != http.StatusOK || !strings.Contains(p.Body.String(), "confirmed") {
		t.Fatalf("enrollment: %d", p.Code)
	}
	if w := x.post("/rotate/show", url.Values{"recovery": {rk}}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<svg") {
		t.Fatalf("show again: %d", w.Code)
	}
}

// #1090 review R2, CRED-1: the page's cancel reaches the vault process,
// so the pending rotation (and any passphrase it holds) goes at once; a
// new start replaces a waiting one the same way.
func TestRotationCancelReachesTheVault(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RK"}})
	if w := x.post("/rotate/card", url.Values{"cancel": {"1"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("cancel: %d", w.Code)
	}
	if _, c, n := x.v.n(); n != 1 || c != 0 {
		t.Fatalf("cancel reached the vault %d times, %d commits", n, c)
	}
	x.start(t, url.Values{"parts": {"wifi", "grid"}, "code": {"123456"}})
	first := x.r.Display()
	x.start(t, url.Values{"parts": {"wifi"}, "code": {"234567"}})
	if _, err := first.Page(); err == nil {
		t.Fatal("a replaced rotation kept its display")
	}
	if _, _, n := x.v.n(); n != 2 {
		t.Fatalf("replacing a rotation did not cancel it: %d", n)
	}
}

// #1090 review R1: the provisioner maps the vault process's refusals: a
// lapsed or spent rotation (410) discards the display, a partial write
// (409) leaves it in effect and uncancellable, anything else keeps the
// card for a retry.
func TestRotationProvisionerMapsTheVaultsRefusals(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RK"}})
	x.v.commitErr = &VaultError{http.StatusBadRequest, "the new card does not match the parts being replaced"}
	if err := x.r.Display().ConfirmAnswers(card.Answers{Group: x.group().Get("group")}); err == nil || errors.Is(err, card.ErrDiscard) || errors.Is(err, card.ErrInEffect) {
		t.Fatalf("400: %v", err)
	}
	if _, err := x.r.Display().Page(); err != nil {
		t.Fatal("a plain failure erased the card")
	}
	x.v.commitErr = &VaultError{http.StatusGone, "this new card has lapsed; nothing changed, start again"}
	if err := x.r.Display().ConfirmAnswers(card.Answers{Group: x.group().Get("group")}); !errors.Is(err, card.ErrDiscard) {
		t.Fatalf("410: %v", err)
	}
	if _, err := x.r.Display().Page(); err == nil {
		t.Fatal("a lapsed rotation kept the card")
	}

	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RK"}})
	x.v.commitErr = &VaultError{http.StatusConflict, "part of the new card is in effect but was not saved; print it now"}
	_, _, before := x.v.n()
	if err := x.r.Display().ConfirmAnswers(card.Answers{Group: x.group().Get("group")}); !errors.Is(err, card.ErrInEffect) {
		t.Fatalf("409: %v", err)
	}
	if err := x.r.Display().Discard(); !errors.Is(err, card.ErrInEffect) {
		t.Fatal("a card in effect could be cancelled")
	}
	if _, _, n := x.v.n(); n != before {
		t.Fatal("a card in effect cancelled the vault's rotation")
	}
}

// A commit whose outcome the page cannot know (the answer was lost, or the
// vault process failed) is treated as in effect: the owner keeps the new
// card and the current one, and a retry cannot answer 410 for a card the
// vault process stored and so erase it. The vault's rotation is dropped.
func TestRotationCommitWithNoAnswerIsInEffect(t *testing.T) {
	for _, e := range []error{errors.New("synthetic: connection reset"), &VaultError{http.StatusInternalServerError, "internal error"}} {
		x := newWireRig(t)
		x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RK"}})
		x.v.commitErr = e
		if err := x.r.Display().ConfirmAnswers(card.Answers{Group: x.group().Get("group")}); !errors.Is(err, card.ErrInEffect) {
			t.Fatalf("%v: %v", e, err)
		}
		if _, _, n := x.v.n(); n != 1 {
			t.Fatalf("%v: the vault's rotation was not dropped: %d", e, n)
		}
	}
}

// A refused start shows the vault process's reason on the form and makes
// no display; the page needs sign-in.
func TestRotationStartRefusals(t *testing.T) {
	x := newWireRig(t)
	x.v.beginErr = &VaultError{http.StatusForbidden, "wrong code; 2 tries left"}
	w := x.post("/rotate/", url.Values{"parts": {"wifi"}, "code": {"000000"}})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "wrong code; 2 tries left") || x.r.Display() != nil {
		t.Fatalf("refused start: %d %s", w.Code, w.Body.String())
	}
	if w := x.post("/rotate/", url.Values{"parts": {"bogus"}, "code": {"000000"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad part: %d", w.Code)
	}
	if b, _, _ := x.v.n(); b != 1 {
		t.Fatal("a bad part reached the vault")
	}
	x.post("/signout", url.Values{})
	if w := x.do("GET", "/rotate/", nil); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock") {
		t.Fatalf("signed out: %d %s", w.Code, w.Header().Get("Location"))
	}
}
