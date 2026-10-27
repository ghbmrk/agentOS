package localui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: REC-4, CRED-1

// fakeRotVault is the vault process's rotation ops as the page sees them.
type fakeRotVault struct {
	mu        sync.Mutex
	begun     []RotationBegin
	committed []card.Card
	commitIDs []string
	cancelIDs []string
	pending   bool
	enrolled  []string
	shown     []string
	beginErr  error
	commitErr error
	result    RotationResult
	expires   time.Time
	// commitIn, when set, is told each commit as it reaches the vault
	// process; commitGo then holds its answer until a send (a late answer).
	commitIn, commitGo chan struct{}
	// onCommit, when set, runs as each commit reaches the vault process
	// (a phone hanging up mid-confirm).
	onCommit func()
}

func (f *fakeRotVault) BeginRotation(_ context.Context, b RotationBegin) (RotationStarted, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.begun = append(f.begun, b)
	if f.beginErr != nil {
		return RotationStarted{}, f.beginErr
	}
	return RotationStarted{Parts: b.Parts, WiFiName: "AgentOS-TEST", Expires: f.expires}, nil
}

func (f *fakeRotVault) CommitRotation(_ context.Context, id string, c card.Card) (RotationResult, error) {
	if f.commitIn != nil {
		f.commitIn <- struct{}{}
		<-f.commitGo
	}
	if f.onCommit != nil {
		f.onCommit()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.committed = append(f.committed, c)
	f.commitIDs = append(f.commitIDs, id)
	if f.commitErr != nil {
		return RotationResult{}, f.commitErr
	}
	return f.result, nil
}

func (f *fakeRotVault) CancelRotation(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelIDs = append(f.cancelIDs, id)
	return nil
}

func (f *fakeRotVault) EnrollmentPending(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pending, nil
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
	return len(f.begun), len(f.committed), len(f.cancelIDs)
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
	x.r.Now = x.clock
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
	x.start(t, url.Values{"parts": {"setup", "grid"}, "code": {"123456"}})
	first := x.r.Display()
	x.start(t, url.Values{"parts": {"setup"}, "code": {"234567"}})
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
	w := x.post("/rotate/", url.Values{"parts": {"setup"}, "code": {"000000"}})
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

// #1175 security S-R1: each rotation's begin names a fresh ID, and its
// commit and its display's discard carry that ID, even when a newer
// rotation has replaced it, so the vault process can refuse a stale one.
func TestRotationOpsCarryTheBegunID(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RK"}})
	first := x.r.Display()
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RK"}})
	a, b := x.v.begun[0].ID, x.v.begun[1].ID
	if len(a) != 32 || len(b) != 32 || a == b {
		t.Fatalf("rotation IDs %q %q", a, b)
	}
	if len(x.v.cancelIDs) != 1 || x.v.cancelIDs[0] != a {
		t.Fatalf("the replaced rotation was cancelled as %v, want %s", x.v.cancelIDs, a)
	}
	_ = first.Discard() // a stale display's discard names its own rotation
	if x.v.cancelIDs[len(x.v.cancelIDs)-1] == b {
		t.Fatal("a stale display's discard named the newer rotation")
	}
	if err := x.r.Display().ConfirmAnswers(card.Answers{Group: x.group().Get("group")}); err != nil {
		t.Fatal(err)
	}
	if len(x.v.commitIDs) != 1 || x.v.commitIDs[0] != b {
		t.Fatalf("commit carried %v, want %s", x.v.commitIDs, b)
	}
}

// #1175 security S-R1: a begin that got no answer (or a vault failure)
// may still be held or arrive late, so the page cancels it by its ID; a
// begin the vault process refused holds nothing and is not cancelled.
func TestRotationBeginWithNoAnswerIsCancelled(t *testing.T) {
	for _, e := range []error{errors.New("synthetic: connection reset"), &VaultError{http.StatusBadGateway, "internal error"}} {
		x := newWireRig(t)
		x.v.beginErr = e
		if err := x.r.Start(context.Background(), RotationBegin{Recovery: "SYNTH-RK", Parts: card.Parts{WiFi: true}}); err == nil {
			t.Fatal("start succeeded")
		}
		if len(x.v.cancelIDs) != 1 || x.v.cancelIDs[0] != x.v.begun[0].ID {
			t.Fatalf("%v: cancels %v for begin %s", e, x.v.cancelIDs, x.v.begun[0].ID)
		}
	}
	x := newWireRig(t)
	x.v.beginErr = &VaultError{http.StatusForbidden, "wrong code"}
	_ = x.r.Start(context.Background(), RotationBegin{Code: "000000", Parts: card.Parts{WiFi: true}})
	if len(x.v.cancelIDs) != 0 {
		t.Fatal("a refused begin was cancelled")
	}
}

// #1175 UX U-R1: while a replaced code generator waits for its first
// code, the start page offers to show it again with the recovery key, and
// the done page points there.
func TestRotationStartPageOffersTheUnconfirmedCodeGenerator(t *testing.T) {
	x := newWireRig(t)
	if p := x.get("/rotate/"); strings.Contains(p, "Show the new code generator") {
		t.Fatal("offered with nothing to show")
	}
	x.v.pending = true
	p := x.get("/rotate/")
	if !strings.Contains(p, "Show the new code generator") || !strings.Contains(p, `action="/rotate/show"`) {
		t.Fatalf("no show form: %s", p)
	}
	if w := x.post("/rotate/show", url.Values{"recovery": {"SYNTH-RK"}}); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<svg") || !strings.Contains(w.Body.String(), `action="/rotate/enroll"`) {
		t.Fatalf("show: %d", w.Code)
	}
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RK"}})
	x.v.result = RotationResult{Enrollment: "otpauth://totp/AgentOS?secret=CANARYSEEDBBBBBB"}
	x.post("/rotate/card", x.group())
	if done := x.get("/rotate/done"); !strings.Contains(done, "Replace Owner Card parts on Home shows it again") {
		t.Fatalf("done page: %s", done)
	}
}

// REQ: REC-4

// #1316: the committed result (notes and the new code generator's seed)
// is the confirming session's. The confirming phone skips /rotate/done;
// another signed-in session's GET of it gets no secret, and the
// confirming phone still gets it once.
func TestRotationResultIsTheConfirmingSessions(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	x.v.result = RotationResult{Notes: []string{"SYNTH-NOTE"}, Enrollment: "otpauth://totp/AgentOS?secret=CANARYSEEDCCCCCC"}
	if w := x.post("/rotate/card", x.group()); w.Header().Get("Location") != "/rotate/done" {
		t.Fatalf("confirm: %d %s", w.Code, w.Header().Get("Location"))
	}
	x.asOther(func() {
		x.signIn()
		w := x.do("GET", "/rotate/done", nil)
		if w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), "SYNTH-NOTE") || strings.Contains(w.Body.String(), "<svg") {
			t.Fatalf("another session read the result: %d %s", w.Code, w.Body.String())
		}
	})
	if done := x.get("/rotate/done"); !strings.Contains(done, "SYNTH-NOTE") || !strings.Contains(done, "<svg") {
		t.Fatalf("the confirming phone lost its result: %s", done)
	}
}

// #1316: the result expires with the rotation's confirm window, and with
// no window from the vault process, resultTTL after the start.
func TestRotationResultExpiresWithTheConfirmWindow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expires time.Duration // from the start; 0: none from the vault process
		after   time.Duration
	}{
		{"vault window", 10 * time.Minute, 10*time.Minute + time.Second},
		{"no window", 0, resultTTL + time.Second},
		// #1339: a vault window past resultTTL is capped at resultTTL.
		{"vault window 45m", 45 * time.Minute, resultTTL + time.Second},
		{"vault window 2h", 2 * time.Hour, resultTTL + time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWireRig(t)
			if tc.expires != 0 {
				x.v.expires = x.clock().Add(tc.expires)
			}
			x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
			x.v.result = RotationResult{Notes: []string{"SYNTH-NOTE"}, Enrollment: "otpauth://totp/AgentOS?secret=CANARYSEEDDDDDDD"}
			x.post("/rotate/card", x.group())
			x.advance(tc.after)
			if w := x.do("GET", "/rotate/done", nil); w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), "SYNTH-NOTE") {
				t.Fatalf("an expired result was shown: %d", w.Code)
			}
		})
	}
}

// #1316: confirming the new code generator, or showing it again with the
// recovery key, clears a result the confirming phone never fetched.
func TestRotationResultClearedByEnrollOrShow(t *testing.T) {
	for _, path := range []string{"/rotate/enroll", "/rotate/show"} {
		t.Run(path, func(t *testing.T) {
			x := newWireRig(t)
			x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
			x.v.result = RotationResult{Notes: []string{"SYNTH-NOTE"}, Enrollment: "otpauth://totp/AgentOS?secret=CANARYSEEDEEEEEE"}
			x.post("/rotate/card", x.group())
			x.post(path, url.Values{"code": {"123456"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
			if w := x.do("GET", "/rotate/done", nil); w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), "SYNTH-NOTE") {
				t.Fatalf("the result outlived %s: %d", path, w.Code)
			}
		})
	}
}

// #1316: a commit answered late, after the owner showed the code
// generator again, stores no result.
func TestRotationLateCommitAnswerStoresNoResult(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	x.v.result = RotationResult{Notes: []string{"SYNTH-NOTE"}, Enrollment: "otpauth://totp/AgentOS?secret=CANARYSEEDFFFFFF"}
	x.v.commitIn, x.v.commitGo = make(chan struct{}), make(chan struct{})
	form := x.group()
	confirmed := make(chan struct{})
	go func() {
		defer close(confirmed)
		x.post("/rotate/card", form)
	}()
	<-x.v.commitIn
	x.post("/rotate/show", url.Values{"recovery": {"SYNTH-RECOVERY-CANARY"}})
	close(x.v.commitGo)
	<-confirmed
	if w := x.do("GET", "/rotate/done", nil); w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), "SYNTH-NOTE") {
		t.Fatalf("a late commit answer stored the result: %d", w.Code)
	}
}

// #1316: a commit reached other than through a session's confirm (no
// confirmer) is shown to no session.
func TestRotationResultWithNoConfirmerIsShownToNone(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	x.v.result = RotationResult{Notes: []string{"SYNTH-NOTE"}}
	_, g := x.r.Display().Asks()
	if err := x.r.Display().ConfirmAnswers(card.Answers{Group: strings.Split(x.gen.RecoveryKey, "-")[g-1]}); err != nil {
		t.Fatal(err)
	}
	if w := x.do("GET", "/rotate/done", nil); w.Code != http.StatusSeeOther {
		t.Fatalf("a result with no confirmer was shown: %d", w.Code)
	}
}

// #1339: a new start clears the result the confirming phone never fetched.
func TestRotationStartVoidsTheResult(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	x.v.result = RotationResult{Notes: []string{"SYNTH-NOTE"}, Enrollment: "otpauth://totp/agentOS?secret=CANARYSEEDGGGGGG"}
	x.post("/rotate/card", x.group())
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	if w := x.do("GET", "/rotate/done", nil); w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), "SYNTH-NOTE") {
		t.Fatalf("the result outlived a new start: %d", w.Code)
	}
}

// #1340: a confirm near the end of the confirm window, or a commit
// answered after it, keeps the result for the confirmer for resultGrace
// after the commit's answer, never past the window plus resultGrace.
func TestRotationLateConfirmKeepsTheResultForAGrace(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expires time.Duration // the vault window, from the start
		confirm time.Duration // when the owner confirms, from the start
		answer  time.Duration // how long the commit takes to answer
		after   time.Duration // the GET of /rotate/done, after the answer
		shown   bool
	}{
		{"confirm 1s before the window ends", 10 * time.Minute, 10*time.Minute - time.Second, 0, 2 * time.Second, true},
		{"answer after the window ends", 10 * time.Minute, 9 * time.Minute, commitTimeout, 2 * time.Second, true},
		{"grace over", 10 * time.Minute, 10*time.Minute - time.Second, 0, resultGrace + time.Second, false},
		{"capped at the window plus the grace", 2 * time.Hour, 40 * time.Minute, 0, time.Second, false},
		{"late confirm past a capped window, within the cap", 2 * time.Hour, 33 * time.Minute, 0, 2*time.Minute - time.Second, true},
		{"late confirm past a capped window, past the cap", 2 * time.Hour, 33 * time.Minute, 0, 2*time.Minute + time.Second, false},
		// #1597: an early confirm's result lasts until the window's end.
		{"early confirm lasts to the window's end", 10 * time.Minute, time.Minute, 0, resultGrace, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newWireRig(t)
			x.v.expires = x.clock().Add(tc.expires)
			x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
			x.v.result = RotationResult{Notes: []string{"SYNTH-NOTE"}, Enrollment: "otpauth://totp/agentOS?secret=CANARYSEEDHHHHHH"}
			x.advance(tc.confirm)
			x.v.commitIn, x.v.commitGo = make(chan struct{}), make(chan struct{})
			form := x.group()
			confirmed := make(chan struct{})
			go func() {
				defer close(confirmed)
				x.post("/rotate/card", form)
			}()
			<-x.v.commitIn
			x.advance(tc.answer)
			close(x.v.commitGo)
			<-confirmed
			x.advance(tc.after)
			w := x.do("GET", "/rotate/done", nil)
			if got := w.Code == http.StatusOK && strings.Contains(w.Body.String(), "SYNTH-NOTE"); got != tc.shown {
				t.Fatalf("shown = %v, want %v: %d", got, tc.shown, w.Code)
			}
		})
	}
}

// REQ: REC-4, HW-1

// #1338: the waiting display (the new parts, and after its confirm the new
// code generator's seed) is the starting session's. Another signed-in
// session's GET and POST of /rotate/card are sent home with neither, the
// vault process sees no commit, and the starter still confirms and gets
// the result.
func TestRotationDisplayIsTheStartingSessions(t *testing.T) {
	x := newWireRig(t)
	x.start(t, url.Values{"parts": {"recovery"}, "recovery": {"SYNTH-RECOVERY-CANARY"}})
	x.v.result = RotationResult{Notes: []string{"SYNTH-NOTE"}, Enrollment: "otpauth://totp/agentOS?secret=CANARYSEEDIIIIII"}
	form := x.group()
	group := form.Get("group")
	x.asOther(func() {
		x.signIn()
		for _, w := range []*httptest.ResponseRecorder{x.do("GET", "/rotate/card", nil), x.post("/rotate/card", form)} {
			b := w.Body.String()
			if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/home" || strings.Contains(b, group) || strings.Contains(b, "CANARYSEED") || strings.Contains(b, "SYNTH-NOTE") {
				t.Fatalf("another session reached the display: %d %s %s", w.Code, w.Header().Get("Location"), b)
			}
		}
		if w := x.do("GET", "/rotate/done", nil); w.Code != http.StatusSeeOther || strings.Contains(w.Body.String(), "SYNTH-NOTE") {
			t.Fatalf("another session read a result: %d", w.Code)
		}
	})
	if _, committed, _ := x.v.n(); committed != 0 {
		t.Fatalf("another session's post committed %d", committed)
	}
	if p := x.get("/rotate/card"); !strings.Contains(p, group) {
		t.Fatal("the starter lost the display")
	}
	if w := x.post("/rotate/card", form); w.Header().Get("Location") != "/rotate/done" {
		t.Fatalf("the starter's confirm: %d %s", w.Code, w.Header().Get("Location"))
	}
	if done := x.get("/rotate/done"); !strings.Contains(done, "SYNTH-NOTE") || !strings.Contains(done, "<svg") {
		t.Fatalf("the starter lost its result: %s", done)
	}
}

// #1338: a start not posted by a session has no starter, so its display
// is shown to no session.
func TestRotationDisplayWithNoStarterIsShownToNone(t *testing.T) {
	x := newWireRig(t)
	if err := x.r.Start(context.Background(), RotationBegin{Recovery: "SYNTH-RK", Parts: card.Parts{Recovery: true}}); err != nil {
		t.Fatal(err)
	}
	for _, w := range []*httptest.ResponseRecorder{x.do("GET", "/rotate/card", nil), x.post("/rotate/card", x.group())} {
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/home" {
			t.Fatalf("a display with no starter was served: %d %s", w.Code, w.Header().Get("Location"))
		}
	}
	if _, committed, _ := x.v.n(); committed != 0 {
		t.Fatal("a display with no starter committed")
	}
}
