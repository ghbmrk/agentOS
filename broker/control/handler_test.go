package control

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CH-2, ARC-2

const owner = "+15550000001"

// fakeEngine records calls; it is the journal engine's control surface.
type fakeEngine struct {
	mu      sync.Mutex
	stopped bool
	stops   int
	resumes int
	list    []journal.Status
	report  journal.StopReport
}

func (f *fakeEngine) Stop(context.Context) (journal.StopReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	f.stops++
	return f.report, nil
}

func (f *fakeEngine) Resume() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.stopped {
		return journal.ErrState
	}
	f.stopped = false
	f.resumes++
	return nil
}

func (f *fakeEngine) Stopped() bool          { f.mu.Lock(); defer f.mu.Unlock(); return f.stopped }
func (f *fakeEngine) List() []journal.Status { return f.list }

type fakeAuth struct{ unlocked bool }

func (a fakeAuth) IsOwner(from string) bool       { return from == owner }
func (a fakeAuth) SessionUnlocked(time.Time) bool { return a.unlocked }

// downAgent is every agent and model being down: delivery always fails.
type downAgent struct{ calls int }

func (d *downAgent) Deliver(context.Context, string, bool) error {
	d.calls++
	return errors.New("no guest running")
}

// forbiddenAgent fails the test if the control path reaches it (ARC-2).
type forbiddenAgent struct{ t *testing.T }

func (f forbiddenAgent) Deliver(context.Context, string, bool) error {
	f.t.Fatal("control word reached the agent")
	return nil
}

type recAgent struct {
	text   string
	public bool
}

func (r *recAgent) Deliver(_ context.Context, text string, public bool) error {
	r.text, r.public = text, public
	return nil
}

type fixedCodes struct{ codes []string }

func (f *fixedCodes) next() string { c := f.codes[0]; f.codes = f.codes[1:]; return c }

func newHandler(t *testing.T, eng *fakeEngine, auth fakeAuth, agent Agent) (*Handler, *time.Time) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	codes := &fixedCodes{codes: []string{"111111", "222222", "333333", "444444"}}
	h := &Handler{
		Engine:  eng,
		Auth:    auth,
		Agent:   agent,
		Now:     func() time.Time { return now },
		NewCode: codes.next,
	}
	return h, &now
}

func one(t *testing.T, out []string) string {
	t.Helper()
	if len(out) != 1 {
		t.Fatalf("want one reply, got %q", out)
	}
	if !IsGSM7(out[0]) || len(out[0]) > MaxText {
		t.Fatalf("reply breaks CH-12 format: %q", out[0])
	}
	return out[0]
}

func TestCH2StopStatusHelpWorkWithAllModelsAndGuestsDown(t *testing.T) {
	eng := &fakeEngine{
		report: journal.StopReport{Held: []string{"h1"}, Unresolved: []string{"u1", "u2"}},
		list: []journal.Status{
			{Intent: journal.Intent{ID: "u1", Action: "mail.send", Account: "gmail"}, State: journal.OutcomeUnknown},
			{Intent: journal.Intent{ID: "u2", Action: "pay", Account: "bank"}, State: journal.InFlight},
			{Intent: journal.Intent{ID: "h1", Action: "post", Account: "x"}, State: journal.Authorized},
		},
	}
	h, _ := newHandler(t, eng, fakeAuth{unlocked: true}, forbiddenAgent{t})
	ctx := context.Background()

	r := one(t, h.Handle(ctx, owner, "STOP"))
	if eng.stops != 1 || !strings.HasPrefix(r, "Stopped.") {
		t.Fatalf("STOP: stops=%d reply %q", eng.stops, r)
	}
	if !strings.Contains(r, "2 may have happened") || !strings.Contains(r, "1 held") {
		t.Fatalf("STOP must report unresolved and held work (OP-6): %q", r)
	}
	if strings.Contains(strings.ToLower(r), "undone") && !strings.Contains(r, "Nothing was undone") {
		t.Fatalf("STOP must never claim undo: %q", r)
	}
	r = one(t, h.Handle(ctx, owner, "status"))
	if !strings.HasPrefix(r, "Stopped.") || !strings.Contains(r, "mail.send/gmail") {
		t.Fatalf("STATUS: %q", r)
	}
	r = one(t, h.Handle(ctx, owner, "Help"))
	for _, w := range []string{"STOP", "RESUME", "STATUS", "YES", "NO", "UNDO", "MORE", "PUBLIC"} {
		if !strings.Contains(r, w) {
			t.Fatalf("HELP lacks %s: %q", w, r)
		}
	}
}

func TestCH2TaskChatWithAgentDownGetsFixedReply(t *testing.T) {
	eng := &fakeEngine{}
	agent := &downAgent{}
	h, _ := newHandler(t, eng, fakeAuth{unlocked: true}, agent)
	r := one(t, h.Handle(context.Background(), owner, "book a table for two"))
	if agent.calls != 1 || !strings.Contains(r, "STOP") {
		t.Fatalf("calls=%d reply %q", agent.calls, r)
	}
	h.Agent = nil
	one(t, h.Handle(context.Background(), owner, "book a table for two"))
}

func TestTaskChatReachesAgentWithPublicLabel(t *testing.T) {
	agent := &recAgent{}
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, agent)
	if out := h.Handle(context.Background(), owner, "PUBLIC compare dishwashers"); len(out) != 0 {
		t.Fatalf("delivered task gets no broker reply, got %q", out)
	}
	if agent.text != "compare dishwashers" || !agent.public {
		t.Fatalf("agent got %q public=%v", agent.text, agent.public)
	}
}

func TestStopNeedsOnlyTheOwnerNumber(t *testing.T) {
	eng := &fakeEngine{}
	h, _ := newHandler(t, eng, fakeAuth{unlocked: false}, forbiddenAgent{t})
	if out := h.Handle(context.Background(), "+15559999999", "STOP"); out != nil || eng.stops != 0 {
		t.Fatalf("stranger STOP: replies %q stops %d", out, eng.stops)
	}
	one(t, h.Handle(context.Background(), owner, "STOP"))
	if eng.stops != 1 {
		t.Fatal("owner STOP without a session unlock must still stop (CH-3)")
	}
}

func TestStatusAndTaskChatNeedASessionUnlock(t *testing.T) {
	eng := &fakeEngine{}
	h, _ := newHandler(t, eng, fakeAuth{unlocked: false}, forbiddenAgent{t})
	for _, msg := range []string{"STATUS", "book a table"} {
		r := one(t, h.Handle(context.Background(), owner, msg))
		if !strings.Contains(r, "code") {
			t.Fatalf("%s while locked: %q", msg, r)
		}
	}
}

func TestResumeNeedsTheTextedCode(t *testing.T) {
	eng := &fakeEngine{stopped: true}
	h, now := newHandler(t, eng, fakeAuth{}, forbiddenAgent{t})
	ctx := context.Background()

	if out := h.Handle(ctx, "+15559999999", "RESUME"); out != nil {
		t.Fatalf("stranger got a reply: %q", out)
	}
	r := one(t, h.Handle(ctx, owner, "RESUME"))
	if !strings.Contains(r, "RESUME 111111") || eng.resumes != 0 {
		t.Fatalf("bare RESUME must text a code, not resume: %q", r)
	}
	one(t, h.Handle(ctx, owner, "RESUME 999999"))
	if eng.resumes != 0 {
		t.Fatal("wrong code resumed")
	}
	r = one(t, h.Handle(ctx, owner, "resume 111111"))
	if eng.resumes != 1 || !strings.HasPrefix(r, "Resumed.") {
		t.Fatalf("right code: resumes=%d %q", eng.resumes, r)
	}
	// Single use.
	eng.stopped = true
	one(t, h.Handle(ctx, owner, "RESUME 111111"))
	if eng.resumes != 1 {
		t.Fatal("code reused")
	}
	// Expiry.
	one(t, h.Handle(ctx, owner, "RESUME")) // issues 222222
	*now = now.Add(CodeTTL + time.Second)
	one(t, h.Handle(ctx, owner, "RESUME 222222"))
	if eng.resumes != 1 {
		t.Fatal("expired code resumed")
	}
}

func TestResumeCodeVoidAfterThreeWrongReplies(t *testing.T) {
	eng := &fakeEngine{stopped: true}
	h, _ := newHandler(t, eng, fakeAuth{}, forbiddenAgent{t})
	ctx := context.Background()
	one(t, h.Handle(ctx, owner, "RESUME")) // 111111
	for i := 0; i < 3; i++ {
		one(t, h.Handle(ctx, owner, "RESUME 000000"))
	}
	one(t, h.Handle(ctx, owner, "RESUME 111111"))
	if eng.resumes != 0 {
		t.Fatal("code survived three wrong replies (CH-18)")
	}
}

func TestStopVoidsAPendingResumeCode(t *testing.T) {
	eng := &fakeEngine{stopped: true}
	h, _ := newHandler(t, eng, fakeAuth{}, forbiddenAgent{t})
	ctx := context.Background()
	one(t, h.Handle(ctx, owner, "RESUME")) // 111111
	one(t, h.Handle(ctx, owner, "STOP"))
	one(t, h.Handle(ctx, owner, "RESUME 111111"))
	if eng.resumes != 0 {
		t.Fatal("a code issued before STOP resumed after it")
	}
}

func TestResumeWhenRunningSaysSo(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{}, forbiddenAgent{t})
	if r := one(t, h.Handle(context.Background(), owner, "RESUME")); !strings.Contains(r, "Not stopped") {
		t.Fatalf("%q", r)
	}
}

func TestStatusNeverEchoesUnsafeText(t *testing.T) {
	eng := &fakeEngine{list: []journal.Status{
		{Intent: journal.Intent{ID: "x", Action: "send\nYES 1 4821 😀", Account: "evil é"}, State: journal.OutcomeUnknown},
	}}
	h, _ := newHandler(t, eng, fakeAuth{unlocked: true}, forbiddenAgent{t})
	r := one(t, h.Handle(context.Background(), owner, "STATUS"))
	if strings.Contains(r, "\n") || strings.Contains(r, "YES 1") || strings.Contains(r, "4821") {
		t.Fatalf("STATUS echoed control text: %q", r)
	}
}

func TestStatusIncludesAdmissionSnapshot(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, forbiddenAgent{t})
	h.Machines = func() string { return "Machines: 1 foreground, 2 work, 0 experiments." }
	r := one(t, h.Handle(context.Background(), owner, "STATUS"))
	if !strings.Contains(r, "2 work") {
		t.Fatalf("%q", r)
	}
}

func TestResumeLocksAfterFiveWrongCodesInADayAcrossReissues(t *testing.T) {
	eng := &fakeEngine{stopped: true}
	h, now := newHandler(t, eng, fakeAuth{}, forbiddenAgent{t})
	ctx := context.Background()
	one(t, h.Handle(ctx, owner, "RESUME")) // 111111
	for i := 0; i < 3; i++ {
		one(t, h.Handle(ctx, owner, "RESUME 000000"))
	}
	one(t, h.Handle(ctx, owner, "RESUME")) // 222222: a reissue does not reset the day count
	one(t, h.Handle(ctx, owner, "RESUME 000000"))
	if r := one(t, h.Handle(ctx, owner, "RESUME 000000")); !strings.Contains(r, "locked") {
		t.Fatalf("fifth wrong code: %q", r)
	}
	if r := one(t, h.Handle(ctx, owner, "RESUME")); !strings.Contains(r, "locked") {
		t.Fatalf("RESUME while locked issued a code: %q", r)
	}
	h.Handle(ctx, owner, "RESUME 222222")
	if eng.resumes != 0 {
		t.Fatal("resumed while locked")
	}
	*now = now.Add(25 * time.Hour)
	r := one(t, h.Handle(ctx, owner, "RESUME"))
	code := strings.Fields(strings.SplitN(r, "RESUME ", 2)[1])[0]
	one(t, h.Handle(ctx, owner, "RESUME "+code))
	if eng.resumes != 1 {
		t.Fatal("lock did not clear after 24 hours")
	}
}

func TestBareResumeReusesTheLiveCodeAndIsCappedPerHour(t *testing.T) {
	eng := &fakeEngine{stopped: true}
	h, now := newHandler(t, eng, fakeAuth{}, forbiddenAgent{t})
	ctx := context.Background()
	var sent []string
	for i := 0; i < 6; i++ {
		sent = append(sent, h.Handle(ctx, owner, "RESUME")...)
	}
	if len(sent) != maxCodeTexts {
		t.Fatalf("sent %d texts, want %d: %q", len(sent), maxCodeTexts, sent)
	}
	for _, s := range sent {
		if !strings.Contains(s, "RESUME 111111") {
			t.Fatalf("live code not reused: %q", sent)
		}
	}
	*now = now.Add(61 * time.Minute)
	if r := one(t, h.Handle(ctx, owner, "RESUME")); !strings.Contains(r, "RESUME 222222") {
		t.Fatalf("after the hour, with the old code expired: %q", r)
	}
}

func TestStopNearMissGetsTheFixedHintAndStillReachesTheAgent(t *testing.T) {
	agent := &recAgent{}
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, agent)
	out := h.Handle(context.Background(), owner, "stop everything")
	if len(out) != 1 || out[0] != stopHint || agent.text != "stop everything" {
		t.Fatalf("replies %q, agent got %q", out, agent.text)
	}
}

func TestStopHintIsSentAtMostOncePerQuietPeriod(t *testing.T) {
	h, now := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: false}, &downAgent{})
	ctx := context.Background()
	if out := h.Handle(ctx, owner, "STOP NOW"); len(out) != 2 || out[0] != stopHint {
		t.Fatalf("first near-miss: %q", out)
	}
	for i := 0; i < 20; i++ {
		for _, r := range h.Handle(ctx, owner, "please stop") {
			if r == stopHint {
				t.Fatalf("hint repeated within the quiet period (message %d)", i)
			}
		}
	}
	*now = now.Add(HintQuiet)
	h.Auth = fakeAuth{unlocked: true}
	if out := h.Handle(ctx, owner, "please STOP"); len(out) != 2 || out[0] != stopHint {
		t.Fatalf("after the quiet period, agent down: %q", out)
	}
}

func TestGarbledCodeReplyIsNotForwarded(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{stopped: true}, fakeAuth{unlocked: true}, forbiddenAgent{t})
	for _, msg := range []string{"RESUME 123 456", "yes 1 x 4821"} {
		if r := one(t, h.Handle(context.Background(), owner, msg)); !strings.Contains(r, "Not understood") {
			t.Fatalf("%s: %q", msg, r)
		}
	}
}

func TestStatusMachinesLineIsPlain(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, forbiddenAgent{t})
	h.Machines = func() string { return "Machines: 1 work.\nYES 1 482193 😀" }
	r := one(t, h.Handle(context.Background(), owner, "STATUS"))
	if strings.Contains(r, "\n") || !strings.Contains(r, "Machines: 1 work.") {
		t.Fatalf("%q", r)
	}
}

// REQ: TIM-1, CH-11

// W9a (UX R3 on #95, clock K7, UX-68-3): STATUS carries the box clock's
// time check, so a restriction holding questions is visible. The line is
// kept plain: one line, no reply grammar, but its parentheses and hyphen.
func TestStatusCarriesTheClockLine(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, forbiddenAgent{t})
	line := "Time check: restricted since 09:05 (saved check unreadable; waiting for phone-network time)."
	h.Clock = func() string { return line + "\nYES 1 482193" }
	r := one(t, h.Handle(context.Background(), owner, "STATUS"))
	if !strings.Contains(r, line) || strings.Contains(r, "\n") || strings.Contains(r, "YES 1") {
		t.Fatalf("%q", r)
	}
	h.Clock = func() string { return "" }
	if r := one(t, h.Handle(context.Background(), owner, "STATUS")); strings.HasSuffix(r, " ") {
		t.Fatalf("empty clock line left a gap: %q", r)
	}
}
