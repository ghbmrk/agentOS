package question

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// REQ: CAP-10, CH-15, REV-5

// rig is a question book on a fake clock and a fake owner channel.
type rig struct {
	t          *testing.T
	mu         sync.Mutex
	clock      time.Time
	mono       time.Duration // the monotonic clock; advance moves it with clock
	restricted bool
	quiet      bool
	approvals  bool // an approval request is open on the channel
	sendErr    error
	sent       []string
	raised     []string
	raiseErr   error
	cfg        Config
	b          *Book
}

func newRig(t *testing.T, edit func(*Config)) *rig {
	r := &rig{t: t, clock: time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)}
	r.cfg = Config{
		Send: func(text string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.sendErr != nil {
				return r.sendErr
			}
			r.sent = append(r.sent, text)
			return nil
		},
		Now: func(context.Context) (time.Time, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.restricted {
				return time.Time{}, errors.New("clock: restricted")
			}
			return r.clock, nil
		},
		Reveal: func(machine string) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.raiseErr != nil {
				return r.raiseErr
			}
			r.raised = append(r.raised, machine)
			return nil
		},
		Quiet: func(time.Time) bool {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.quiet
		},
		ApprovalsOpen: func() bool {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.approvals
		},
		Mono: func() time.Duration {
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.mono
		},
		Location: time.UTC,
	}
	if edit != nil {
		edit(&r.cfg)
	}
	r.open()
	return r
}

func (r *rig) open() {
	r.t.Helper()
	b, err := New(r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	r.b = b
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	r.clock = r.clock.Add(d)
	r.mono += d
	r.mu.Unlock()
}

func (r *rig) set(f func()) {
	r.mu.Lock()
	f()
	r.mu.Unlock()
}

func (r *rig) texts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sent...)
}

func (r *rig) ask(asker, req string, s Spec) Status {
	r.t.Helper()
	st, err := r.b.Ask(context.Background(), asker, req, s)
	if err != nil {
		r.t.Fatalf("ask %s/%s: %v", asker, req, err)
	}
	return st
}

func (r *rig) status(asker, req string) Status {
	r.t.Helper()
	st, err := r.b.Status(context.Background(), asker, req, "m1")
	if err != nil {
		r.t.Fatalf("status %s/%s: %v", asker, req, err)
	}
	return st
}

func (r *rig) answer(text string) (string, bool) {
	return r.b.Answer(context.Background(), text)
}

func slot() Spec {
	return Spec{Text: "Book the 9:00 or the 9:30 dentist slot?", Default: "9:30", Wait: 30 * time.Minute}
}

// TestQuestionIsTextedWithItsDefaultAndDeadline: the broker renders the
// question with its ID, the default, and the deadline it computed.
func TestQuestionIsTextedWithItsDefaultAndDeadline(t *testing.T) {
	r := newRig(t, nil)
	st := r.ask("lin1", "q1", slot())
	if st.State != Waiting || st.ID != "Q100" || !st.Deadline.Equal(r.clock.Add(30*time.Minute)) {
		t.Fatalf("status %+v", st)
	}
	got := r.texts()
	if len(got) != 1 {
		t.Fatalf("texts %q", got)
	}
	for _, want := range []string{"Q100", "Book the 9:00 or the 9:30 dentist slot?", `"9:30"`, "13:30", "Reply Q100 and"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("text %q lacks %q", got[0], want)
		}
	}
	// A retry with the same request ID is the same question, texted once.
	if again := r.ask("lin1", "q1", slot()); again.ID != "Q100" || len(r.texts()) != 1 {
		t.Fatalf("retry %+v, texts %d", again, len(r.texts()))
	}
	// The same request ID with other content is refused, not a new question.
	other := slot()
	other.Default = "9:00"
	if _, err := r.b.Ask(context.Background(), "lin1", "q1", other); err == nil {
		t.Fatal("a reused request ID with a different question was accepted")
	}
	// Another lineage's request ID is its own namespace.
	if st := r.ask("lin2", "q1", slot()); st.ID == "Q100" {
		t.Fatal("two lineages share a question")
	}
}

// TestOwnerReplyIsMatchedBack: a tagged reply answers that question; the
// guest reads the answer only after its machine's label has risen.
func TestOwnerReplyIsMatchedBack(t *testing.T) {
	r := newRig(t, nil)
	r.ask("lin1", "a", slot())
	r.ask("lin1", "b", Spec{Text: "Order more coffee?", Default: "no", Wait: time.Hour})
	if _, ok := r.answer("sounds good"); ok {
		t.Fatal("an untagged text was taken as an answer")
	}
	if _, ok := r.answer("Q909 yes"); ok {
		t.Fatal("a reply to no open question was taken")
	}
	reply, ok := r.answer("q101: yes, two bags")
	if !ok || !strings.Contains(reply, "Q101") {
		t.Fatalf("reply %q %v", reply, ok)
	}
	st := r.status("lin1", "b")
	if st.State != Answered || st.Answer != "yes, two bags" || !st.FromOwner {
		t.Fatalf("status %+v", st)
	}
	if len(r.raised) != 1 || r.raised[0] != "m1" {
		t.Fatalf("label not raised before the owner's answer was read: %v", r.raised)
	}
	if st := r.status("lin1", "a"); st.State != Waiting || st.Answer != "" {
		t.Fatalf("other question %+v", st)
	}
	// An answer is final: a second reply is told so and changes nothing.
	reply, ok = r.answer("Q101 no")
	if !ok || r.status("lin1", "b").Answer != "yes, two bags" || !strings.Contains(reply, "already") {
		t.Fatalf("second answer %q %v", reply, ok)
	}
	// Another lineage cannot read it.
	if _, err := r.b.Status(context.Background(), "lin2", "b", "m2"); err == nil {
		t.Fatal("another lineage read the question")
	}
	// A failed raise reveals nothing (REV-5).
	r.set(func() { r.raiseErr = errors.New("vm busy") })
	if _, err := r.b.Status(context.Background(), "lin1", "b", "m1"); err == nil {
		t.Fatal("answer returned although the label could not rise")
	}
}

// TestChoicesBoundTheAnswer: with choices, an answer must be one of them
// (by text or number) and the default must be one.
func TestChoicesBoundTheAnswer(t *testing.T) {
	r := newRig(t, nil)
	s := Spec{Text: "Which slot?", Choices: []string{"9:00", "9:30"}, Default: "9:45", Wait: time.Hour}
	if _, err := r.b.Ask(context.Background(), "lin1", "c", s); err == nil {
		t.Fatal("a default outside the choices was accepted")
	}
	s.Default = "9:30"
	r.ask("lin1", "c", s)
	if !strings.Contains(r.texts()[0], "1) 9:00") {
		t.Fatalf("choices not rendered: %q", r.texts()[0])
	}
	if reply, ok := r.answer("Q100 10:00"); !ok || !strings.Contains(reply, "9:00") || r.status("lin1", "c").State != Waiting {
		t.Fatalf("off-list answer %q %v", reply, ok)
	}
	r.answer("Q100 1")
	if st := r.status("lin1", "c"); st.State != Answered || st.Answer != "9:00" {
		t.Fatalf("numbered answer %+v", st)
	}
}

// TestUntaggedChoiceAnswersTheOnlyQuestion: with one question open, an
// untagged reply that is exactly one of its choices answers it (UX R2);
// with two open, or a reply that is not a choice, it stays chat.
func TestUntaggedChoiceAnswersTheOnlyQuestion(t *testing.T) {
	r := newRig(t, nil)
	s := Spec{Text: "Which slot?", Choices: []string{"9:00", "9:30"}, Default: "9:30", Wait: time.Hour}
	r.ask("lin1", "a", s)
	if _, ok := r.answer("sure, 9:00 works"); ok {
		t.Fatal("chat taken as an answer")
	}
	if _, ok := r.answer("1"); ok {
		t.Fatal("an untagged number taken as an answer")
	}
	// A choice the channel would take when sent alone is refused.
	for _, c := range []string{"run", "No", "stop.", "RESUME", "yes,", "(run)", "*run*", "yes, please"} {
		if _, err := r.b.Ask(context.Background(), "lin1", "cw", Spec{Text: "Proceed?", Choices: []string{c, "wait"}, Default: "wait", Wait: time.Hour}); err == nil {
			t.Errorf("choice %q accepted", c)
		}
	}
	r.ask("lin1", "b", s)
	if _, ok := r.answer("9:00"); ok {
		t.Fatal("untagged reply taken with two questions open")
	}
	r.answer("Q101 9:30")
	// Not while an approval request is open: a bare reply may be for it.
	r.set(func() { r.approvals = true })
	if _, ok := r.answer("9:00"); ok {
		t.Fatal("untagged reply taken while an approval request is open")
	}
	r.set(func() { r.approvals = false })
	if reply, ok := r.answer("9:00"); !ok || !strings.Contains(reply, "Q100") {
		t.Fatalf("reply %q %v", reply, ok)
	}
	if st := r.status("lin1", "a"); st.State != Answered || st.Answer != "9:00" {
		t.Fatalf("status %+v", st)
	}
}

// TestNoReplyByTheDeadlineTakesTheDefault: the broker's timer lapses the
// question, the guest proceeds on the default, and the digest lists it.
func TestNoReplyByTheDeadlineTakesTheDefault(t *testing.T) {
	r := newRig(t, nil)
	r.ask("lin1", "q", slot())
	r.advance(29 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "q"); st.State != Waiting {
		t.Fatalf("lapsed early: %+v", st)
	}
	r.advance(time.Minute)
	r.b.Tick(context.Background())
	st := r.status("lin1", "q")
	if st.State != Defaulted || st.Answer != "9:30" || st.FromOwner {
		t.Fatalf("status %+v", st)
	}
	if len(r.raised) != 0 {
		t.Fatal("a default (agent text) raised the label")
	}
	d := r.b.TakeDigest()
	if len(d) != 1 || !strings.Contains(d[0], "Q100") || !strings.Contains(d[0], `"9:30"`) || !strings.Contains(d[0], "no reply") {
		t.Fatalf("digest %q", d)
	}
	if d := r.b.TakeDigest(); len(d) != 0 {
		t.Fatalf("digest repeated: %q", d)
	}
	// A late reply is told the default stands and is passed on as late.
	reply, ok := r.answer("Q100 9:00 please")
	if !ok || !strings.Contains(reply, "Too late for Q100") {
		t.Fatalf("late reply %q %v", reply, ok)
	}
	if st := r.status("lin1", "q"); st.State != Defaulted || st.Late != "9:00 please" {
		t.Fatalf("late %+v", st)
	}
}

// TestTheGuestCannotLapseAQuestion: nothing the asker does closes a
// question; only the broker's timer or the owner does.
func TestTheGuestCannotLapseAQuestion(t *testing.T) {
	r := newRig(t, nil)
	r.ask("lin1", "q", slot())
	for i := 0; i < 5; i++ {
		r.ask("lin1", "q", slot())
		r.status("lin1", "q")
	}
	if _, err := r.b.Call(context.Background(), "lin1", "m1", ToolStatus, []byte(`{"request_id":"q","state":"defaulted"}`)); err != nil {
		t.Fatal(err)
	}
	if st := r.status("lin1", "q"); st.State != Waiting {
		t.Fatalf("guest calls moved the question: %+v", st)
	}
}

// TestBrokerBoundsDefaultAndDeadline: the wait is clamped, a default is
// required, text is bounded and single-line, and open questions are capped.
func TestBrokerBoundsDefaultAndDeadline(t *testing.T) {
	r := newRig(t, nil)
	if st := r.ask("lin1", "short", Spec{Text: "Now?", Default: "yes", Wait: time.Second}); !st.Deadline.Equal(r.clock.Add(DefaultMinWait)) {
		t.Fatalf("short wait not raised: %v", st.Deadline.Sub(r.clock))
	}
	if st := r.ask("lin1", "long", Spec{Text: "Later?", Default: "yes", Wait: 30 * 24 * time.Hour}); !st.Deadline.Equal(r.clock.Add(DefaultMaxWait)) {
		t.Fatalf("long wait not cut: %v", st.Deadline.Sub(r.clock))
	}
	bad := []Spec{
		{Text: "No default?", Wait: time.Hour},
		{Text: "No wait?", Default: "x"},
		{Text: "", Default: "x", Wait: time.Hour},
		{Text: strings.Repeat("a", MaxText+1), Default: "x", Wait: time.Hour},
		{Text: "Long default?", Default: strings.Repeat("d", MaxDefault+1), Wait: time.Hour},
		{Text: "Many?", Default: "a", Choices: []string{"a", "b", "c", "d", "e"}, Wait: time.Hour},
		// Nothing that reads as a code or as a reply for the owner to copy.
		{Text: "Reply YES A4 to go on?", Default: "x", Wait: time.Hour},
		{Text: "Send RESUME 482913?", Default: "x", Wait: time.Hour},
		{Text: "Is it 482 913?", Default: "x", Wait: time.Hour},
		{Text: "Is it ４８２９１３?", Default: "x", Wait: time.Hour},
		{Text: "Which?", Default: "undo b12", Wait: time.Hour},
		// Rendered past one owner text (control.MaxText less the agent prefix).
		{Text: strings.Repeat("q", MaxText), Default: strings.Repeat("a", MaxChoice),
			Choices: []string{strings.Repeat("a", MaxChoice), strings.Repeat("b", MaxChoice), strings.Repeat("c", MaxChoice), strings.Repeat("d", MaxChoice)}, Wait: time.Hour},
	}
	for i, s := range bad {
		if _, err := r.b.Ask(context.Background(), "lin1", fmt.Sprintf("bad%d", i), s); err == nil {
			t.Errorf("spec %d accepted: %+v", i, s)
		}
	}
	if _, err := r.b.Ask(context.Background(), "lin1", "toolong", bad[len(bad)-1]); err == nil || !strings.Contains(err.Error(), "too long for one text") {
		t.Errorf("long render: %v", err)
	}
	// Newlines and control characters are flattened, so a question cannot
	// lay out a fake broker template.
	r.ask("lin1", "nl", Spec{Text: "Line one\nLine two\u2028three\x07", Default: "ok", Wait: time.Hour})
	last := r.texts()[len(r.texts())-1]
	if strings.ContainsAny(last, "\n\x07") {
		t.Fatalf("control characters reached the owner: %q", last)
	}
	// Per asker cap: the third open question above is the cap.
	if _, err := r.b.Ask(context.Background(), "lin1", "over", Spec{Text: "One more?", Default: "no", Wait: time.Hour}); !errors.Is(err, ErrTooMany) {
		t.Fatalf("over cap: %v", err)
	}
}

// TestPacingHoldsQuestionsAndTheDeadlineStartsAtSend: questions past the
// hourly text budget, in quiet hours, or when the text fails are held; the
// deadline starts when the owner is actually texted (CH-15).
func TestPacingHoldsQuestionsAndTheDeadlineStartsAtSend(t *testing.T) {
	r := newRig(t, func(c *Config) { c.SendsPerHour = 1; c.PerAsker = 5 })
	r.ask("lin1", "a", slot())
	st := r.ask("lin1", "b", slot())
	if st.State != Held || !st.Deadline.IsZero() || len(r.texts()) != 1 {
		t.Fatalf("over pace: %+v, texts %d", st, len(r.texts()))
	}
	r.advance(2 * time.Hour) // a lapses meanwhile; b was never seen
	r.b.Tick(context.Background())
	if st := r.status("lin1", "b"); st.State != Waiting || !st.Deadline.Equal(r.clock.Add(30*time.Minute)) {
		t.Fatalf("held question after the hour: %+v", st)
	}

	r.set(func() { r.quiet = true })
	if st := r.ask("lin1", "c", slot()); st.State != Held {
		t.Fatalf("quiet hours: %+v", st)
	}
	r.advance(10 * time.Hour)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "c"); st.State != Held {
		t.Fatalf("a held question lapsed or was sent in quiet hours: %+v", st)
	}
	r.set(func() { r.quiet = false; r.sendErr = errors.New("no modem") })
	r.b.Tick(context.Background())
	if st := r.status("lin1", "c"); st.State != Held {
		t.Fatalf("a failed text started the deadline: %+v", st)
	}
	r.set(func() { r.sendErr = nil })
	r.b.Tick(context.Background())
	if st := r.status("lin1", "c"); st.State != Waiting {
		t.Fatalf("not sent after the modem came back: %+v", st)
	}
}

// TestARestrictedClockKeepsTheWaitAndHoldsNewTexts: while the clock guard
// says time cannot be trusted, a texted question keeps waiting and lapses
// only when its wait runs out (PQ4), and with quiet hours configured
// nothing new is sent (TIM-1).
func TestARestrictedClockKeepsTheWaitAndHoldsNewTexts(t *testing.T) {
	r := newRig(t, nil)
	r.ask("lin1", "q", slot())
	r.set(func() { r.restricted = true })
	r.advance(20 * time.Minute)
	r.b.Tick(context.Background())
	st := r.status("lin1", "q")
	if st.State != Waiting || st.Answer != "" {
		t.Fatalf("restricted clock: %+v", st)
	}
	if !strings.Contains(st.Reason, "clock") {
		t.Fatalf("reason %q", st.Reason)
	}
	if st := r.ask("lin1", "new", slot()); st.State != Held || len(r.texts()) != 1 {
		t.Fatalf("asked while restricted: %+v, texts %d", st, len(r.texts()))
	}
	// The owner can still answer: an answer needs no clock.
	if _, ok := r.answer("Q100 9:00"); !ok {
		t.Fatal("answer refused while the clock is restricted")
	}
	r.set(func() { r.restricted = false })
	r.b.Tick(context.Background())
	if st := r.status("lin1", "q"); st.State != Answered || st.Answer != "9:00" {
		t.Fatalf("after recovery: %+v", st)
	}
	if st := r.status("lin1", "new"); st.State != Waiting {
		t.Fatalf("held question not sent after recovery: %+v", st)
	}
}

// REQ: CAP-10, TIM-1
//
// W9a PQ4 (#95 gate): a texted question's wait runs on the monotonic
// clock while the wall clock is restricted, so a restriction never
// stretches the deadline the owner was given; the lapse is dated at that
// deadline. A held question still waits, and a restart forgets the
// monotonic reading, so a question loaded from disk waits for trusted time.
func TestARestrictedClockDoesNotStretchTheWait(t *testing.T) {
	path := filepath.Join(t.TempDir(), "questions.json")
	r := newRig(t, func(c *Config) { c.Path = path })
	r.ask("lin1", "q", slot())
	r.set(func() { r.restricted = true })
	r.ask("lin2", "held", slot()) // asked while restricted: never texted
	r.advance(29 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "q"); st.State != Waiting {
		t.Fatalf("lapsed early: %+v", st)
	}
	r.advance(time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "q"); st.State != Defaulted || st.Answer != "9:30" {
		t.Fatalf("not lapsed on the monotonic clock: %+v", st)
	}
	if d := strings.Join(r.b.TakeDigest(), "\n"); !strings.Contains(d, "no reply by 13:30") {
		t.Fatalf("digest %q", d)
	}
	if st := r.status("lin2", "held"); st.State != Held || !strings.Contains(st.Reason, "clock") {
		t.Fatalf("a held question: %+v", st)
	}
	if out, _ := r.answer("Q100 9:00"); !strings.HasPrefix(out, "Too late for Q100") {
		t.Fatalf("answer after the lapse: %q", out)
	}

	// An answer that arrives before the tick still finds the wait over.
	r.set(func() { r.restricted = false })
	r.ask("lin3", "a", slot())
	r.set(func() { r.restricted = true })
	r.advance(31 * time.Minute)
	if out, _ := r.answer("Q102 9:00"); !strings.HasPrefix(out, "Too late for Q102") {
		t.Fatalf("answer past the wait: %q", out)
	}

	// After a restart the reading is gone: wait for trusted time.
	r.set(func() { r.restricted = false })
	r.ask("lin3", "b", slot())
	r.set(func() { r.restricted = true })
	r.open()
	r.advance(time.Hour)
	r.b.Tick(context.Background())
	if st := r.status("lin3", "b"); st.State != Held {
		t.Fatalf("loaded question lapsed on a restricted clock: %+v", st)
	}
	// One texted after the restart counts again.
	r.set(func() { r.restricted = false })
	r.b.Tick(context.Background())
	r.ask("lin4", "c", slot())
	r.set(func() { r.restricted = true })
	r.advance(30 * time.Minute)
	r.b.Tick(context.Background())
	if st := r.status("lin4", "c"); st.State != Defaulted {
		t.Fatalf("texted after the restart: %+v", st)
	}
}

// TestAnswersCannotCarryCodes: a six-digit token in an answer is refused,
// so a question cannot phish an approval code for the guest.
func TestAnswersCannotCarryCodes(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Hidden = func(s string) bool { return strings.Contains(s, "sk-") } })
	r.ask("lin1", "q", Spec{Text: "What did the bank say?", Default: "none", Wait: time.Hour})
	key := "ABCD7-EFGH2-JKLM3-NPQR4-STUV5-WXYZ6-2345A-6789B"
	for _, a := range []string{"Q100 482913", "Q100 it is 482 913", "Q100 4-8-2-9-1-3", "Q100 ４８２９１３", "Q100 48291377",
		// A recovery key, whole, undashed, lowercase, or half of it (C1).
		"Q100 " + key, "Q100 " + strings.ReplaceAll(key, "-", ""), "Q100 " + strings.ToLower(strings.ReplaceAll(key, "-", " ")),
		"Q100 the first part is " + key[:23],
		"Q100 " + strings.ReplaceAll(key, "-", "/"), "Q100 " + strings.ReplaceAll(key, "-", "_"), "Q100 ABCD7 EFGH2", "Q100 abcd7efgh2jklm3",
		// Digit groups joined by any short separator run.
		"Q100 482/913", "Q100 482:913", "Q100 482,913", "Q100 4,8,2,9,1,3",
		// Shapes next to or inside benign ones (L3 on 7c211be).
		"Q100 1:23 456", "Q100 482 9:13", "Q100 12:34:56", "Q100 09:30:12:34",
		"Q100 $482913", "Q100 $482,913.00", "Q100 48/29/13", "Q100 48.29.13", "Q100 48-29-13",
		"Q100 4829-13-57", "Q100 4,829.13", "Q100 1,482,913", "Q100 £1,250.00", "Q100 1,234,567",
		"Q100 2026/31", "Q100 4:28, 9:13", "Q100 10:00, 9:30", "Q100 482913 000", "Q100 482913 482913", "Q100 2026-1990", "Q100 4, 8, 2, 9, 1, 3", "Q100 482_913",
		// Whatever the channel would withhold as secret-shaped (C1).
		"Q100 sk-live-abc"} {
		reply, ok := r.answer(a)
		if !ok || !strings.Contains(reply, "only for the box") {
			t.Fatalf("%q: reply %q %v", a, reply, ok)
		}
	}
	if st := r.status("lin1", "q"); st.State != Waiting {
		t.Fatalf("a code-shaped answer was recorded: %+v", st)
	}
	// The owner sees the refusals as a guard hit in the digest (R1).
	if d := r.b.TakeDigest(); len(d) != 1 || !strings.Contains(d[0], "40 answers") {
		t.Fatalf("digest %q", d)
	}
	// A full phone number or an ordinary sentence is neither.
	for _, a := range []string{"Q100 call 555 010 0199", "Q100 maybe after lunch, about three or later",
		"Q100 great sweet happy dance", "Q100 between 9:30, 10:00",
		"Q100 05/10/2026", "Q100 12/31/2026", "Q100 the 2026/27 season", "Q100 2026-10-05 at 14:30", "Q100 9:30-10:00",
		"Q100 1250 pounds", "Q100 +44 7700 900123", "Q100 from 1990-2026", "Q100 9:30, 9:45, 10:00"} {
		if reply, _ := r.answer(a); strings.Contains(reply, "only for the box") {
			t.Fatalf("%q refused: %q", a, reply)
		}
	}
}

// TestQuestionsCannotNameCredentials: a question, default or choice that
// names a code, PIN, password, key or the Owner Card is refused (C2).
func TestQuestionsCannotNameCredentials(t *testing.T) {
	r := newRig(t, nil)
	for i, s := range []Spec{
		{Text: "What is the verification code?", Default: "none", Wait: time.Hour},
		{Text: "Can you read me grid cell B4?", Default: "no", Wait: time.Hour},
		{Text: "Which one?", Default: "my PIN", Wait: time.Hour},
		{Text: "Send the recovery words?", Default: "no", Wait: time.Hour},
		{Text: "Which?", Choices: []string{"OTP", "none"}, Default: "none", Wait: time.Hour},
		{Text: "Your 2FA app?", Default: "no", Wait: time.Hour},
		{Text: "Type your passphrase?", Default: "no", Wait: time.Hour},
		{Text: "What does the authenticator show?", Default: "no", Wait: time.Hour},
		{Text: "Where is the Owner Card?", Default: "no", Wait: time.Hour},
		{Text: "What is the seed?", Default: "no", Wait: time.Hour},
		{Text: "Change the password now?", Default: "no", Wait: time.Hour},
		{Text: "Your pass-word?", Default: "no", Wait: time.Hour},
		{Text: "Your P.I.N.?", Default: "no", Wait: time.Hour},
	} {
		if _, err := r.b.Ask(context.Background(), "lin1", fmt.Sprintf("c%d", i), s); err == nil {
			t.Errorf("spec %d accepted: %+v", i, s)
		}
	}
	if len(r.texts()) != 0 {
		t.Fatal("a credential question was texted")
	}
}

// TestQuestionsSurviveARestart: open questions, answers and pending
// digest lines are on disk; after a restart the deadline still holds, but
// a short grace lets replies queued at the carrier arrive first.
func TestQuestionsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "questions.json")
	r := newRig(t, func(c *Config) { c.Path = path })
	r.ask("lin1", "a", slot())
	r.ask("lin1", "b", Spec{Text: "Coffee?", Default: "no", Wait: time.Hour})
	r.answer("Q101 yes")
	r.advance(45 * time.Minute) // a's deadline passed while the broker was down
	r.open()
	r.b.Tick(context.Background())
	if st := r.status("lin1", "a"); st.State != Waiting {
		t.Fatalf("lapsed inside the restart grace: %+v", st)
	}
	if st := r.status("lin1", "b"); st.State != Answered || st.Answer != "yes" {
		t.Fatalf("answer lost: %+v", st)
	}
	r.advance(DefaultRestartGrace)
	r.b.Tick(context.Background())
	if st := r.status("lin1", "a"); st.State != Defaulted {
		t.Fatalf("not lapsed after the grace: %+v", st)
	}
	r.open()
	if d := r.b.TakeDigest(); len(d) != 1 {
		t.Fatalf("digest lost across restart: %q", d)
	}
	r.open()
	if d := r.b.TakeDigest(); len(d) != 0 {
		t.Fatalf("taken digest came back: %q", d)
	}
	// IDs do not restart at Q100 while Q100 and Q101 are still known.
	if st := r.ask("lin1", "c", slot()); st.ID == "Q100" || st.ID == "Q101" {
		t.Fatalf("reused ID %s", st.ID)
	}
}

// TestToolCalls: the broker tools a guest calls, with bounded arguments
// and fixed error strings.
func TestToolCalls(t *testing.T) {
	r := newRig(t, nil)
	if len(Tools) != 2 {
		t.Fatalf("tools %d", len(Tools))
	}
	out, err := r.b.Call(context.Background(), "lin1", "m1", ToolAsk,
		[]byte(`{"request_id":"q1","question":"Which slot?","choices":["9:00","9:30"],"default":"9:30","wait_minutes":30}`))
	if err != nil {
		t.Fatal(err)
	}
	if out.State != string(Waiting) || out.Question != "Q100" || out.Default != "9:30" || out.Deadline == "" {
		t.Fatalf("ask %+v", out)
	}
	r.answer("Q100 2")
	out, err = r.b.Call(context.Background(), "lin1", "m1", ToolStatus, []byte(`{"request_id":"q1"}`))
	if err != nil || out.State != string(Answered) || out.Answer != "9:30" || out.AnsweredBy != "owner" {
		t.Fatalf("status %+v %v", out, err)
	}
	for _, raw := range []string{`[]`, `{"request_id":"bad id!","question":"x","default":"y","wait_minutes":5}`, `{"request_id":"q101","question":"x","default":"y"}`} {
		if _, err := r.b.Call(context.Background(), "lin1", "m1", ToolAsk, []byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, err := r.b.Call(context.Background(), "lin1", "m1", "nope", nil); err == nil {
		t.Fatal("unknown tool")
	}
}

// TestAReplyAfterTheDeadlineIsLate: the deadline decides, not when the
// timer last ran; a reply after it is late even before the next tick.
func TestAReplyAfterTheDeadlineIsLate(t *testing.T) {
	r := newRig(t, nil)
	r.ask("lin1", "q", slot())
	r.advance(31 * time.Minute)
	if reply, ok := r.answer("Q100 9:00"); !ok || !strings.Contains(reply, "Too late for Q100") {
		t.Fatalf("reply %q %v", reply, ok)
	}
	if st := r.status("lin1", "q"); st.State != Defaulted || st.Answer != "9:30" || st.Late != "9:00" {
		t.Fatalf("status %+v", st)
	}
	if d := r.b.TakeDigest(); len(d) != 1 {
		t.Fatalf("digest %q", d)
	}
}

// TestTagsAreNeverApprovalIDs: tags are four characters (Q100-Q999), so
// none is an approval request ID (a letter and at most two digits); a
// short tag is not taken as an answer.
func TestTagsAreNeverApprovalIDs(t *testing.T) {
	r := newRig(t, func(c *Config) { c.PerAsker = 8 })
	for i := 0; i < 8; i++ {
		st := r.ask("lin1", fmt.Sprintf("q%d", i), slot())
		if !tagRE.MatchString(st.ID) || len(st.ID) != 4 {
			t.Fatalf("tag %q", st.ID)
		}
	}
	if _, ok := r.answer("Q1 yes"); ok {
		t.Fatal("a 2-character tag was taken")
	}
	b := &Book{next: firstTag + numTags - 1}
	if id := b.allocLocked(); id != "Q100" {
		t.Fatalf("wrap: %s", id)
	}
}

// TestAnswerInsideTheRestartGraceIsOnTime: right after a restart, a reply
// the carrier queued counts as an answer even though the deadline passed.
func TestAnswerInsideTheRestartGraceIsOnTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "questions.json")
	r := newRig(t, func(c *Config) { c.Path = path })
	r.ask("lin1", "a", slot())
	r.advance(45 * time.Minute)
	r.open()
	if reply, ok := r.answer("Q100 9:00"); !ok || !strings.Contains(reply, "Got it") {
		t.Fatalf("reply %q %v", reply, ok)
	}
	if st := r.status("lin1", "a"); st.State != Answered {
		t.Fatalf("status %+v", st)
	}
}

// TestHiddenQuestionIsRefused: a question the channel would withhold as
// secret-shaped is refused rather than left to default unseen.
func TestHiddenQuestionIsRefused(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Hidden = func(s string) bool { return strings.Contains(s, "password") } })
	if _, err := r.b.Ask(context.Background(), "lin1", "h", Spec{Text: "Is the password hunter2?", Default: "yes", Wait: time.Hour}); err == nil {
		t.Fatal("hidden question accepted")
	}
	if len(r.texts()) != 0 {
		t.Fatal("hidden question texted")
	}
}

// TestPacingIsFairAndSurvivesARestart: an asker texted in the last hour
// waits behind one that was not, and the hour's sends are on disk.
func TestPacingIsFairAndSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "questions.json")
	r := newRig(t, func(c *Config) { c.Path = path; c.SendsPerHour = 2 })
	r.ask("lin1", "a", slot())
	r.set(func() { r.quiet = true })
	r.ask("lin1", "b", slot())
	r.ask("lin2", "a", slot())
	r.set(func() { r.quiet = false })
	r.set(func() { r.quiet = true })
	r.ask("lin1", "c", slot())
	r.set(func() { r.quiet = false })
	r.b.Tick(context.Background())
	// lin2 leads the text; lin1's questions only share it (PQ1), so
	// lin1 takes no more of the budget.
	if got := r.texts(); len(got) != 2 || !strings.HasPrefix(got[1], "Q102: ") || !strings.Contains(got[1], " Q101: ") {
		t.Fatalf("texts %q", got)
	}
	if st, _ := r.b.Status(context.Background(), "lin2", "a", "m2"); st.State != Waiting {
		t.Fatalf("lin2 waited: %+v", st)
	}
	// The budget is spent; a restart does not reset it.
	r.set(func() { r.quiet = true })
	r.ask("lin2", "b", slot())
	r.set(func() { r.quiet = false })
	r.open()
	r.b.Tick(context.Background())
	if st := r.status("lin2", "b"); st.State != Held || len(r.texts()) != 2 {
		t.Fatalf("restart reset pacing: %+v, texts %d", st, len(r.texts()))
	}
}

// TestKeepNeverExhaustsTags: questions close only after a text, so
// keeping them under tags/SendsPerHour hours leaves a tag free.
func TestKeepNeverExhaustsTags(t *testing.T) {
	r := newRig(t, func(c *Config) { c.SendsPerHour = 60; c.Keep = 30 * 24 * time.Hour })
	// Closes in Keep plus the hour before it, plus every open question,
	// must leave a tag free (S1 on #117).
	if got := r.b.cfg.Keep; r.b.cfg.SendsPerHour*MaxPerText*(int(got/time.Hour)+1)+r.b.cfg.MaxOpen >= numTags {
		t.Fatalf("keep %v with %d sends an hour can hold every tag", got, r.b.cfg.SendsPerHour)
	}
}

// TestOneRefusedAnswerReadsSingular: the digest line counts correctly.
func TestOneRefusedAnswerReadsSingular(t *testing.T) {
	r := newRig(t, nil)
	r.ask("lin1", "q", slot())
	r.answer("Q100 482913")
	if d := r.b.TakeDigest(); len(d) != 1 || !strings.HasPrefix(d[0], "1 answer to") {
		t.Fatalf("digest %q", d)
	}
}

// A failed store must not hand the guest the path (os errors name it).
func TestAStoreFailureDoesNotNameThePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing", "questions.json")
	r := newRig(t, func(c *Config) { c.Path = path })
	_, err := r.b.Ask(context.Background(), "lin1", "q", slot())
	if err == nil || strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "missing") || strings.Contains(err.Error(), "/") {
		t.Fatalf("path leaked: %v", err)
	}
	if err.Error() != "the broker could not store that question; retry" {
		t.Fatalf("err %v", err)
	}
	if _, err := r.b.Status(context.Background(), "lin1", "q", "m1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a failed store kept the question: %v", err)
	}
}
