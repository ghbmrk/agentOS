package localsrv

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-7, CH-10, CH-11, CH-18, ARC-2

const good = "123456"

type fakeOwner struct {
	mu       sync.Mutex
	now      *time.Time
	locks    uint64
	stopped  bool
	signIns  int
	resumes  int
	left     int
	unlocked bool
	answers  []string
	answerFn func(id, sum string, approve bool, code string) (string, error)
	// relock, when set, locks and unlocks again just after each status
	// read, as the owner can between two reads.
	relock bool
}

func (f *fakeOwner) LocalStatus() owner.LocalStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := owner.LocalStatus{Stopped: f.stopped, Unlocked: f.unlocked, Locks: f.locks, LocalLeft: f.left}
	if f.left <= 0 {
		st.LocalReset = "14:05"
	}
	if f.relock {
		f.locks++
		f.unlocked = true
	}
	return st
}
func (f *fakeOwner) LocalGridCell() string { return "B4" }
func (f *fakeOwner) LocalSignIn(code string) (time.Time, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signIns++
	if code != good {
		return time.Time{}, 0, owner.ErrWrongCode
	}
	return f.now.Add(time.Hour), f.locks, nil
}
func (f *fakeOwner) LocalStop(context.Context) error {
	f.mu.Lock()
	f.stopped = true
	f.mu.Unlock()
	return nil
}
func (f *fakeOwner) LocalResume(locks uint64) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if locks != f.locks {
		return "", owner.ErrLocked
	}
	f.resumes++
	return "Resumed.", nil
}
func (f *fakeOwner) LocalRequests() []owner.LocalRequest {
	return []owner.LocalRequest{{ID: "K7", Sum: "s1"}}
}
func (f *fakeOwner) LocalWaiting() string        { return "1 waiting for you on my Wi-Fi page." }
func (f *fakeOwner) LocalStatusLines() string    { return "Running. 0 may have happened." }
func (f *fakeOwner) UnlockPeriod() time.Duration { return 7 * 24 * time.Hour }
func (f *fakeOwner) LocalAnswer(id, sum string, approve bool, code string) (string, error) {
	f.mu.Lock()
	f.answers = append(f.answers, id)
	fn := f.answerFn
	f.mu.Unlock()
	if fn != nil {
		return fn(id, sum, approve, code)
	}
	if approve && code != good {
		return "Wrong code. 2 tries left.", owner.ErrWrongCode
	}
	if approve {
		return "Approved K7. Your agent can go ahead.", nil
	}
	return "Denied K7.", nil
}

type rig struct {
	t       *testing.T
	now     time.Time
	own     *fakeOwner
	srv     *Server
	ops     map[string]sockets.Handler
	follows []string
	asks    []string
	forgets []string
	adopted []string
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	r.own = &fakeOwner{now: &r.now, left: 24}
	r.srv = New(Config{Owner: r.own, Line: func() localapi.Line { return testLine }, Now: func() time.Time { return r.now },
		DescribeRoot: func(_ context.Context, root []byte) (localapi.RootSummary, error) {
			if string(root) != "root" {
				return localapi.RootSummary{}, errors.New("bad root")
			}
			return localapi.RootSummary{Version: 1, Digest: digest}, nil
		},
		Follow: func(_ context.Context, name, d string) (string, error) {
			r.follows = append(r.follows, name+"@"+d)
			return "Asked: K8", nil
		},
		Paused: func() []localapi.PausedGrant {
			return []localapi.PausedGrant{{ID: "G2", What: "Read mail.", By: "Loop 2", Pause: "loop2/pause/G2/1"}}
		},
		AskResume: func(_ context.Context, grant, pause string) (string, error) {
			r.asks = append(r.asks, grant+"@"+pause)
			if pause != "loop2/pause/G2/1" {
				return "", errors.New("grants: /var/lib/x")
			}
			return "Asked.", nil
		},
		AdoptSIM: func(tag string) error {
			if tag != simTag {
				return ErrStaleSIM
			}
			r.adopted = append(r.adopted, tag)
			return nil
		},
		ForgetTasks: func(unlocked bool) localapi.ForgetTasks {
			if !unlocked {
				return localapi.ForgetTasks{Locked: true}
			}
			return localapi.ForgetTasks{Tasks: []localapi.ForgetTask{{ID: "owner:a", Date: "Mon 5 Oct 11:00", Label: `"pay the gas bill" (today 11:00)`}}}
		},
		Forget: func(_ context.Context, goal string, unlocked bool) string {
			if unlocked {
				goal += "@unlocked"
			}
			r.forgets = append(r.forgets, goal)
			return "Asked."
		}})
	r.ops = r.srv.Ops()
	return r
}

func (r *rig) call(op string, args any) (any, error) {
	r.t.Helper()
	b, err := json.Marshal(args)
	if err != nil {
		r.t.Fatal(err)
	}
	h := r.ops[op]
	if h == nil {
		r.t.Fatalf("no op %s", op)
	}
	return h(context.Background(), sockets.Peer{Kind: "localui"}, b)
}

func (r *rig) raw(op, args string) (any, error) {
	return r.ops[op](context.Background(), sockets.Peer{Kind: "localui"}, json.RawMessage(args))
}

func (r *rig) signIn() string {
	r.t.Helper()
	out, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: good})
	if err != nil {
		r.t.Fatal(err)
	}
	return out.(localapi.Session).Token
}

// refusal is a sign-in's refusal, as a code or in the Session.
func refusal(out any, err error) string {
	if ses, ok := out.(localapi.Session); ok && err == nil {
		return ses.Refusal
	}
	return code(err)
}

func code(err error) string {
	var c sockets.Code
	if errors.As(err, &c) {
		return string(c)
	}
	if err == nil {
		return ""
	}
	return "uncoded: " + err.Error()
}

// tokenOps are the ops that need a token, with args carrying tok.
func tokenOps(tok string) map[string]any {
	return map[string]any{
		localapi.OpSignOut:     localapi.Auth{Token: tok},
		localapi.OpSession:     localapi.Auth{Token: tok},
		localapi.OpLines:       localapi.Auth{Token: tok},
		localapi.OpLine:        localapi.Auth{Token: tok},
		localapi.OpResume:      localapi.Resume{Token: tok},
		localapi.OpRequests:    localapi.Auth{Token: tok},
		localapi.OpWaiting:     localapi.Auth{Token: tok},
		localapi.OpAnswer:      localapi.Answer{Token: tok, ID: "K7", Sum: "s1", Approve: false},
		localapi.OpFollowRoot:  localapi.FollowRoot{Token: tok, Root: []byte("root")},
		localapi.OpFollow:      localapi.Follow{Token: tok, Name: "Acme", Digest: digest},
		localapi.OpPaused:      localapi.Auth{Token: tok},
		localapi.OpAskResume:   localapi.AskResume{Token: tok, Grant: "G2", Pause: "loop2/pause/G2/1"},
		localapi.OpSIM:         localapi.AdoptSIM{Token: tok, SIM: simTag, Code: good},
		localapi.OpForgetTasks: localapi.Auth{Token: tok},
		localapi.OpForget:      localapi.Forget{Token: tok, ID: "owner:a"},
	}
}

// Security L1: without a token agentosd mints, every op but status, STOP,
// the grid cell and sign-in itself is refused, whatever the client sends.
func TestEveryOpButTheOpenOnesNeedsAToken(t *testing.T) {
	r := newRig(t)
	open := map[string]bool{localapi.OpStatus: true, localapi.OpStop: true, localapi.OpGridCell: true, localapi.OpSignIn: true}
	if len(r.ops) != len(localapi.Ops) {
		t.Fatalf("ops %d, contract lists %d", len(r.ops), len(localapi.Ops))
	}
	for _, op := range localapi.Ops {
		if open[op] {
			continue
		}
		args, ok := tokenOps("")[op]
		if !ok {
			t.Fatalf("op %s has no token case", op)
		}
		for _, tok := range []string{"", strings.Repeat("0", 2*localapi.TokenBytes), "made-up"} {
			args = tokenOps(tok)[op]
			if _, err := r.call(op, args); code(err) != localapi.ErrUnauthorized {
				t.Errorf("%s with token %q: %v, want unauthorized", op, tok, err)
			}
		}
		if _, err := r.raw(op, `{}`); code(err) != localapi.ErrUnauthorized {
			t.Errorf("%s with no args: %v", op, err)
		}
	}
	if len(r.own.answers) != 0 || len(r.follows) != 0 || len(r.adopted) != 0 || len(r.forgets) != 0 {
		t.Fatalf("reached the channel: %v %v %v %v", r.own.answers, r.follows, r.adopted, r.forgets)
	}
	for op := range open {
		var args any = struct{}{}
		if op == localapi.OpSignIn {
			args = localapi.SignIn{Code: good}
		}
		if _, err := r.call(op, args); err != nil {
			t.Errorf("%s: %v", op, err)
		}
	}
	if !r.own.stopped {
		t.Fatal("STOP without a token did not stop")
	}
}

func TestATokenOpensTheSignedInOps(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	for op, args := range tokenOps(tok) {
		if op == localapi.OpSignOut {
			continue
		}
		if _, err := r.call(op, args); err != nil {
			t.Errorf("%s: %v", op, err)
		}
	}
	out, _ := r.call(localapi.OpLines, localapi.Auth{Token: tok})
	if l := out.(localapi.Lines); l.Status != "Running. 0 may have happened." {
		t.Fatalf("lines %+v", l)
	}
	out, _ = r.call(localapi.OpRequests, localapi.Auth{Token: tok})
	if rq := out.(localapi.Requests); len(rq.Requests) != 1 || rq.Requests[0].ID != "K7" {
		t.Fatalf("requests %+v", rq)
	}
}

// Tokens are random and of fixed size; two sign-ins get two tokens.
func TestTokensAreRandomAndBounded(t *testing.T) {
	r := newRig(t)
	a, b := r.signIn(), r.signIn()
	if a == b {
		t.Fatal("two sign-ins share a token")
	}
	for _, tok := range []string{a, b} {
		if raw, err := hex.DecodeString(tok); err != nil || len(raw) != localapi.TokenBytes {
			t.Fatalf("token %q", tok)
		}
	}
}

func TestATokenEndsAtItsTimeSignOutOrALock(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.now = r.now.Add(time.Hour)
	if _, err := r.call(localapi.OpWaiting, localapi.Auth{Token: tok}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("expired token: %v", err)
	}

	tok = r.signIn()
	if _, err := r.call(localapi.OpSignOut, localapi.Auth{Token: tok}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.call(localapi.OpWaiting, localapi.Auth{Token: tok}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("signed-out token: %v", err)
	}

	tok = r.signIn()
	r.own.mu.Lock()
	r.own.locks++
	r.own.mu.Unlock()
	if _, err := r.call(localapi.OpWaiting, localapi.Auth{Token: tok}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("token after a session lock: %v", err)
	}
}

// The table of sessions is bounded: the oldest goes first.
func TestSessionsAreBounded(t *testing.T) {
	r := newRig(t)
	first := r.signIn()
	for i := 0; i < MaxSessions; i++ {
		r.signIn()
	}
	if _, err := r.call(localapi.OpWaiting, localapi.Auth{Token: first}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("oldest session kept past the bound: %v", err)
	}
	if n := len(r.srv.sessions); n != MaxSessions {
		t.Fatalf("%d sessions", n)
	}
}

func TestAWrongSignInIsRefusedWithAFixedCode(t *testing.T) {
	r := newRig(t)
	if out, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: "000000"}); refusal(out, err) != localapi.RefusedWrongCode {
		t.Fatalf("wrong sign-in: %v", err)
	}
	r.own.answerFn = nil
	tooMany := &fakeTooMany{fakeOwner: r.own}
	r.srv.cfg.Owner = tooMany
	if out, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: good}); refusal(out, err) != localapi.RefusedTooMany {
		t.Fatalf("bound spent: %v", err)
	}
}

type fakeTooMany struct{ *fakeOwner }

func (f *fakeTooMany) LocalSignIn(string) (time.Time, uint64, error) {
	return time.Time{}, 0, owner.ErrTooMany
}

// Security L2: wrong codes are counted in agentosd for the socket, so a
// compromised page cannot spray codes faster than the page's own bound.
func TestWrongCodesOnTheSocketAreLimited(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	for i := 0; i < WrongPerMinute; i++ {
		if out, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: "000000"}); refusal(out, err) != localapi.RefusedWrongCode {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	before := r.own.signIns
	if _, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: good}); code(err) != localapi.ErrLimited {
		t.Fatalf("past the limit: %v", err)
	}
	out, err := r.call(localapi.OpAnswer, localapi.Answer{Token: tok, ID: "K7", Sum: "s1", Approve: true, Code: good})
	if code(err) != localapi.ErrLimited {
		t.Fatalf("answer past the limit: %v %v", out, err)
	}
	if r.own.signIns != before || len(r.own.answers) != 0 {
		t.Fatal("a limited try reached the channel")
	}
	// Denying needs no code, so it is not limited.
	if _, err := r.call(localapi.OpAnswer, localapi.Answer{Token: tok, ID: "K7", Sum: "s1"}); err != nil {
		t.Fatalf("deny while limited: %v", err)
	}
	r.now = r.now.Add(time.Minute)
	if _, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: good}); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
}

// Wrong approval codes, and the texted code, count toward the same limit.
func TestWrongAnswerCodesCountTowardTheLimit(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.own.answerFn = func(id, sum string, approve bool, c string) (string, error) {
		if c == "texted" {
			return "", owner.ErrTextedCode
		}
		return "Wrong code.", owner.ErrWrongCode
	}
	for i := 0; i < WrongPerMinute; i++ {
		c := "000000"
		if i%2 == 0 {
			c = "texted"
		}
		if _, err := r.call(localapi.OpAnswer, localapi.Answer{Token: tok, ID: "K7", Sum: "s1", Approve: true, Code: c}); err != nil {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	if _, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: good}); code(err) != localapi.ErrLimited {
		t.Fatalf("sign-in after %d wrong answers: %v", WrongPerMinute, err)
	}
}

// Tries in flight hold a slot, so concurrent tries cannot pass the limit.
func TestTriesInFlightHoldASlot(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	release := make(chan struct{})
	entered := make(chan struct{}, WrongPerMinute+1)
	r.own.answerFn = func(id, sum string, approve bool, c string) (string, error) {
		entered <- struct{}{}
		<-release
		return "Wrong code.", owner.ErrWrongCode
	}
	var wg sync.WaitGroup
	for i := 0; i < WrongPerMinute; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.call(localapi.OpAnswer, localapi.Answer{Token: tok, ID: "K7", Sum: "s1", Approve: true, Code: "000000"})
		}()
	}
	for i := 0; i < WrongPerMinute; i++ {
		<-entered
	}
	if _, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: good}); code(err) != localapi.ErrLimited {
		t.Fatalf("try past the in-flight slots: %v", err)
	}
	close(release)
	wg.Wait()
}

// A right code gives its slot back.
func TestARightCodeGivesItsSlotBack(t *testing.T) {
	r := newRig(t)
	for i := 0; i < 3*WrongPerMinute; i++ {
		r.signIn()
	}
}

func TestAnswersAreRefusedWithFixedRefusals(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	cases := []struct {
		err     error
		msg     string
		refusal string
		text    string
	}{
		{owner.ErrWrongCode, "Wrong code. 2 tries left.", localapi.RefusedWrongCode, "Wrong code. 2 tries left."},
		{owner.ErrTooMany, "", localapi.RefusedTooMany, ""},
		{owner.ErrNoRequest, "", localapi.RefusedNoRequest, ""},
		{owner.ErrChanged, "", localapi.RefusedChanged, ""},
		{owner.ErrTextedCode, "", localapi.RefusedTextedCode, owner.ErrTextedCode.Error()},
		{errors.New("K7 has expired."), "K7 has expired.", localapi.RefusedNotSettled, "K7 has expired."},
	}
	for _, c := range cases {
		r.own.answerFn = func(string, string, bool, string) (string, error) { return c.msg, c.err }
		out, err := r.call(localapi.OpAnswer, localapi.Answer{Token: tok, ID: "K7", Sum: "s1", Approve: false})
		if err != nil {
			t.Fatalf("%v: %v", c.err, err)
		}
		if a := out.(localapi.Answered); a.Refusal != c.refusal || a.Text != c.text {
			t.Errorf("%v: %+v", c.err, a)
		}
	}
	r.own.answerFn = nil
	out, err := r.call(localapi.OpAnswer, localapi.Answer{Token: tok, ID: "K7", Sum: "s1", Approve: true, Code: good})
	if a := out.(localapi.Answered); err != nil || a.Refusal != "" || a.Text != "Approved K7. Your agent can go ahead." {
		t.Fatalf("approve: %+v %v", out, err)
	}
}

// Security L3: every string field is bounded, and unknown fields refused.
func TestFieldsAreBounded(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	long := func(n int) string { return strings.Repeat("a", n+1) }
	bad := []struct {
		op   string
		args any
	}{
		{localapi.OpSignIn, localapi.SignIn{Code: long(localapi.MaxCode)}},
		{localapi.OpSignIn, localapi.SignIn{}},
		{localapi.OpAnswer, localapi.Answer{Token: tok, ID: long(localapi.MaxID), Sum: "s1"}},
		{localapi.OpAnswer, localapi.Answer{Token: tok, ID: "K7", Sum: long(localapi.MaxSum)}},
		{localapi.OpAnswer, localapi.Answer{Token: tok, ID: "K7", Sum: "s1", Approve: true, Code: long(localapi.MaxCode)}},
		{localapi.OpAnswer, localapi.Answer{Token: tok, ID: "K7", Sum: "s1", Approve: true}},
		{localapi.OpAnswer, localapi.Answer{Token: tok, Sum: "s1"}},
	}
	for _, b := range bad {
		if _, err := r.call(b.op, b.args); code(err) != localapi.ErrBadArgs {
			t.Errorf("%s %+v: %v", b.op, b.args, err)
		}
	}
	if _, err := r.raw(localapi.OpSignIn, `{"code":"123456","extra":1}`); code(err) != localapi.ErrBadArgs {
		t.Errorf("unknown field: %v", err)
	}
	if _, err := r.raw(localapi.OpSignIn, `not json`); code(err) != localapi.ErrBadArgs {
		t.Errorf("malformed: %v", err)
	}
	if len(r.own.answers) != 0 || r.own.signIns != 1 {
		t.Fatalf("a bad request reached the channel: %v %d", r.own.answers, r.own.signIns)
	}
}

// Errors the channel returns never reach the page as their own text.
func TestChannelFailuresAreFixedCodes(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Owner = &failing{fakeOwner: r.own}
	tok := r.srv.mint(r.now.Add(time.Hour), 0)
	for op, args := range map[string]any{
		localapi.OpStop:   struct{}{},
		localapi.OpResume: localapi.Resume{Token: tok},
		localapi.OpSignIn: localapi.SignIn{Code: good},
	} {
		if _, err := r.call(op, args); code(err) != localapi.ErrFailed {
			t.Errorf("%s: %v", op, err)
		}
	}
}

type failing struct{ *fakeOwner }

func (f *failing) LocalStop(context.Context) error    { return errors.New("journal: /var/lib/x") }
func (f *failing) LocalResume(uint64) (string, error) { return "", errors.New("journal: /var/lib/x") }
func (f *failing) LocalSignIn(string) (time.Time, uint64, error) {
	return time.Time{}, 0, errors.New("state: /var/lib/x")
}

// Security D1 on the P2-2w plan: status before sign-in carries fixed
// flags and the owner line's note, never task text or request contents.
func TestStatusWithoutATokenCarriesNoActivity(t *testing.T) {
	r := newRig(t)
	canary := "CANARY-task-7f3a"
	r.srv.cfg.Owner = &planted{fakeOwner: r.own, canary: canary}
	out, err := r.call(localapi.OpStatus, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), canary) || strings.Contains(string(b), "recipient@example.com") || strings.Contains(string(b), "Running") {
		t.Fatalf("status before sign-in: %s", b)
	}
	if st := out.(localapi.Status); st.LineNote != "I can't reach my phone modem." {
		t.Fatalf("line note %q", st.LineNote)
	}
}

type planted struct {
	*fakeOwner
	canary string
}

func (p *planted) LocalStatusLines() string { return "Running. 1 awaiting a decision: " + p.canary }
func (p *planted) LocalWaiting() string     { return "1 waiting: " + p.canary }
func (p *planted) LocalRequests() []owner.LocalRequest {
	return []owner.LocalRequest{{ID: "K7", Sum: "s1", Items: []owner.Item{{Object: p.canary, Recipient: "recipient@example.com"}}}}
}

// Security S1 on step a: refused sign-ins of every kind count, unlock
// proofs (which the channel leaves to the vault) and failures included.
func TestEveryRefusedSignInCountsTowardTheLimit(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Owner = &failing{fakeOwner: r.own}
	for i := 0; i < WrongPerMinute; i++ {
		if _, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: owner.UnlockProofPrefix + "ticket"}); code(err) != localapi.ErrFailed {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	if _, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: owner.UnlockProofPrefix + "ticket"}); code(err) != localapi.ErrLimited {
		t.Fatalf("sixth refused proof: %v", err)
	}
	r.now = r.now.Add(time.Minute)
	r.srv.cfg.Owner = &fakeTooMany{fakeOwner: r.own}
	for i := 0; i < 2*WrongPerMinute; i++ {
		if out, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: good}); refusal(out, err) != localapi.RefusedTooMany {
			t.Fatalf("spent bound %d: %v", i, err)
		}
	}
}

// Security S2 on step a, UX option B: RESUME from the page needs a code
// once the session's sign-in is FreshFor old; a good code counts as a
// fresh sign-in, a wrong one as a wrong code.
func TestAStaleSessionNeedsACodeToResume(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	resume := func(c string) localapi.Answered {
		t.Helper()
		out, err := r.call(localapi.OpResume, localapi.Resume{Token: tok, Code: c})
		if err != nil {
			t.Fatalf("resume %q: %v", c, err)
		}
		return out.(localapi.Answered)
	}
	if a := resume(""); a.Refusal != "" || a.Text != "Resumed." || r.own.resumes != 1 {
		t.Fatalf("fresh: %+v %d", a, r.own.resumes)
	}
	r.now = r.now.Add(localapi.FreshFor)
	signIns := r.own.signIns
	if a := resume(""); a.Refusal != localapi.RefusedCodeNeeded || r.own.resumes != 1 || r.own.signIns != signIns {
		t.Fatalf("stale without a code: %+v", a)
	}
	for i := 0; i < WrongPerMinute; i++ {
		if a := resume("000000"); a.Refusal != localapi.RefusedWrongCode || r.own.resumes != 1 {
			t.Fatalf("wrong code %d: %+v", i, a)
		}
	}
	if _, err := r.call(localapi.OpResume, localapi.Resume{Token: tok, Code: good}); code(err) != localapi.ErrLimited {
		t.Fatalf("past the limit: %v", err)
	}
	r.now = r.now.Add(time.Minute)
	if a := resume(good); a.Refusal != "" || r.own.resumes != 2 {
		t.Fatalf("good code: %+v", a)
	}
	if a := resume(""); a.Refusal != "" || r.own.resumes != 3 {
		t.Fatalf("right after a good code: %+v", a)
	}
	if _, err := r.call(localapi.OpResume, localapi.Resume{Token: tok, Code: strings.Repeat("1", localapi.MaxCode+1)}); code(err) != localapi.ErrBadArgs {
		t.Fatalf("long code: %v", err)
	}
}

// The page asks whether its cookie's token is live, and until when.
func TestASessionReportsItsTime(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	out, err := r.call(localapi.OpSession, localapi.Auth{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	if ses := out.(localapi.Session); ses.Token != tok || !ses.Until.Equal(r.now.Add(time.Hour)) {
		t.Fatalf("session %+v", ses)
	}
	out, _ = r.call(localapi.OpStatus, struct{}{})
	if st := out.(localapi.Status); st.UnlockDays != 7 {
		t.Fatalf("unlock days %d", st.UnlockDays)
	}
}

// L3 SHOULD on #184: without randomness no token is minted; the sign-in
// fails closed rather than handing out a guessable one.
func TestNoRandomnessMintsNoToken(t *testing.T) {
	r := newRig(t)
	r.srv = New(Config{Owner: r.own, Now: func() time.Time { return r.now }, Rand: failingRand{}})
	r.ops = r.srv.Ops()
	if _, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: good}); code(err) != localapi.ErrFailed {
		t.Fatalf("sign-in without randomness: %v", err)
	}
	if len(r.srv.sessions) != 0 {
		t.Fatal("a session was kept")
	}
}

type failingRand struct{}

func (failingRand) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// UX-2wb-2: a wrong code on a signed-in RESUME tells the day's tries once
// 2 or fewer remain; before sign-in no count is told (Security D1).
func TestAWrongResumeCodeTellsTheTriesLeft(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	r.now = r.now.Add(localapi.FreshFor)
	for _, c := range []struct {
		left int
		want string
	}{{5, ""}, {2, "2 tries left today."}, {1, "1 try left today."}, {0, "No more codes can be tried today. Try again after 14:05, or use your recovery key."}} {
		r.own.mu.Lock()
		r.own.left = c.left
		r.own.mu.Unlock()
		out, err := r.call(localapi.OpResume, localapi.Resume{Token: tok, Code: "000000"})
		want := localapi.RefusedWrongCode
		if c.left == 0 {
			want = localapi.RefusedTooMany
		}
		if a := out.(localapi.Answered); err != nil || a.Refusal != want || a.Text != c.want {
			t.Fatalf("left %d: %+v %v", c.left, out, err)
		}
		r.now = r.now.Add(time.Minute) // past the socket's limit
	}
	if out, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: "000000"}); refusal(out, err) != localapi.RefusedTooMany {
		t.Fatalf("sign-in once none are left: %v", err)
	}
}

// Security D1: page_sign_in is untokened, so a wrong code there gets only
// its fixed refusal, and status before sign-in never tells the tries.
func TestAWrongSignInTellsNoTriesLeft(t *testing.T) {
	r := newRig(t)
	for _, c := range []struct {
		left    int
		refusal string
		text    string
	}{
		{5, localapi.RefusedWrongCode, ""},
		{2, localapi.RefusedWrongCode, ""},
		{0, localapi.RefusedTooMany, ""},
	} {
		r.own.mu.Lock()
		r.own.left = c.left
		r.own.mu.Unlock()
		out, err := r.call(localapi.OpSignIn, localapi.SignIn{Code: "000000"})
		if ses := out.(localapi.Session); err != nil || ses.Refusal != c.refusal || ses.Token != "" {
			t.Fatalf("left %d: %+v %v", c.left, out, err)
		}
		st, _ := r.call(localapi.OpStatus, struct{}{})
		b, _ := json.Marshal(st)
		if strings.Contains(string(b), "tries") || strings.Contains(string(b), "14:05") || strings.Contains(string(b), "No more") {
			t.Fatalf("status before sign-in tells the tries: %s", b)
		}
		r.now = r.now.Add(time.Minute)
	}
}

// W5a-resume: a signed-in page lists the paused grants and asks to resume
// one from the pause it showed; the ask's own failures are fixed codes,
// and a bad ask never reaches the gate.
func TestAPausedGrantIsAskedToResumeFromASession(t *testing.T) {
	r := newRig(t)
	tok := r.signIn()
	out, err := r.call(localapi.OpPaused, localapi.Auth{Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	if p := out.(localapi.Paused); len(p.Grants) != 1 || p.Grants[0].ID != "G2" || p.Grants[0].Pause != "loop2/pause/G2/1" {
		t.Fatalf("paused %+v", p)
	}
	out, err = r.call(localapi.OpAskResume, localapi.AskResume{Token: tok, Grant: "G2", Pause: "loop2/pause/G2/1"})
	if err != nil || out.(localapi.Text).Text != "Asked." {
		t.Fatalf("ask: %v %v", out, err)
	}
	if _, err := r.call(localapi.OpAskResume, localapi.AskResume{Token: tok, Grant: "G2", Pause: "loop2/pause/G2/0"}); code(err) != localapi.ErrFailed {
		t.Fatalf("stale pause: %v", err)
	}
	long := func(n int) string { return strings.Repeat("a", n+1) }
	for _, in := range []localapi.AskResume{
		{Token: tok, Pause: "p"}, {Token: tok, Grant: "G2"},
		{Token: tok, Grant: long(localapi.MaxID), Pause: "p"}, {Token: tok, Grant: "G2", Pause: long(localapi.MaxPause)},
	} {
		if _, err := r.call(localapi.OpAskResume, in); code(err) != localapi.ErrBadArgs {
			t.Errorf("%+v: %v", in, err)
		}
	}
	if len(r.asks) != 2 {
		t.Fatalf("asks reaching the gate %v", r.asks)
	}
	r.srv.cfg.Paused, r.srv.cfg.AskResume = nil, nil
	for op, args := range map[string]any{
		localapi.OpPaused:    localapi.Auth{Token: tok},
		localapi.OpAskResume: localapi.AskResume{Token: tok, Grant: "G2", Pause: "loop2/pause/G2/1"},
	} {
		if _, err := r.call(op, args); code(err) != localapi.ErrFailed {
			t.Errorf("%s with no hook: %v", op, err)
		}
	}
}
