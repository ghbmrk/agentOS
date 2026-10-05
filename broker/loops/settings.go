package loops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
)

// Loop names one of the three loops (§11A).
type Loop string

const (
	Improve  Loop = "improve"  // Loop 1: self-improvement (LOOP-4 to LOOP-6)
	Secure   Loop = "secure"   // Loop 2: self-securing (LOOP-7 to LOOP-10)
	Maintain Loop = "maintain" // Loop 3: maintenance (LOOP-11)
)

// All lists the loops in their owner-facing order (LOOP 1, 2, 3).
var All = []Loop{Improve, Secure, Maintain}

func (l Loop) number() int {
	for i, x := range All {
		if x == l {
			return i + 1
		}
	}
	return 0
}

// Settings are the owner's loop settings (LOOP-0). The zero value is the
// spec default: every loop on. Sharing (§11B) is the change pipeline's
// setting (SetSharing); per-category contribution policy belongs to the
// contribution package (P4).
type Settings struct {
	// Off is the global switch.
	Off bool `json:"off"`
	// Paused lists loops the owner turned off one by one.
	Paused map[Loop]bool `json:"paused,omitempty"`
	// Spare is the spare AI budget per meter window (LOOP-2), counted in
	// model calls; tokens scale with it (TokensPerCall).
	SpareCalls int64 `json:"spare_calls"`
}

// On reports whether loop l may run.
func (s Settings) On(l Loop) bool { return !s.Off && !s.Paused[l] }

// DefaultSpareCalls is the default spare budget: a conservative share of a
// day's model use (LOOP-0), small next to meter.DefaultOverallCap.
const DefaultSpareCalls = 100

// TokensPerCall turns the owner's call count into the meter's token cap.
const TokensPerCall = 10_000

// SpareLimits is the meter cap for a spare budget of calls. The meter has
// no zero cap, so a zero budget is one call of one token: no real call
// fits under it.
func SpareLimits(calls int64) meter.Limits {
	if calls <= 0 {
		return meter.Limits{Calls: 1, Tokens: 1}
	}
	return meter.Limits{Calls: calls, Tokens: calls * TokensPerCall}
}

// MaxSpareCalls bounds what one owner text may set, so a typo cannot ask
// for an unbounded budget; larger budgets are set on the local page.
const MaxSpareCalls = 5000

// Kind is what an owner request changes.
type Kind string

const (
	KindLoops   Kind = "loops"   // turn all loops, or one, off or on
	KindBudget  Kind = "budget"  // set the spare budget
	KindSharing Kind = "sharing" // the change pipeline's sharing setting
)

// Request is one parsed owner setting.
type Request struct {
	Kind  Kind
	Loop  Loop // KindLoops: empty means every loop (the global switch)
	On    bool
	Calls int64 // KindBudget
}

// ParseText reads an owner text as a loop setting (LOOP-0, CH-11). Like a
// control word, it counts only when it is the whole message, ignoring case
// and punctuation:
//
//	LOOPS OFF | LOOPS ON
//	LOOP 1 OFF | LOOP 2 ON | ...
//	SPARE BUDGET 200          (model calls a day for the loops)
//	STOP SHARING | START SHARING
//
// Anything else is not a loop setting and goes on to the agent.
func ParseText(msg string) (Request, bool) {
	f := strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToUpper(r)
		}
		return ' '
	}, msg))
	onOff := func(w string) (bool, bool) {
		switch w {
		case "ON":
			return true, true
		case "OFF":
			return false, true
		}
		return false, false
	}
	switch {
	case len(f) == 2 && f[0] == "LOOPS":
		if on, ok := onOff(f[1]); ok {
			return Request{Kind: KindLoops, On: on}, true
		}
	case len(f) == 3 && f[0] == "LOOP":
		n, err := strconv.Atoi(f[1])
		on, ok := onOff(f[2])
		if err == nil && ok && n >= 1 && n <= len(All) && f[1] == strconv.Itoa(n) {
			return Request{Kind: KindLoops, Loop: All[n-1], On: on}, true
		}
	case len(f) == 3 && f[0] == "SPARE" && f[1] == "BUDGET":
		n, err := strconv.ParseInt(f[2], 10, 64)
		if err == nil && n >= 0 && n <= MaxSpareCalls && f[2] == strconv.FormatInt(n, 10) {
			return Request{Kind: KindBudget, Calls: n}, true
		}
	case len(f) == 2 && f[1] == "SHARING" && (f[0] == "STOP" || f[0] == "START"):
		return Request{Kind: KindSharing, On: f[0] == "START"}, true
	}
	return Request{}, false
}

// HelpText lists the loop settings for HELP, in one line.
const HelpText = "LOOPS OFF or LOOPS ON pauses or restarts spare-time work (LOOP 1 learns from your tasks, " +
	"LOOP 2 tests security, LOOP 3 checks updates; e.g. LOOP 2 OFF). SPARE BUDGET 100 sets its AI calls a day. " +
	"STOP SHARING keeps learned skills on this box."

// DefaultsLine is onboarding's one line on the loop defaults (LOOP-0).
func DefaultsLine(calls int64) string {
	return fmt.Sprintf("In spare time the box learns from your tasks, tests its own security and checks for updates, "+
		"using up to %d AI calls a day; reply LOOPS OFF to stop that.", calls)
}

// Journal vocabulary for loop settings, which are broker-state intents
// (OP-5). Decisions read only the intent ID, which the journal never
// redacts; params repeat it for audit.
const (
	Executor    = "loops"
	OriginOwner = "owner"

	ActionOff         = journal.ActionLoopsOff // narrowing: works during STOP
	ActionOn          = "meta.loops.on"
	ActionBudget      = "meta.loops.budget" // raising the spare budget
	ActionBudgetLower = journal.ActionLoopsBudgetLower
)

// ErrNeedsOwner is returned by Check for a setting only an approved owner
// request may make: raising the spare budget spends the owner's quota, so
// a spoofed text must not be enough (CH-10). The broker's policy turns it
// into an approval request, as for change.ErrNeedsOwner.
var ErrNeedsOwner = errors.New("loops: needs the owner's approval")

// state is what the scheduler persists.
type state struct {
	Seq      int             `json:"seq"`
	Settings Settings        `json:"settings"`
	Applied  map[string]bool `json:"applied"`
}

// settingID is the intent ID for a request: loops:<n>:<verb>:<arg>.
func settingID(n int, r Request) (id, action string, err error) {
	switch r.Kind {
	case KindLoops:
		target := "all"
		if r.Loop != "" {
			if r.Loop.number() == 0 {
				return "", "", fmt.Errorf("loops: unknown loop %q", r.Loop)
			}
			target = string(r.Loop)
		}
		verb, action := "off", ActionOff
		if r.On {
			verb, action = "on", ActionOn
		}
		return fmt.Sprintf("loops:n%d:%s:%s", n, verb, target), action, nil
	case KindBudget:
		if r.Calls < 0 || r.Calls > MaxSpareCalls {
			return "", "", fmt.Errorf("loops: spare budget %d out of range", r.Calls)
		}
		return fmt.Sprintf("loops:n%d:budget:%d", n, r.Calls), "", nil
	}
	return "", "", fmt.Errorf("loops: %q is not a loop setting", r.Kind)
}

// parseSetting reads an intent ID back into a request.
func parseSetting(id string) (Request, bool) {
	p := strings.Split(id, ":")
	if len(p) != 4 || p[0] != "loops" || !strings.HasPrefix(p[1], "n") {
		return Request{}, false
	}
	if _, err := strconv.Atoi(p[1][1:]); err != nil {
		return Request{}, false
	}
	switch p[2] {
	case "on", "off":
		r := Request{Kind: KindLoops, On: p[2] == "on"}
		if p[3] != "all" {
			r.Loop = Loop(p[3])
			if r.Loop.number() == 0 {
				return Request{}, false
			}
		}
		return r, true
	case "budget":
		n, err := strconv.ParseInt(p[3], 10, 64)
		if err != nil || n < 0 || n > MaxSpareCalls || p[3] != strconv.FormatInt(n, 10) {
			return Request{}, false
		}
		return Request{Kind: KindBudget, Calls: n}, true
	}
	return Request{}, false
}

// Set submits an owner setting as an intent and runs it: a loop setting
// through the journal (OP-5), sharing through the change pipeline. The
// wiring calls it only for text from the owner channel or the local page,
// whose origin the broker authenticated. It returns ErrPending when the
// setting waits for the owner's approval (raising the budget).
func (s *Scheduler) Set(ctx context.Context, r Request) error {
	if r.Kind == KindSharing {
		if s.cfg.Sharing == nil {
			return errors.New("loops: sharing is not wired")
		}
		return s.cfg.Sharing(ctx, r.On)
	}
	if s.cfg.Journal == nil {
		return errors.New("loops: no journal attached")
	}
	s.mu.Lock()
	s.st.Seq++
	n, cur := s.st.Seq, s.st.Settings
	err := s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	id, action, err := settingID(n, r)
	if err != nil {
		return err
	}
	params := map[string]any{"setting": string(r.Kind)}
	switch r.Kind {
	case KindLoops:
		params["loop"], params["on"] = string(r.Loop), r.On
	case KindBudget:
		params["calls"] = r.Calls
		action = ActionBudget
		if r.Calls <= cur.SpareCalls {
			action = ActionBudgetLower
		}
	}
	return runIntent(ctx, s.cfg.Journal, journal.Intent{ID: id, Origin: OriginOwner, Account: journal.BrokerAccount,
		Action: action, Executor: Executor, Params: params})
}

// ErrPending means the setting waits for the owner's approval.
var ErrPending = errors.New("loops: waiting for the owner")

func runIntent(ctx context.Context, j Journal, in journal.Intent) error {
	st, err := j.Submit(in)
	if err != nil {
		return err
	}
	if st.State == journal.Pending {
		if st, err = j.Authorize(ctx, in.ID); err != nil {
			return err
		}
	}
	switch st.State {
	case journal.Pending:
		return ErrPending
	case journal.Denied:
		return errors.New("loops: refused: " + st.Permission.Reason)
	case journal.Authorized:
		if st, err = j.Dispatch(ctx, in.ID); err != nil {
			return err
		}
	}
	if st.State != journal.Succeeded {
		return errors.New("loops: setting not applied")
	}
	return nil
}

// Check is the policy for meta.loops intents (OP-3), at authorize and
// again before dispatch. Only the owner changes loop settings: no loop,
// pipeline, or guest origin may, so Loop 1 cannot change its own budget
// (LOOP-6, CHG-2). Turning loops off and lowering the budget are allowed
// on the owner's text; turning loops on is too, since it spends only the
// budget the owner already set; raising the budget needs an approved
// owner request (ErrNeedsOwner).
func (s *Scheduler) Check(_ context.Context, _ journal.Phase, in journal.Intent) error {
	if in.Account != journal.BrokerAccount || in.Executor != Executor {
		return errors.New("loops: not a loop setting intent")
	}
	if in.Origin != OriginOwner {
		return errors.New("loops: only the owner changes loop settings")
	}
	r, ok := parseSetting(in.ID)
	if !ok {
		return errors.New("loops: malformed loop setting intent")
	}
	s.mu.Lock()
	cur := s.st.Settings.SpareCalls
	s.mu.Unlock()
	switch {
	case r.Kind == KindLoops && !r.On && in.Action == ActionOff:
		return nil
	case r.Kind == KindLoops && r.On && in.Action == ActionOn:
		return nil
	case r.Kind == KindBudget && in.Action == ActionBudgetLower:
		if r.Calls > cur {
			return errors.New("loops: not a lower budget")
		}
		return nil
	case r.Kind == KindBudget && in.Action == ActionBudget:
		return ErrNeedsOwner
	}
	return errors.New("loops: action does not match the setting")
}

// Execute applies a loop setting. Only Check-allowed intents reach it.
func (s *Scheduler) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	r, ok := parseSetting(in.ID)
	if !ok {
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "malformed"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Applied[in.ID] {
		return journal.Outcome{Result: journal.ResultSucceeded}
	}
	prev := s.st.Settings
	next := prev
	next.Paused = map[Loop]bool{}
	for k, v := range prev.Paused {
		next.Paused[k] = v
	}
	switch r.Kind {
	case KindLoops:
		if r.Loop == "" {
			next.Off = !r.On
			if r.On {
				next.Paused = map[Loop]bool{} // LOOPS ON restarts every loop
			}
		} else if r.On {
			if next.Off {
				// LOOP n ON after LOOPS OFF turns on that loop only.
				next.Off = false
				for _, l := range All {
					next.Paused[l] = true
				}
			}
			delete(next.Paused, r.Loop)
		} else {
			next.Paused[r.Loop] = true
		}
	case KindBudget:
		next.SpareCalls = r.Calls
	}
	if r.Kind == KindBudget && s.cfg.Spare != nil {
		if err := s.cfg.Spare.SetOverallCap(SpareLimits(r.Calls)); err != nil {
			return journal.Outcome{Result: journal.ResultNotApplied, Evidence: err.Error()}
		}
	}
	s.st.Settings = next
	s.st.Applied[in.ID] = true
	if err := s.saveLocked(); err != nil {
		s.st.Settings = prev
		delete(s.st.Applied, in.ID)
		if r.Kind == KindBudget && s.cfg.Spare != nil {
			_ = s.cfg.Spare.SetOverallCap(SpareLimits(prev.SpareCalls))
		}
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not saved"}
	}
	if s.done != nil && (next.Off || next.Paused[s.runningLoop]) {
		s.preempted = true // offered again if the loop comes back on
		s.cancelLocked()
	}
	s.wakeLocked()
	return journal.Outcome{Result: journal.ResultSucceeded}
}

// Reconcile answers from the saved state: a setting not saved was not
// applied.
func (s *Scheduler) Reconcile(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Applied[in.ID] {
		return journal.Outcome{Result: journal.ResultSucceeded}
	}
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not in saved state"}
}

// Settings returns the current settings.
func (s *Scheduler) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.st.Settings
	out.Paused = map[Loop]bool{}
	for k, v := range s.st.Settings.Paused {
		out.Paused[k] = v
	}
	return out
}

func (s *Scheduler) saveLocked() error {
	b, err := json.Marshal(s.st)
	if err != nil {
		return err
	}
	return s.cfg.Store.Save(b)
}
