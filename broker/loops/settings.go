package loops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/owner"
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
	KindHelp    Kind = "help"    // HELP LOOPS: the full list, changes nothing
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
//	LEARNING, SECURITY TESTS, UPDATE CHECKS + OFF | ON (one loop by name)
//	STOP SHARING | START SHARING
//	HELP LOOPS
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
		// Any whole number is a budget request; one over MaxSpareCalls is
		// answered with the limit rather than passed to the agent (UX-57-2).
		n, err := strconv.ParseInt(f[2], 10, 64)
		if errors.Is(err, strconv.ErrRange) && strings.Trim(f[2], "0123456789") == "" {
			n, err = MaxSpareCalls+1, nil
		}
		if err == nil && n >= 0 && (n > MaxSpareCalls || f[2] == strconv.FormatInt(n, 10)) {
			return Request{Kind: KindBudget, Calls: min(n, MaxSpareCalls+1)}, true
		}
	case len(f) == 2 && f[1] == "SHARING" && (f[0] == "STOP" || f[0] == "START"):
		return Request{Kind: KindSharing, On: f[0] == "START"}, true
	case len(f) == 2 && f[0] == "HELP" && f[1] == "LOOPS":
		return Request{Kind: KindHelp}, true
	case len(f) >= 2:
		// Word names for each loop (UX-49-2): LEARNING OFF, SECURITY
		// TESTS OFF, UPDATE CHECKS ON.
		on, ok := onOff(f[len(f)-1])
		name := strings.Join(f[:len(f)-1], " ")
		for l, w := range loopAliases {
			if ok && name == w {
				return Request{Kind: KindLoops, Loop: l, On: on}, true
			}
		}
	}
	return Request{}, false
}

// loopAliases are the loops' names in owner texts.
var loopAliases = map[Loop]string{
	Improve:  "LEARNING",
	Secure:   "SECURITY TESTS",
	Maintain: "UPDATE CHECKS",
}

// HelpLine is the one line HELP carries for the loops; HELP LOOPS gives
// HelpText. HELP as a whole must fit CH-12's three segments (UX-49-1).
const HelpLine = "LOOPS OFF/ON: spare-time learning and self-tests. HELP LOOPS for more."

// HelpText is the reply to HELP LOOPS.
const HelpText = "LOOPS OFF/ON: all spare-time work. LEARNING, SECURITY TESTS or UPDATE CHECKS OFF/ON: one part. " +
	"SPARE BUDGET 100: AI calls a day. STOP SHARING."

// Confirm is the owner's one-line reply once a request took effect
// (UX-49-3; security C1 for turning work back on).
func Confirm(r Request, set Settings) string {
	switch r.Kind {
	case KindHelp:
		return HelpText
	case KindBudget:
		return fmt.Sprintf("Spare-time work may now use up to %d AI calls a day.", set.SpareCalls)
	case KindSharing:
		if r.On {
			return "Sharing is on: learned skills built from public data may be shared. Reply STOP SHARING to stop."
		}
		return "Sharing is off: nothing learned leaves this box."
	}
	if r.Loop == "" {
		if r.On {
			return "Spare-time work is back on. Reply LOOPS OFF if this wasn't you."
		}
		return "Spare-time work is off: no learning, security tests or update checks until you reply LOOPS ON."
	}
	w := strings.ToLower(loopAliases[r.Loop])
	if r.On {
		return fmt.Sprintf("%s %s back on. Reply %s OFF if this wasn't you.", capitalize(w), be(r.Loop), loopAliases[r.Loop])
	}
	return fmt.Sprintf("%s %s off until you reply %s ON.", capitalize(w), be(r.Loop), loopAliases[r.Loop])
}

// be is the verb for a loop's word name: "Learning is", "Security tests
// are".
func be(l Loop) string {
	if strings.HasSuffix(loopAliases[l], "S") {
		return "are"
	}
	return "is"
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// BudgetAsk is the broker-rendered approval text for raising the spare
// budget, old and new from broker state, never from the request's text
// (security C2).
func (s *Scheduler) BudgetAsk(in journal.Intent) (string, error) {
	r, ok := parseSetting(in.ID)
	if !ok || r.Kind != KindBudget {
		return "", errors.New("loops: not a budget intent")
	}
	cur := s.Settings().SpareCalls
	return fmt.Sprintf("Raise spare-time AI use from %d to %d calls a day?", cur, r.Calls), nil
}

// LowTierRaiseMax is the most spare calls a day a low-tier raise may set.
const LowTierRaiseMax = 5 * DefaultSpareCalls

// Line is the owner request for an intent Check sent to the owner (the
// grants gate's Loops.Line): raising the spare budget, with the old and
// new calls from broker state (security C2). Spare calls are paid AI use
// on the owner's provider account, so only a small step is low tier (a
// texted code): to at most twice the current budget and at most
// LowTierRaiseMax. Anything larger needs the code generator (GrantChange),
// so a SIM swapper holding the owner's number cannot open-endedly spend
// the owner's money (security B1 on #57).
func (s *Scheduler) Line(in journal.Intent) (owner.Item, error) {
	r, ok := parseSetting(in.ID)
	if !ok || r.Kind != KindBudget || in.Action != ActionBudget {
		return owner.Item{}, errors.New("loops: no owner line for this intent")
	}
	cur := s.Settings().SpareCalls
	kind := owner.Ordinary
	if r.Calls > 2*cur || r.Calls > LowTierRaiseMax {
		kind = owner.GrantChange
	}
	return owner.Item{Object: "spare-time AI use", Detail: fmt.Sprintf("from %d to %d paid AI calls a day", cur, r.Calls),
		UndoBy: fmt.Sprintf("SPARE BUDGET %d any time", cur),
		Facts:  owner.Facts{Kind: kind, Verb: "raise", NoRecipient: true}}, nil
}

// Text answers an owner text that is a loop setting (the owner channel's
// settings hook): ok is false for any other message, which goes on to the
// agent. The owner channel calls it only for messages from the owner's
// number, after its own control words. In a locked session (unlocked
// false) only narrowing settings are taken: anything OFF, STOP SHARING, a
// budget no higher than the current one, and HELP LOOPS, whose worst case
// is a pause, as for CH-11's pause words (UX-57-1). Turning work on and
// raising the budget return ok false there, so the owner channel asks for
// the unlock.
func (s *Scheduler) Text(ctx context.Context, msg string, unlocked bool) (reply string, ok bool) {
	r, ok := ParseText(msg)
	if !ok {
		return "", false
	}
	if !unlocked && !s.narrowing(r) {
		return "", false
	}
	if r.Kind == KindBudget && r.Calls > MaxSpareCalls {
		return fmt.Sprintf("The most is %d calls a day.", MaxSpareCalls), true
	}
	err := s.Set(ctx, r)
	var no refused
	switch {
	case err == nil:
		return Confirm(r, s.Settings()), true
	case errors.Is(err, ErrPending):
		return "Raising spare-time AI use needs your approval; a request follows.", true
	case errors.Is(err, errNoSharing):
		return "Sharing is not available yet.", true
	case errors.As(err, &no):
		return "Not allowed: " + no.reason + ".", true
	default:
		return "The box could not save that setting. Try again later.", true
	}
}

// Narrows reports that msg is a loop setting a locked session takes: the
// owner channel runs it at once instead of holding it for the unlock.
func (s *Scheduler) Narrows(msg string) bool {
	r, ok := ParseText(msg)
	return ok && s.narrowing(r)
}

// narrowing reports a request whose worst case is a pause.
func (s *Scheduler) narrowing(r Request) bool {
	switch r.Kind {
	case KindHelp:
		return true
	case KindLoops, KindSharing:
		return !r.On
	case KindBudget:
		return r.Calls <= s.Settings().SpareCalls
	}
	return false
}

// refused is a setting the broker's policy denied, with its reason.
type refused struct{ reason string }

func (r refused) Error() string { return "loops: refused: " + r.reason }

var errNoSharing = errors.New("loops: sharing is not wired")

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
// It reports NeedsOwner, which is how the grants gate tells it apart
// without importing this package (ARC-2), as for change.ErrNeedsOwner.
var ErrNeedsOwner error = needsOwner{}

type needsOwner struct{}

func (needsOwner) Error() string    { return "loops: needs the owner's approval" }
func (needsOwner) NeedsOwner() bool { return true }

// state is what the scheduler persists.
type state struct {
	Seq      int             `json:"seq"`
	Settings Settings        `json:"settings"`
	Applied  map[string]bool `json:"applied"`
	// Order is Applied's IDs in the order they were applied, oldest
	// first; pruning drops the oldest (L3 R2 on #49).
	Order []string `json:"order,omitempty"`
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
	if r.Kind == KindHelp {
		return nil
	}
	if r.Kind == KindSharing {
		if s.cfg.Sharing == nil {
			return errNoSharing
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
		return refused{strings.TrimPrefix(st.Permission.Reason, "loops: ")}
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
		if in.Action == ActionBudgetLower && r.Calls > prev.SpareCalls {
			// Check allowed it as narrowing; the budget changed since.
			return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not a lower budget"}
		}
		next.SpareCalls = r.Calls
	}
	if r.Kind == KindBudget && s.cfg.Spare != nil {
		if err := s.cfg.Spare.SetOverallCap(SpareLimits(r.Calls)); err != nil {
			return journal.Outcome{Result: journal.ResultNotApplied, Evidence: err.Error()}
		}
	}
	s.st.Settings = next
	prevOrder, prevApplied := s.st.Order, maps.Clone(s.st.Applied)
	s.st.Applied[in.ID] = true
	s.st.Order = append(slices.Clip(s.st.Order), in.ID)
	s.pruneLocked()
	if err := s.saveLocked(); err != nil {
		s.st.Settings = prev
		s.st.Order, s.st.Applied = prevOrder, prevApplied
		if r.Kind == KindBudget && s.cfg.Spare != nil {
			_ = s.cfg.Spare.SetOverallCap(SpareLimits(prev.SpareCalls))
		}
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: "not saved"}
	}
	if s.done != nil && (next.Off || next.Paused[s.runningLoop]) {
		s.preempted = true // offered again if the loop comes back on
		// The owner's setting: not a cut a candidate caused (PE5).
		s.cancelLocked(change.ErrOwnerPreempt)
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

// keepApplied is how many recent settings Reconcile can answer for; older
// ones settled long ago (security R2).
const keepApplied = 256

// pruneLocked keeps the last keepApplied settings by apply order, so a
// setting applied now is kept however old its submission is (an approval
// that waited while many others were made).
func (s *Scheduler) pruneLocked() {
	if n := len(s.st.Order) - keepApplied; n > 0 {
		for _, id := range s.st.Order[:n] {
			delete(s.st.Applied, id)
		}
		s.st.Order = slices.Clone(s.st.Order[n:])
	}
}

// orderLocked rebuilds Order for state saved before it existed: by
// submission number, which is the order those builds applied them in
// unless an approval waited.
func (s *Scheduler) orderLocked() {
	if len(s.st.Order) > 0 || len(s.st.Applied) == 0 {
		return
	}
	for id := range s.st.Applied {
		s.st.Order = append(s.st.Order, id)
	}
	seq := func(id string) int {
		p := strings.Split(id, ":")
		if len(p) < 2 {
			return -1
		}
		n, err := strconv.Atoi(strings.TrimPrefix(p[1], "n"))
		if err != nil {
			return -1
		}
		return n
	}
	slices.SortFunc(s.st.Order, func(a, b string) int { return seq(a) - seq(b) })
}
