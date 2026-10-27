package loops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"unicode"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
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
	// Spare is the spare AI budget per day (LOOP-2), counted in
	// model calls; tokens scale with it (TokensPerCall).
	SpareCalls int64 `json:"spare_calls"`
	// Updates are the owner's update channel and cadence (UPD-4, UPD-5),
	// which Loop 3 reads.
	Updates UpdateSettings `json:"updates,omitzero"`
}

// Update channels (UPD-4), as update and maintain name them.
const (
	ChannelStable = "stable" // the default
	ChannelFast   = "fast"
	ChannelPinned = "pinned" // no automatic updates, security notices only
)

// Soak bounds for stable releases, in days (UPD-5: at least 7).
const (
	DefaultSoakDays = 7
	MinSoakDays     = 7
	MaxSoakDays     = 60 // well inside maintain's 90-day memory of first sightings
)

// UpdateSettings are UPD-5's cadence defaults as owner settings. The zero
// value is the spec default: stable, a 7-day soak, tested security fixes
// staged on their own.
type UpdateSettings struct {
	// Channel is ChannelStable, ChannelFast or ChannelPinned; empty is
	// stable.
	Channel string `json:"channel,omitempty"`
	// SoakDays is how long a stable release waits before it is offered;
	// zero is DefaultSoakDays.
	SoakDays int `json:"soak_days,omitempty"`
	// SecurityAsk sends every security fix to the owner instead of staging
	// a tested one on its own.
	SecurityAsk bool `json:"security_ask,omitempty"`
}

// ChannelName is the channel, with the default filled in. A saved value
// that is not a channel reads as stable, so a damaged state file never
// stops checks or security notices (L3 MUST on #130).
func (u UpdateSettings) ChannelName() string {
	if _, ok := channelRank[u.Channel]; !ok {
		return ChannelStable
	}
	return u.Channel
}

// Soak is the soak in days, with the default filled in and clamped to
// MinSoakDays..MaxSoakDays whatever the saved state says (L3 MUST on #130).
func (u UpdateSettings) Soak() int {
	if u.SoakDays <= 0 {
		return DefaultSoakDays
	}
	return min(max(u.SoakDays, MinSoakDays), MaxSoakDays)
}

// channelRank orders channels from fastest to most cautious.
var channelRank = map[string]int{ChannelFast: 0, ChannelStable: 1, ChannelPinned: 2}

// channelWords are the channels in owner texts.
var channelWords = map[string]string{"STABLE": ChannelStable, "FAST": ChannelFast, "PINNED": ChannelPinned}

// On reports whether loop l may run.
func (s Settings) On(l Loop) bool { return !s.Off && !s.Paused[l] }

// NoSpareBudget is the default spare budget: no fixed call budget, so
// loops use spare quota above the owner reserve (LOOP-0, RES-5, LOOP-1).
// An owner's SPARE BUDGET n sets a fixed one.
const NoSpareBudget int64 = -1

// PaidRouteCalls is the spare budget with no fixed one. Loop calls through
// the model socket can reach pay-per-token API routes, which keep a money cap
// (OP-8), and until RES-5a the cap cannot tell those from plan quota, so no
// fixed budget is the OP-8 default of 1500 calls a day, not unlimited
// (security and combined fix-lists on #2319).
const PaidRouteCalls int64 = 1500

// budgetCalls is the calls a day the budget cur allows: the paid-route
// cap when there is no fixed budget.
func budgetCalls(cur int64) int64 {
	if cur < 0 {
		return PaidRouteCalls
	}
	return cur
}

// withinBudget reports whether calls is at most the budget cur.
func withinBudget(calls, cur int64) bool { return calls <= budgetCalls(cur) }

// TokensPerCall turns the owner's call count into output tokens.
const TokensPerCall = 10_000

// SpareCap is the day spend cap, in minor units, for a spare budget of calls
// on a route priced outPerM minor units per million output tokens: each call
// its TokensPerCall at that price, rounded up. No fixed budget is
// PaidRouteCalls. A zero budget is a zero cap: no call that costs anything
// fits under it.
func SpareCap(calls, outPerM int64) int64 {
	return mulDiv(budgetCalls(calls), TokensPerCall*max(outPerM, 0), 1_000_000, true)
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

	KindChannel     Kind = "channel"      // UPDATES STABLE | FAST | PINNED (UPD-4)
	KindSoak        Kind = "soak"         // UPDATE SOAK n: days a stable release waits (UPD-5)
	KindSecurity    Kind = "security"     // SECURITY UPDATES AUTO (On) | ASK
	KindHelpUpdates Kind = "help-updates" // HELP UPDATES, changes nothing
)

// Request is one parsed owner setting.
type Request struct {
	Kind  Kind
	Loop  Loop // KindLoops: empty means every loop (the global switch)
	On    bool
	Calls int64 // KindBudget
	// Channel is KindChannel's channel.
	Channel string
	// Days is KindSoak's soak; out of range is answered with the bound.
	Days int
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
//	UPDATES STABLE | UPDATES FAST | UPDATES PINNED
//	UPDATE SOAK 14 [DAYS]
//	SECURITY UPDATES AUTO | SECURITY UPDATES ASK
//	HELP UPDATES
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
	case len(f) == 2 && f[0] == "HELP" && f[1] == "UPDATES":
		return Request{Kind: KindHelpUpdates}, true
	// UPDATE and UPDATES are both taken (UX-130-1).
	case len(f) == 2 && (f[0] == "UPDATES" || f[0] == "UPDATE") && channelWords[f[1]] != "":
		return Request{Kind: KindChannel, Channel: channelWords[f[1]]}, true
	case (len(f) == 3 || len(f) == 4 && (f[3] == "DAYS" || f[3] == "DAY")) && (f[0] == "UPDATE" || f[0] == "UPDATES") && f[1] == "SOAK":
		n, err := strconv.Atoi(f[2])
		if errors.Is(err, strconv.ErrRange) && strings.Trim(f[2], "0123456789") == "" {
			n, err = MaxSoakDays+1, nil
		}
		if err == nil && n >= 0 && (n > MaxSoakDays || f[2] == strconv.Itoa(n)) {
			return Request{Kind: KindSoak, Days: min(n, MaxSoakDays+1)}, true
		}
	case len(f) == 3 && f[0] == "SECURITY" && (f[1] == "UPDATES" || f[1] == "UPDATE") && (f[2] == "AUTO" || f[2] == "ASK"):
		return Request{Kind: KindSecurity, On: f[2] == "AUTO"}, true
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
const HelpText = "LOOPS OFF/ON: all spare-time work. LEARNING, SECURITY TESTS, UPDATE CHECKS OFF/ON: one part. " +
	"SPARE BUDGET 100: AI calls/day. STOP SHARING. HELP UPDATES."

// HelpUpdates is the reply to HELP UPDATES.
const HelpUpdates = "UPDATES STABLE, FAST or PINNED: which releases I offer. UPDATE SOAK 7: days other boxes test a release first. " +
	"SECURITY UPDATES AUTO or ASK."

// Confirm is the owner's one-line reply once a request took effect
// (UX-49-3; security C1 for turning work back on).
func Confirm(r Request, set Settings) string {
	switch r.Kind {
	case KindHelp:
		return HelpText
	case KindHelpUpdates:
		return HelpUpdates
	case KindChannel:
		switch r.Channel {
		case ChannelFast:
			return "Updates: fast channel. New releases are offered as they come out."
		case ChannelPinned:
			return "Updates: pinned. Nothing installs on its own; I still tell you about security fixes."
		}
		return fmt.Sprintf("Updates: stable channel. Releases are offered after other boxes have tested them for %d days.", set.Updates.Soak())
	case KindSoak:
		reply := fmt.Sprintf("Stable releases now wait %d days before I offer them.", set.Updates.Soak())
		if set.Updates.ChannelName() != ChannelStable {
			reply += " It applies once you're on UPDATES STABLE." // UX-130-3
		}
		return reply
	case KindSecurity:
		if r.On {
			return "Tested security fixes install on their own again. Reply SECURITY UPDATES ASK if this wasn't you."
		}
		return "I will ask you before I install each security fix. Reply SECURITY UPDATES AUTO to undo."
	case KindBudget:
		return fmt.Sprintf("Spare-time work may now use up to %d AI calls a day.", set.SpareCalls)
	case KindSharing:
		if r.On {
			return "Sharing is on: learned skills built from public data may be shared. Reply STOP SHARING to stop."
		}
		return "Sharing is off: nothing I learn leaves me."
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

// Text answers an owner text that is a loop setting (the owner channel's
// settings hook): ok is false for any other message, which goes on to the
// agent. The owner channel calls it only for messages from the owner's
// number, after its own control words. In a locked session (unlocked
// false) only narrowing settings are taken: anything OFF, STOP SHARING, a
// budget no higher than the current one, slower or more cautious updates,
// and HELP LOOPS, whose worst case is a pause, as for CH-11's pause words
// (UX-57-1). Turning work on, raising the budget and faster updates return
// ok false there, so the owner channel asks for the unlock (CH-14).
func (s *Scheduler) Text(ctx context.Context, msg string, unlocked bool) (reply string, ok bool) {
	r, ok := ParseText(msg)
	if !ok {
		return "", false
	}
	if !unlocked && !narrows(r, s.Settings()) {
		return "", false
	}
	if r.Kind == KindBudget && r.Calls > MaxSpareCalls {
		return fmt.Sprintf("The most is %d calls a day.", MaxSpareCalls), true
	}
	if r.Kind == KindSoak && r.Days < MinSoakDays {
		return fmt.Sprintf("The shortest soak is %d days; UPDATES FAST takes releases as they come out.", MinSoakDays), true
	}
	if r.Kind == KindSoak && r.Days > MaxSoakDays {
		return fmt.Sprintf("The longest soak is %d days.", MaxSoakDays), true
	}
	prev := s.Settings().Updates
	err := s.Set(ctx, r, unlocked)
	switch {
	case err == nil, errors.Is(err, errUnsaved):
		reply := Confirm(r, s.Settings())
		// Making updates faster again says how to undo it (security C1).
		switch {
		case r.Kind == KindSoak && r.Days < prev.Soak():
			reply += fmt.Sprintf(" Reply UPDATE SOAK %d if this wasn't you.", prev.Soak())
		case r.Kind == KindChannel && r.Channel == ChannelStable && prev.ChannelName() == ChannelPinned:
			reply += " Reply UPDATES PINNED if this wasn't you."
		case r.Kind == KindChannel && r.Channel != ChannelStable:
			// The undo names the channel the box was on (L3 on #130).
			back := prev.ChannelName()
			if back == r.Channel {
				back = ChannelStable
			}
			if r.Channel == ChannelFast {
				reply += fmt.Sprintf(" Reply UPDATES %s if this wasn't you.", strings.ToUpper(back))
			} else {
				reply += fmt.Sprintf(" Reply UPDATES %s to undo.", strings.ToUpper(back))
			}
		}
		if err != nil {
			// A narrowing is in effect at once even when it is not saved
			// (KEY-6); the owner learns it lapses on restart.
			reply += " " + unsavedReply
		}
		return reply, true
	case errors.Is(err, errWidens):
		// A racing lower made a locked session's lower a raise: it waits
		// for the unlock like any other raise (CH-14).
		return "", false
	case errors.Is(err, errNoPasskey):
		return "Raising spare-time AI use needs your passkey. Nothing changed.", true
	case errors.Is(err, ErrMoved):
		return "The spare budget changed while I waited for your passkey. Nothing changed; send it again.", true
	case errors.Is(err, errStopped):
		return "Everything is stopped, so only pauses and lower limits apply now.", true
	case errors.Is(err, errNoSharing):
		return "Sharing is not available yet.", true
	default:
		return "I could not save that setting. Try again later.", true
	}
}

// unsavedReply ends the reply to a narrowing that applied but did not save.
// In the box's own voice (CH-21).
const unsavedReply = "It is in effect now, but I could not save it, so it lapses if I restart."

// Narrows reports that msg is a loop setting a locked session takes: the
// owner channel runs it at once instead of holding it for the unlock.
func (s *Scheduler) Narrows(msg string) bool {
	r, ok := ParseText(msg)
	return ok && narrows(r, s.Settings())
}

// narrows reports a request whose worst case, from cur, is a pause.
func narrows(r Request, cur Settings) bool {
	switch r.Kind {
	case KindHelp, KindHelpUpdates:
		return true
	case KindLoops, KindSharing:
		return !r.On
	case KindBudget:
		return withinBudget(r.Calls, cur.SpareCalls)
	// Update settings narrow when they make updates slower or more
	// cautious, as UPDATE CHECKS OFF does: a later channel, a longer soak,
	// asking before security fixes.
	case KindChannel:
		return channelRank[r.Channel] >= channelRank[cur.Updates.ChannelName()]
	case KindSoak:
		return r.Days >= cur.Updates.Soak()
	case KindSecurity:
		return !r.On
	}
	return false
}

var (
	errNoSharing = errors.New("loops: sharing is not wired")
	// errWidens refuses a setting that is not a narrowing in a locked
	// session (CH-14).
	errWidens = errors.New("loops: a locked session takes only narrowing settings")
	// errStopped refuses a setting that is not a narrowing while STOP is in
	// force.
	errStopped = errors.New("loops: only narrowing settings apply during STOP")
	// errNoPasskey refuses a raise the owner's passkey did not widen
	// (KEY-6).
	errNoPasskey = errors.New("loops: raising the spare budget needs the owner's passkey")
	// errUnsaved is a narrowing that applied in memory but did not save.
	errUnsaved = errors.New("loops: setting applied but not saved")
)

// DefaultsLine is onboarding's one line on the loop defaults (LOOP-0).
func DefaultsLine(calls int64) string {
	if calls < 0 {
		return "In spare time I learn from your tasks, check myself against known problems and repair what I can, and check for updates, " +
			fmt.Sprintf("using spare plan quota beyond what you need, at most %d AI calls a day while a pay-per-token key may be used; reply LOOPS OFF to stop that.", PaidRouteCalls)
	}
	return fmt.Sprintf("In spare time I learn from your tasks, check myself against known problems and repair what I can, and check for updates, "+
		"using up to %d AI calls a day; reply LOOPS OFF to stop that.", calls)
}

// Executor is the loops executor's name, which agentosd still registers as
// a retired executor (#2801) so old journal entries for it settle. It goes
// when the journal does.
const Executor = "loops"

// state is what the scheduler persists. State saved before the journal
// round trip was removed also has seq, applied and order, which loading
// ignores.
type state struct {
	Settings Settings `json:"settings"`
}

// validate refuses a request no owner text makes.
func validate(r Request) error {
	switch r.Kind {
	case KindLoops:
		if r.Loop != "" && r.Loop.number() == 0 {
			return fmt.Errorf("loops: unknown loop %q", r.Loop)
		}
	case KindBudget:
		if r.Calls < 0 || r.Calls > MaxSpareCalls {
			return fmt.Errorf("loops: spare budget %d out of range", r.Calls)
		}
	case KindChannel:
		if _, ok := channelRank[r.Channel]; !ok {
			return fmt.Errorf("loops: unknown channel %q", r.Channel)
		}
	case KindSoak:
		if r.Days < MinSoakDays || r.Days > MaxSoakDays {
			return fmt.Errorf("loops: soak %d days out of range", r.Days)
		}
	case KindSecurity:
	default:
		return fmt.Errorf("loops: %q is not a loop setting", r.Kind)
	}
	return nil
}

// Set applies an owner setting (HLD-4): loop and update settings here,
// sharing through the change pipeline. The wiring calls it only for text
// from the owner channel or the local page, whose sender the broker
// authenticated. Set checks narrowing itself, against the settings current
// when it applies: a session not unlocked with an approval code (unlocked
// false) makes only narrowing settings (CH-14), and while STOP is in force
// only narrowings apply. A raise of the spare budget needs the owner's
// passkey (KEY-6); see setBudget.
//
// A widening that fails to save rolls back. A narrowing that fails to save
// stays in effect and returns an error wrapping errUnsaved: a narrowing
// takes effect before any further step is checked (KEY-6), and rolling back
// a lower would be a raise.
func (s *Scheduler) Set(ctx context.Context, r Request, unlocked bool) error {
	switch r.Kind {
	case KindHelp, KindHelpUpdates:
		return nil
	case KindSharing:
		if !unlocked && r.On {
			return errWidens
		}
		if s.cfg.Sharing == nil {
			return errNoSharing
		}
		return s.cfg.Sharing(ctx, r.On)
	}
	if err := validate(r); err != nil {
		return err
	}
	if r.Kind == KindBudget {
		return s.setBudget(r, unlocked)
	}
	stopped := s.cfg.Stopped()
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.st.Settings
	narrow := narrows(r, prev)
	switch {
	case !narrow && !unlocked:
		return errWidens
	case !narrow && stopped:
		return errStopped
	}
	s.st.Settings = applied(prev, r)
	if err := s.saveLocked(); err != nil {
		if !narrow {
			s.st.Settings = prev
			return err
		}
		s.appliedLocked()
		return fmt.Errorf("%w: %w", errUnsaved, err)
	}
	s.appliedLocked()
	return nil
}

// setBudget sets the spare budget. budgetMu orders budget changes, so
// narrowing is judged against the budget current when the cap changes. A
// raise asks for the owner's passkey (Spare.Prepare) before it takes
// budgetMu, so a lowering never waits on the passkey; if the cap moved while
// it waited, the raise is refused (ErrMoved) and the owner sends it again.
// A lowering commits at once.
func (s *Scheduler) setBudget(r Request, unlocked bool) error {
	sp := s.cfg.Spare
	n := SpareCap(r.Calls, sp.OutPerM)
	var prep Prepared
	raise := !withinBudget(r.Calls, s.Settings().SpareCalls)
	if raise {
		switch {
		case !unlocked:
			return errWidens
		case s.cfg.Stopped():
			return errStopped
		}
		p, err := sp.Prepare(n)
		if err != nil {
			s.cfg.Logf("loops: the spare budget was not raised: %v", err)
			return fmt.Errorf("%w: %w", errNoPasskey, err)
		}
		prep = p
	}
	s.budgetMu.Lock()
	defer s.budgetMu.Unlock()
	prev := s.Settings()
	narrow := withinBudget(r.Calls, prev.SpareCalls)
	switch {
	case !narrow && !unlocked:
		return errWidens
	case !narrow && !raise:
		// A lower when Set read the budget, a raise now: the passkey was
		// never asked.
		return ErrMoved
	case !narrow && s.cfg.Stopped():
		return errStopped
	}
	if !raise {
		p, err := sp.prepare(n, false)
		if err != nil {
			return err
		}
		prep = p
	}
	if err := sp.Commit(prep); err != nil {
		return err
	}
	s.mu.Lock()
	s.st.Settings.SpareCalls = r.Calls
	err := s.saveLocked()
	if err != nil && !narrow {
		s.st.Settings.SpareCalls = prev.SpareCalls
		s.mu.Unlock()
		// Back to the cap before the raise: a lowering, which revokes the
		// raise's keys.
		back, perr := sp.prepare(SpareCap(prev.SpareCalls, sp.OutPerM), false)
		if perr == nil {
			perr = sp.Commit(back)
		}
		if perr != nil {
			s.cfg.Logf("loops: the spare cap stayed raised after a failed save: %v", perr)
		}
		return err
	}
	s.wakeLocked()
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("%w: %w", errUnsaved, err)
	}
	return nil
}

// applied is prev with the loop or update setting r applied.
func applied(prev Settings, r Request) Settings {
	next := prev
	next.Paused = maps.Clone(prev.Paused)
	if next.Paused == nil {
		next.Paused = map[Loop]bool{}
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
	case KindChannel:
		next.Updates.Channel = r.Channel
	case KindSoak:
		next.Updates.SoakDays = r.Days
	case KindSecurity:
		next.Updates.SecurityAsk = !r.On
	}
	return next
}

// appliedLocked acts on settings just applied: a running unit whose loop
// went off stops, and the scheduler looks again.
func (s *Scheduler) appliedLocked() {
	if r := s.cur; r != nil && (s.st.Settings.Off || s.st.Settings.Paused[r.loop]) {
		// Offered again if the loop comes back on. The owner's setting:
		// not a cut a candidate caused (PE5).
		r.stopLocked(change.ErrOwnerStop)
	}
	s.wakeLocked()
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
	err = s.cfg.Store.Save(b)
	if errors.Is(err, privfile.ErrUnsynced) {
		// The new settings are in place and a restart loads them, so they
		// are applied; only a power cut before the next save could undo
		// them (#1320).
		s.cfg.Logf("loops: settings saved, but a power cut before the next save could undo them")
		return nil
	}
	return err
}
