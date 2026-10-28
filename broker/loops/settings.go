package loops

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
)

// The loop settings texts (LOOP-0, CH-11). The scheduler that applied them
// went with the change pipeline (#2785, MIG-4-untrusted-change-c2);
// agentosd's learn-state sweep still reads them (learnstate.go).

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

// channelWords are the channels in owner texts.
var channelWords = map[string]string{"STABLE": ChannelStable, "FAST": ChannelFast, "PINNED": ChannelPinned}

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

// Executor is the loops executor's name, which agentosd still registers as
// a retired executor (#2801) so old journal entries for it settle. It goes
// when the journal does.
const Executor = "loops"
