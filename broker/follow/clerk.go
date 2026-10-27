package follow

import (
	"context"
	"regexp"
	"strings"
	"unicode"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/owner"
)

// ClerkName is the follow clerk's name in a plan step and a key's root.
const ClerkName = "follow"

// A switch of update root is box configuration nobody can undo for the
// owner, so it is change-account, irreversible at the high tier (VRB-2,
// KRN-4). Its object is the digest of the root summary the page showed;
// its value is the owner's name for the source, "" to switch back to the
// project's own root.
const (
	ArgRoot = "target"
	ArgName = "value"
)

// The owner's name for a source: 1 to MaxName printable characters on one
// line, no leading or trailing space, and at most MaxNameDigits digits, so
// the name can carry a year but never a code, even spaced out (security
// R1 on #180; codes are 6 digits). It reaches the owner in broker-voiced
// texts.
const (
	MaxName       = 40
	MaxNameDigits = 4
)

// Clerk refusal details beside clerk.Check's codes.
const (
	RVerb      = "verb"      // the step is not change-account
	ROwner     = "owner"     // the plan is not the owner's own approval of this switch
	RMalformed = "malformed" // the digest or the name is not one the clerk takes
)

// PlanStep is the one step that follows the root with this digest under
// name, "" switching back to the project's own root.
func PlanStep(digest, name string) kernel.PlanStep {
	return kernel.PlanStep{Verb: key.ChangeAccount, Clerk: ClerkName, Args: map[string]string{ArgRoot: digest, ArgName: name}}
}

// Facts is the clerk's own reading of a step: a switch carries no content
// class or flow label the clerk vouches for, and moves no money (KEY-2).
func (x *Executor) Facts(s key.Step) (string, []string, int64) { return "", nil, clerk.Amount(s) }

// Do switches to the held root the step names, once its own checks pass
// (CLK-2): the key against the clerk's anchors on the guard clock's Latest,
// and the plan as the owner's own approval of this exact switch, signed by
// a passkey under a bare root (CH-10's tier 4; KRN-4 lets no standing key
// cover it here). A switch the box already holds is answered ok without
// acting again, so an answer lost after the switch never switches twice
// (KRN-8).
func (x *Executor) Do(r kernel.Request, v kernel.View) kernel.Result {
	ctx := context.Background()
	if rf := clerk.Check(x.cfg.Anchors, ClerkName, x.Facts, x.latest(ctx).UnixMilli(), r, v); rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	st := r.Step()
	if st.Verb != key.ChangeAccount {
		return kernel.Result{Outcome: "failed", Detail: RVerb}
	}
	if len(r.Plan.Key.Links) != 0 {
		return kernel.Result{Outcome: "failed", Detail: ROwner}
	}
	digest, name := st.Args[ArgRoot].Value, st.Args[ArgName].Value
	if !hexDigest(digest) || name != "" && !NameOK(name) {
		return kernel.Result{Outcome: "failed", Detail: RMalformed}
	}
	if s, ev := x.settled(digest, name); s == switchedOK {
		return kernel.Result{Outcome: "ok", Detail: "already: " + ev}
	}
	s, ev := x.switchTo(ctx, digest, name)
	switch s {
	case switchedOK:
		return kernel.Result{Outcome: "ok", Detail: ev}
	case switchedUnknown:
		return kernel.Result{Outcome: "unknown", Detail: ev}
	}
	return kernel.Result{Outcome: "failed", Detail: ev}
}

// Probe answers from the box's own trusted root and source, never from
// what this process held, so it answers the same after a restart: done
// when the box follows the step's root under its name, notdone when it
// trusts neither, unknown otherwise. A done switch alerts the owner again
// (at least once, OWN-4): the alert of a switch whose answer was lost may
// never have gone out.
func (x *Executor) Probe(r kernel.Request, _ kernel.View) kernel.Result {
	st := r.Step()
	if st.Clerk != ClerkName || st.Verb != key.ChangeAccount {
		return kernel.Result{Outcome: "unknown", Detail: RVerb}
	}
	digest, name := st.Args[ArgRoot].Value, st.Args[ArgName].Value
	switch s, ev := x.settled(digest, name); s {
	case switchedOK:
		ctx := context.Background()
		return kernel.Result{Outcome: "done", Detail: ev + x.alert(ctx, name, x.latest(ctx))}
	case notSwitched:
		return kernel.Result{Outcome: "notdone", Detail: ev}
	default:
		return kernel.Result{Outcome: "unknown", Detail: ev}
	}
}

// hexDigest is 64 lower-case hex characters.
func hexDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// lookAlike matches the project's name in any of the CH-12 folds (case,
// accents, confusable skeletons, ignorable characters), with or without
// its space, so a named follow never reads as switching back (#957).
var lookAlike = []*regexp.Regexp{
	regexp.MustCompile(owner.FoldPattern("agentos project")),
	regexp.MustCompile(owner.FoldPattern("agentosproject")),
}

// NameOK reports whether the clerk takes name for a named follow: the
// length, character and digit rules above, and no look-alike of the
// project's own name (#957, CH-10).
func NameOK(name string) bool {
	n, digits := 0, 0
	for _, c := range name {
		if !unicode.IsPrint(c) {
			return false
		}
		if unicode.IsDigit(c) {
			digits++
		}
		n++
	}
	if n == 0 || n > MaxName || digits > MaxNameDigits || strings.TrimSpace(name) != name {
		return false
	}
	for _, f := range append(owner.CheckFolds(name), strings.ToLower(name)) {
		for _, re := range lookAlike {
			if re.MatchString(f) {
				return false
			}
		}
	}
	return true
}
