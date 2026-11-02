package guest

import (
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// codes are the fixed codes a plan's rejection or a step's clerk answer may
// carry to the guest, listed by value (PLN-1, #3262): a clerk whose detail
// is one lowercase word taken from a mail or a page has the shape of a code,
// so shape alone cannot keep content from the planner. The kernel's and the
// key's refusal codes are named here; the clerks' are written out, since
// this package does not import the clerks, and codes_test.go reads the
// clerks' sources and holds the list to the codes found there, both ways. A code not listed is
// dropped: a new clerk code reaches the guest only once it is added here.
var codes = set(
	// The kernel's refusal codes: a rejected plan, or a step a clerk
	// refused for the kernel's own check (a clerk's rf.Code).
	kernel.CKey, kernel.CUngranted, kernel.CGrantHeld, kernel.CCutOff, kernel.CPlan,
	kernel.CDuplicate, kernel.CClerk, kernel.CPool, kernel.CNotHeld, kernel.CExtension,
	kernel.CHeld, kernel.CBroken, kernel.CInFlight, kernel.CTask, kernel.CCosign,
	kernel.CTrip, kernel.CTripped,
	key.RMalformed, key.RStopped, key.RRevoked, key.RPaused, key.RExpired, key.RClerk,
	key.RVerb, key.RArg, key.RContent, key.RLabels, key.RSpendTask, key.RSpendDay,
	key.RRate, key.RUses, key.RTask,

	// The kernel's clerk wire (kernel/proc).
	"unreachable", "lost", "view", "too-large",

	// broker/clerk: its refusals, the exit's answers and sign-ins.
	"claim", "dispatch", "hold", "fault", "toolarge",
	"sent", "done", "undeclared", "arg", "credential", "blocked", "noanswer",
	"inflight", "auth", "declined", "notfound", "rejected", "timeout", "conflict",
	"busy", "redirect", "server", "refresh", "reconnect",
	"signedin", "nosignin", "notours", "state", "use", "refused", "scope",
	"nogrant", "exchange", "revoked", "norevoke", "noaccount", "registered",

	// broker/clerk/run.
	"not-owner-approved", "grant-not-staged", "not-this-clerk",
	"no-account", "sign-in-refused", "no-sign-in", "address", "notgmail",
	"plan-not-allowed", "plan-consent", "signin-busy", "signin-code", "signin-failed",
	"signin-timed-out", "signin-stopped", "requalify", "plan-refused", "plan-meter", "plan-unknown",

	// broker/clerk/model: an API call's refusals and failures.
	"private", "nokey", "body", "upstream", "answer",

	// broker/clerk/plan.
	"plan-unmetered", "plan-body", "plan-undeclared", "plan-placeholder", "plan-stopped",
	"plan-unswappable", "plan-exchange", "plan-save", "plan-encoded", "plan-stale", "plan-ended", "plan-secret",

	// broker/clerk/inbox and its mailboxes.
	"unconfirmed", "unclassified", "not-dispatched", "unknown-mail", "bad-label",
	"not-trashable", "no-alert-guard", "alert", "trash-not-restorable", "unknown-sender",
	"no-longer-eligible", "outside-key",
	"renumbered", "no-move", "no-trash-folder", "no-poster", "bad-flag", "no-uidnext",
	"bad-unsubscribe-url", "egress-refused", "post-not-sent", "gmail-not-sent",

	// broker/clerk/line.
	"unavailable", "planner-number", "not-a-contact", "not-owner-fixed", "needs-contact",
	"own-number", "not-a-number", "cancelled", "not-taken", "provider-refused",
	"may-have-been-sent",

	// broker/browser and broker/follow/followclerk.
	"unapproved", "verb", "owner", "malformed",
)

func set(cs ...string) map[string]bool {
	m := make(map[string]bool, len(cs))
	for _, c := range cs {
		m[c] = true
	}
	return m
}

// code is s when it is a listed code; anything else, such as a browser
// clerk's page snapshot or a word from a mail, never reaches the guest
// (PLN-1).
func code(s string) string {
	if !codes[s] {
		return ""
	}
	return s
}
