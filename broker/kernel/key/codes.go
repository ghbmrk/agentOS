package key

import (
	"fmt"
	"maps"
)

// Code is a refusal code declared below, or the zero Code ("", none) (#6023). Its
// field is unexported: no other package makes one, and it decodes only by name.
type Code struct{ name string }

// The declared codes (key's, the kernel's, the clerks'); others alias them.
var (
	RMalformed   = code("malformed")
	RStopped     = code("stopped")
	RRevoked     = code("revoked")
	RPaused      = code("paused")
	RExpired     = code("expired")
	RClerk       = code("clerk")
	RVerb        = code("verb")
	RArg         = code("arg")
	RContent     = code("content")
	RLabels      = code("labels")
	RSpendTask   = code("spend-task")
	RSpendDay    = code("spend-day")
	RRate        = code("rate")
	RUses        = code("uses")
	RTask        = code("task")         // a step or call for another task than the key's (KRN-5), or (CTask) a key whose task is not live
	RRung        = code("rung")         // the step's owner events reached a lower rung than the key asks (CH-3)
	CKey         = code("key")          // the chain does not verify
	CUngranted   = code("not-granted")  // the passkey never granted the key's root or first link into the log
	CGrantHeld   = code("grant-held")   // the grant is still in its hold (D-146)
	CCutOff      = code("cut-off")      // a passkey cut off since narrowed the key (Narrow)
	CPlan        = code("plan")         // the plan is malformed
	CDuplicate   = code("duplicate")    // the same effect within 24 hours needs a fresh owner key (KRN-8)
	CClerk       = code("no-clerk")     // the plan's clerk is not registered
	CPool        = code("pool")         // the pool is at the owner's reserve until it resets (RES-5)
	CNotHeld     = code("not-held")     // no hold on that task
	CExtension   = code("extension")    // the key cannot extend this hold
	CHeld        = code("held")         // the task is held until the owner extends it (LOG-7)
	CBroken      = code("log-broken")   // a write failed: no spend until the log is reopened (KRN-5)
	CErased      = code("erased")       // the owner erased a subject the plan's lineage read before submitting it (LOG-4)
	CTrip        = code("trip")         // the plan is a trip: refused, and the trip logged
	CTripped     = code("tripped")      // planning is stopped after a trip until the owner resumes
	CTask        = RTask                // the key's task is not live
	CCosign      = code("needs-cosign") // a very large one-off lacks its second passkey
	CInFlight    = code("in-flight")    // the worst case fits once the calls in flight settle
	COwner       = code("owner")        // the owner cancelled the plan (OWN-17)
	RClaim       = code("claim")        // a claim the clerk's facts contradict, or no facts to judge it
	RDispatch    = code("dispatch")     // the log has no such step in flight
	RHold        = code("hold")         // the step was not held, or its window is not over
	DPlanUnknown = code("plan-unknown") // the call names no plan this clerk serves; nothing done
)

// declared is every code by name, filled by code: reassigning a var above changes no decoding.
var declared = map[string]Code{}

func code(n string) Code { declared[n] = Code{n}; return declared[n] }

// Codes is every declared code, keyed by name: a copy.
func Codes() map[string]Code { return maps.Clone(declared) }

// String and MarshalText give the code's name, IsZero whether it names none.
func (c Code) String() string               { return c.name }
func (c Code) IsZero() bool                 { return c.name == "" }
func (c Code) MarshalText() ([]byte, error) { return []byte(c.name), nil }

// UnmarshalText reads a declared code's name, or "" as the zero Code.
func (c *Code) UnmarshalText(b []byte) error {
	d, ok := declared[string(b)]
	if !ok && len(b) > 0 {
		return fmt.Errorf("key: undeclared refusal code %q", b)
	}
	*c = d
	return nil
}
