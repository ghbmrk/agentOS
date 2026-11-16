package key

import "fmt"

// Code is a refusal code. Its one field is unexported, so only this package
// makes a Code: every code there is, is one of the values declared below
// (KEY-refusal-code, #6023). A Code outside this package can only be copied
// from them, or be the zero Code, which names no code ("" on the wire). A
// Code reads and writes as its name, the same JSON string as before, and
// decoding a name not declared here fails, so a log entry or socket message
// cannot introduce one.
type Code struct{ name string }

// The declared codes: key's own, then the kernel's, then the clerks'.
// Other packages may alias them (var CPlan = key.CPlan).
var (
	RMalformed = Code{"malformed"}
	RStopped   = Code{"stopped"}
	RRevoked   = Code{"revoked"}
	RPaused    = Code{"paused"}
	RExpired   = Code{"expired"}
	RClerk     = Code{"clerk"}
	RVerb      = Code{"verb"}
	RArg       = Code{"arg"}
	RContent   = Code{"content"}
	RLabels    = Code{"labels"}
	RSpendTask = Code{"spend-task"}
	RSpendDay  = Code{"spend-day"}
	RRate      = Code{"rate"}
	RUses      = Code{"uses"}
	// RTask is a step or a metered call for another task than the key's
	// (KRN-5), and, as the kernel's CTask, a key whose task is not live: one
	// wire name, so one code.
	RTask = Code{"task"}
	RRung = Code{"rung"} // the step's owner events reached a lower rung than the key asks (CH-3)

	CKey       = Code{"key"}          // the chain does not verify
	CUngranted = Code{"not-granted"}  // the passkey never granted the key's root or first link into the log
	CGrantHeld = Code{"grant-held"}   // the grant is still in its hold (D-146)
	CCutOff    = Code{"cut-off"}      // a passkey cut off since narrowed the key (Narrow)
	CPlan      = Code{"plan"}         // the plan is malformed
	CDuplicate = Code{"duplicate"}    // the same effect within 24 hours needs a fresh owner key (KRN-8)
	CClerk     = Code{"no-clerk"}     // the plan's clerk is not registered
	CPool      = Code{"pool"}         // the pool is at the owner's reserve until it resets (RES-5)
	CNotHeld   = Code{"not-held"}     // no hold on that task
	CExtension = Code{"extension"}    // the key cannot extend this hold
	CHeld      = Code{"held"}         // the task is held until the owner extends it (LOG-7)
	CBroken    = Code{"log-broken"}   // a write failed: no spend until the log is reopened (KRN-5)
	CErased    = Code{"erased"}       // the owner erased a subject the plan's lineage read before submitting it (LOG-4)
	CTrip      = Code{"trip"}         // the plan is a trip: refused, and the trip logged
	CTripped   = Code{"tripped"}      // planning is stopped after a trip until the owner resumes
	CTask      = RTask                // the key's task is not live
	CCosign    = Code{"needs-cosign"} // a very large one-off lacks its second passkey
	CInFlight  = Code{"in-flight"}    // the worst case fits once the calls in flight settle
	COwner     = Code{"owner"}        // the owner cancelled the plan (OWN-17)

	RClaim       = Code{"claim"}        // a claim the clerk's facts contradict, or no facts to judge it
	RDispatch    = Code{"dispatch"}     // the log has no such step in flight
	RHold        = Code{"hold"}         // the step was not held, or its window is not over
	DPlanUnknown = Code{"plan-unknown"} // the call names no plan this clerk serves; nothing done
)

// declared is every code by name. It is built from copies taken at package
// initialisation, so a later assignment to an exported variable above can
// neither add a name nor change what a name decodes to.
var declared = func() map[string]Code {
	m := map[string]Code{}
	for _, c := range []Code{
		RMalformed, RStopped, RRevoked, RPaused, RExpired, RClerk, RVerb, RArg,
		RContent, RLabels, RSpendTask, RSpendDay, RRate, RUses, RTask, RRung,
		CKey, CUngranted, CGrantHeld, CCutOff, CPlan, CDuplicate, CClerk, CPool,
		CNotHeld, CExtension, CHeld, CBroken, CErased, CTrip, CTripped, CCosign,
		CInFlight, COwner,
		RClaim, RDispatch, RHold, DPlanUnknown,
	} {
		if _, dup := m[c.name]; dup {
			panic("key: refusal code declared twice: " + c.name)
		}
		m[c.name] = c
	}
	return m
}()

// Codes is every declared code, keyed by name: a copy, for pins and tests.
func Codes() map[string]Code {
	m := make(map[string]Code, len(declared))
	for n, c := range declared {
		m[n] = c
	}
	return m
}

// String is the code's name; the zero Code's is "".
func (c Code) String() string { return c.name }

// IsZero reports whether c names no code.
func (c Code) IsZero() bool { return c.name == "" }

// MarshalText writes the code's name.
func (c Code) MarshalText() ([]byte, error) { return []byte(c.name), nil }

// UnmarshalText reads a declared code's name, or "" as the zero Code. Any
// other name fails.
func (c *Code) UnmarshalText(b []byte) error {
	d, err := ParseCode(string(b))
	if err != nil {
		return err
	}
	*c = d
	return nil
}

// ParseCode is the declared code named n, or the zero Code for "".
func ParseCode(n string) (Code, error) {
	if n == "" {
		return Code{}, nil
	}
	c, ok := declared[n]
	if !ok {
		return Code{}, fmt.Errorf("key: undeclared refusal code %q", n)
	}
	return c, nil
}
