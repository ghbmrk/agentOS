package provagent

import "fmt"

// Reason is a closed refusal reason. Every refusal a guest sees is one of
// these, never free text.
type Reason string

const (
	Unqualified     Reason = "unqualified"
	OptInRequired   Reason = "opt-in-required"
	Ungranted       Reason = "ungranted"
	Unsigned        Reason = "unsigned"
	PrivateUnmarked Reason = "private-unmarked"
	PoolAtReserve   Reason = "pool-at-reserve"
	// Fallback outcomes (CAP-9): the caller tries another granted route.
	UsedUp       Reason = "used-up"
	LoginRefused Reason = "login-refused"
	VaultLocked  Reason = "vault-locked" // the owner's vault is locked: the owner can unlock it
	RouteBusy    Reason = "route-busy"   // the route is stalled or contended (#1857)
	Failed       Reason = "failed"
	TimedOut     Reason = "timed-out"
	// Withheld: the result carried a credential format (CRED-7).
	Withheld Reason = "result-withheld"
	// Stopped: the owner's STOP held or ended the run (OP-6). Final: no
	// route runs under STOP, so CAP-9 tries none.
	Stopped Reason = "stopped"
)

// Reasons is every closed reason, for the wiring's mapping onto the guest's
// texts.
func Reasons() []Reason {
	return []Reason{Unqualified, OptInRequired, Ungranted, Unsigned, PrivateUnmarked, PoolAtReserve,
		UsedUp, LoginRefused, VaultLocked, RouteBusy, Failed, TimedOut, Withheld, Stopped}
}

// Refusal is a run that did not return a result.
type Refusal struct{ Reason Reason }

func (r *Refusal) Error() string { return fmt.Sprintf("provider_run: %s", r.Reason) }

func refuse(r Reason) error { return &Refusal{r} }

// FallsBack reports whether err is an outcome CAP-9 answers by trying the
// remaining granted routes: a used-up plan, a refused login, a busy or
// locked route, a failed or timed-out run. Gate refusals, a withheld
// result and a stopped run are final.
func FallsBack(err error) bool {
	if r, ok := err.(*Refusal); ok {
		switch r.Reason {
		case UsedUp, LoginRefused, VaultLocked, RouteBusy, Failed, TimedOut, PoolAtReserve:
			return true
		}
	}
	return false
}

// Gate is the qualification gate: what the broker knows of the image and
// the owner when a run is asked for.
type Gate struct {
	ImageVersion string // the CLI version the image pins
	Consent      bool   // the owner's recorded consent for this provider (CRED-5c)
}

// Check is nil when d may run. A verdict of unclear is the Claude opt-in's
// to lift (#1380), so here it always refuses.
func (g Gate) Check(d Declaration) error {
	if d.Q.Verdict == Unclear {
		return refuse(OptInRequired)
	}
	if !d.Q.Complete() || d.Q.CLIVersion != g.ImageVersion {
		return refuse(Unqualified)
	}
	switch d.Q.Verdict {
	case Allowed:
		return nil
	case Unconfirmed:
		if g.Consent {
			return nil
		}
	}
	return refuse(Unqualified)
}
