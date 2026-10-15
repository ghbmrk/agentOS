package modelroute

import (
	"errors"
	"strings"
)

// KindPlan is the route kind of a provider-agent plan route (CAP-9,
// CAP-11): a whole subtask handed to the owner's plan through the
// provider's own agent CLI, beside the API-key kinds. A used-up plan or a
// failed run falls back over the remaining granted routes.
const KindPlan = "plan"

// ErrNoPlanLogin is the vault process's answer when no plan login is stored
// for a provider (egress.ErrNoLogin): the owner has not signed in. It is a
// refusal that sets the sign-in line, not a fallback, and not a locked
// vault.
var ErrNoPlanLogin = errors.New("no plan login stored")

// noLoginText is egress.ErrNoLogin's text, which the control socket writes
// as the body of its 500 (cmd/agentos-egress workerroute.go).
const noLoginText = "no plan login stored"

func isNoLogin(body string) bool { return strings.TrimSpace(body) == noLoginText }

// FallsBack reports whether err from the route control is a condition the
// plan route falls back on: a 503 from a locked, stalled or contended route
// (ErrVaultLocked, #1857). Nothing else is.
func FallsBack(err error) bool { return errors.Is(err, ErrVaultLocked) }
