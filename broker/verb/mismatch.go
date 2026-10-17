package verb

import (
	"fmt"
	"sort"
)

// DemoRun is one exercise of a declared operation against the tool's demo
// or sandbox environment, with synthetic data only (ADP-8). Effects are
// what the demo harness observed the run do at the tool, each named by
// the verb it amounts to; a run observed to do nothing has none. They come
// from the harness's own observation, never from the adapter's
// declaration (ASSUMPTIONS V3).
type DemoRun struct {
	Operation string
	Effects   []string
}

// Mismatch checks an adapter's mapping, operation name to verb, against
// its demo runs (ADP-8). An operation mapped to "" is one the owner has not
// chosen a verb for, which stays draft-only (ADP-2), so it is held to
// Draft. It returns the first operation, in name order, that blocks
// adoption and why, or "", "" when none does. An operation blocks when
// its verb is off the list, it has no run (one never exercised is not a
// pass), or a run shows an effect beyond its verb (Exceeds). A run of an
// operation the mapping does not declare blocks too, and so does an empty
// mapping.
func Mismatch(ops map[string]string, runs []DemoRun) (operation, why string) {
	if len(ops) == 0 {
		return "", "declares no operations"
	}
	ran := map[string][]DemoRun{}
	for _, r := range runs {
		ran[r.Operation] = append(ran[r.Operation], r)
	}
	names := make([]string, 0, len(ops)+len(ran))
	for op := range ops {
		names = append(names, op)
	}
	for op := range ran {
		if _, ok := ops[op]; !ok {
			names = append(names, op)
		}
	}
	sort.Strings(names)
	for _, op := range names {
		v, declared := ops[op]
		switch {
		case !declared:
			return op, "ran in the demo environment but is not declared"
		case v == "":
			v = Draft
		case !Valid(v):
			return op, fmt.Sprintf("maps to %q, which is not on the verb list", v)
		}
		if len(ran[op]) == 0 {
			return op, "was never exercised in the demo environment"
		}
		for _, r := range ran[op] {
			for _, eff := range r.Effects {
				if Exceeds(eff, v) {
					return op, fmt.Sprintf("is mapped to %s but was observed to %s in the demo environment", v, eff)
				}
			}
		}
	}
	return "", ""
}

// Exceeds reports whether an observed effect goes beyond the verb an
// operation is mapped to. The same verb never does, and neither does a
// reversible effect under an irreversible verb (a send that keeps a sent
// copy). Read is within every verb. Any other reversible effect exceeds a
// different reversible verb, and any irreversible or secret effect exceeds
// every verb but itself, so a payment mapped to send blocks. A verb off
// the list on either side exceeds.
func Exceeds(effect, mapped string) bool {
	ce, okE := classes[effect]
	cm, okM := classes[mapped]
	switch {
	case !okE || !okM:
		return true
	case effect == mapped, effect == Read:
		return false
	case ce == Reversible:
		return cm == Reversible
	default:
		return true
	}
}
