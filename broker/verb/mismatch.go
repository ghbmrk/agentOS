package verb

// DemoRun is one exercise of a declared operation against the tool's
// demo or sandbox, with synthetic data only (ADP-8). Outbound means the
// run caused an effect that left the sandbox.
type DemoRun struct {
	Operation string
	Verb      string
	Outbound  bool
}

// Mismatch reports the first operation whose demo run left the sandbox
// even though the adapter mapped it as read or draft. That adapter is
// not adopted. An outbound run of a verb that is not on the list blocks
// too: an unknown mapping is not a pass. A send, or any other listed
// irreversible verb, is expected to leave the sandbox, so it is not a
// mismatch.
func Mismatch(runs []DemoRun) (operation string, blocked bool) {
	for _, r := range runs {
		if !r.Outbound {
			continue
		}
		switch r.Verb {
		case Read, Draft:
			return r.Operation, true
		default:
			if !Valid(r.Verb) {
				return r.Operation, true
			}
		}
	}
	return "", false
}
