package kernel

import (
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// SendCheck is sendCheck at one time, for the external tests.
func SendCheck(s *State, p *PlanState, st *StepState, i int, now int64) *key.Refusal {
	return sendCheck(s, p, st, i, At(now))
}

// NextAt and AdmitAt are Next and Admit at a reading, for the external tests.
var (
	NextAt  = next
	AdmitAt = admit
)

// Emit logs an entry as the kernel would, for the tests that need a log
// shape the kernel no longer writes.
func Emit(k *Kernel, now int64, typ string, body any) error {
	_, err := k.emit(At(now), typ, body)
	return err
}

// GraphReach is the classes clerk's keys reach through the declarations.
func GraphReach(s *State, clerk string) []key.Asset { return s.graphReach(clerk) }

// Reached is the sorted nodes node reaches, itself included; nil when no
// declaration names it.
func Reached(s *State, node string) []string {
	var out []string
	for id := range s.reached(node) {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
