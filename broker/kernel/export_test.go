package kernel

import "github.com/ghbmrk/agentos/broker/kernel/key"

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
