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

// Fold folds one entry of type typ and body b onto s as the log's next, for
// the tests of a fold without a kernel.
func Fold(s *State, typ string, b []byte) error {
	return s.Apply(Entry{Seq: s.Seq + 1, Type: typ, V: schema[typ], Body: b})
}

// Reached is the node set clerk's node reaches over s's declarations.
func Reached(s *State, clerk string) map[string]bool { return s.decl.reached(clerk) }
