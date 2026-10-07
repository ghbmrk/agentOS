package clock

import "testing"

type flushCount struct{ n int }

func (f *flushCount) Flush() { f.n++ }

// REQ: TIM-1
func TestTIM1FlushBeforePlannedRestart(t *testing.T) {
	BeforePlannedRestart(nil) // must not panic
	f := &flushCount{}
	BeforePlannedRestart(f)
	if f.n != 1 {
		t.Fatalf("Flush called %d times", f.n)
	}
}
