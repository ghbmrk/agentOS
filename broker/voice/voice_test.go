package voice

import "testing"

// REQ: CH-21
func TestCH21ThirdPersonSelfReference(t *testing.T) {
	for _, bad := range []string{
		"The box is updating first.",
		"This box cannot reach the modem.",
		"The agent is starting.",
		"Agent: booked a table.",
	} {
		if OK(bad) {
			t.Fatalf("accepted %q", bad)
		}
		if len(Hits(bad)) == 0 {
			t.Fatalf("no hit for %q", bad)
		}
	}
	for _, good := range []string{
		"I am updating first.",
		"I cannot reach the modem.",
		"I am starting.",
		"Booked a table.",
		"Your agent is starting.", // owner-facing about the guest, not self
	} {
		if !OK(good) {
			t.Fatalf("rejected %q hits %v", good, Hits(good))
		}
	}
}
