package owner

import "testing"

// REQ: CH-15, CH-19
// A reply to the owner's message is conversation: in quiet hours with
// the hour's texts spent it goes at once, behind the agent prefix, is
// never held and spends nothing. A secret-shaped reply still becomes the
// pointer.
func TestConverseIsNeverPaced(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	for i := 0; i < DefaultTextsPerHour; i++ {
		if err := r.ch.Post(ClassSecurity, "Security alert."); err != nil {
			t.Fatal(err)
		}
	}
	r.sentTexts()
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d, want spent", a)
	}
	if err := r.ch.Converse("Your invoice is drafted."); err != nil {
		t.Fatal(err)
	}
	if err := r.ch.Converse("Your login code is 482913."); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) != 2 || got[0] != AgentPrefix+"Your invoice is drafted." || got[1] != Hidden {
		t.Fatalf("Converse in quiet hours sent %q, want the prefixed reply and the pointer", got)
	}
	if len(r.held()) != 0 {
		t.Fatalf("held %d, want none", len(r.held()))
	}
	r.ch.mu.Lock()
	n := len(r.ch.codes.st.Sent)
	r.ch.mu.Unlock()
	if n != DefaultTextsPerHour {
		t.Fatalf("%d sends counted, want %d: conversation counted", n, DefaultTextsPerHour)
	}
}
