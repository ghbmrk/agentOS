package verb

import "testing"

// REQ: ADP-8

// A draft or a read that sends in the demo environment blocks adoption.
// A send that sends does not, and a read that stays inside does not.
func TestADP8ADraftThatSendsBlocksAdoption(t *testing.T) {
	runs := []DemoRun{
		{Operation: "list", Verb: Read, Outbound: false},
		{Operation: "save", Verb: Draft, Outbound: true},
		{Operation: "deliver", Verb: Send, Outbound: true},
	}
	op, blocked := Mismatch(runs)
	if !blocked || op != "save" {
		t.Fatalf("got %q blocked=%v", op, blocked)
	}
	if _, blocked = Mismatch([]DemoRun{{Operation: "list", Verb: Read}}); blocked {
		t.Fatal("a read that stays inside blocked")
	}
	if _, blocked = Mismatch([]DemoRun{{Operation: "deliver", Verb: Send, Outbound: true}}); blocked {
		t.Fatal("a send that sends blocked")
	}
	if op, blocked = Mismatch([]DemoRun{{Operation: "mystery", Verb: "frob", Outbound: true}}); !blocked || op != "mystery" {
		t.Fatalf("unknown verb: %q blocked=%v", op, blocked)
	}
	if _, blocked = Mismatch([]DemoRun{{Operation: "mystery", Verb: "frob"}}); blocked {
		t.Fatal("an unknown verb that did not send blocked")
	}
}
