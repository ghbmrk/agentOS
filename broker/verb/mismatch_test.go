package verb

import "testing"

// REQ: ADP-8, ADP-2

// A draft or a read that sends in the demo environment blocks adoption.
// A send that sends does not, and a read that stays inside does not.
func TestADP8ADraftThatSendsBlocksAdoption(t *testing.T) {
	ops := map[string]string{"list": Read, "save": Draft, "deliver": Send}
	runs := []DemoRun{
		{Operation: "list", Effects: []string{Read}},
		{Operation: "save", Effects: []string{Draft, Send}},
		{Operation: "deliver", Effects: []string{Draft, Send}},
	}
	if op, why := Mismatch(ops, runs); why == "" || op != "save" {
		t.Fatalf("got %q %q", op, why)
	}
	if _, why := Mismatch(map[string]string{"list": Read}, []DemoRun{{Operation: "list"}}); why != "" {
		t.Fatalf("a read that stays inside blocked: %s", why)
	}
	if _, why := Mismatch(map[string]string{"deliver": Send}, []DemoRun{{Operation: "deliver", Effects: []string{Send}}}); why != "" {
		t.Fatalf("a send that sends blocked: %s", why)
	}
	if op, why := Mismatch(map[string]string{"mystery": "frob"}, []DemoRun{{Operation: "mystery"}}); why == "" || op != "mystery" {
		t.Fatalf("a verb off the list passed: %q %q", op, why)
	}
	if op, why := Mismatch(map[string]string{"list": Read}, []DemoRun{{Operation: "list", Effects: []string{"frob"}}}); why == "" || op != "list" {
		t.Fatalf("an effect off the list passed: %q %q", op, why)
	}
}

// Any outbound effect from a Reversible verb blocks, whatever its name:
// an operation mapped to organize that sends is a gate bypass, and so is
// a read that sends.
func TestADP8AReversibleVerbThatSendsBlocksAdoption(t *testing.T) {
	for _, v := range []string{Read, Draft, Organize} {
		op, why := Mismatch(map[string]string{"deliver": Send, "tidy": v}, []DemoRun{
			{Operation: "deliver", Effects: []string{Send}},
			{Operation: "tidy", Effects: []string{Send}},
		})
		if why == "" || op != "tidy" {
			t.Fatalf("outbound %s: got %q %q", v, op, why)
		}
	}
	if _, why := Mismatch(map[string]string{"tidy": Organize}, []DemoRun{{Operation: "tidy", Effects: []string{Organize}}}); why != "" {
		t.Fatalf("an organize that stays inside blocked: %s", why)
	}
	for v, c := range classes {
		_, why := Mismatch(map[string]string{"op": v}, []DemoRun{{Operation: "op", Effects: []string{Send}}})
		if want := c == Reversible || v != Send; (why != "") != want {
			t.Fatalf("%s that sends: blocked=%v, want %v", v, why != "", want)
		}
	}
}

// Brief item 6: an effect stricter than the mapped verb blocks even when
// both are irreversible, so a payment mapped to send blocks (the owner may
// pre-allow send, ADP-9). A secret effect blocks under any other verb.
func TestADP8AnEffectBeyondItsIrreversibleVerbBlocks(t *testing.T) {
	cases := []struct {
		mapped, effect string
		blocks         bool
	}{
		{Send, Buy, true},
		{Send, Share, true},
		{Post, Send, true},
		{Buy, RevealSecret, true},
		{Send, ChangeAccount, true},
		{Buy, Buy, false},
		{Send, Draft, false}, // a send that also keeps a sent copy
		{Send, Read, false},
		{Draft, Organize, true},
		{Organize, Draft, true},
		{Draft, Read, false},
		{RevealSecret, RevealSecret, false},
	}
	for _, c := range cases {
		_, why := Mismatch(map[string]string{"op": c.mapped}, []DemoRun{{Operation: "op", Effects: []string{c.effect}}})
		if (why != "") != c.blocks {
			t.Errorf("%s mapped, %s observed: blocked=%v, want %v (%s)", c.mapped, c.effect, why != "", c.blocks, why)
		}
	}
}

// Brief item 5: every declared operation needs a demo run; one never
// exercised is not a pass. A run of an operation the adapter does not
// declare blocks too, since nothing maps it to a verb.
func TestADP8AnOperationNeverExercisedBlocks(t *testing.T) {
	ops := map[string]string{"list": Read, "deliver": Send}
	if op, why := Mismatch(ops, []DemoRun{{Operation: "list"}}); why == "" || op != "deliver" {
		t.Fatalf("missing run: got %q %q", op, why)
	}
	if op, why := Mismatch(ops, nil); why == "" || op != "deliver" {
		t.Fatalf("no runs: got %q %q", op, why)
	}
	if _, why := Mismatch(map[string]string{}, nil); why == "" {
		t.Fatal("an adapter with no operations passed")
	}
	runs := []DemoRun{{Operation: "list"}, {Operation: "deliver", Effects: []string{Send}}, {Operation: "pay", Effects: []string{Buy}}}
	if op, why := Mismatch(ops, runs); why == "" || op != "pay" {
		t.Fatalf("undeclared run: got %q %q", op, why)
	}
	if _, why := Mismatch(ops, runs[:2]); why != "" {
		t.Fatalf("every operation run and within its verb blocked: %s", why)
	}
}

// ADP-2: an unmapped operation stays draft-only until the owner chooses,
// so the check holds it to Draft: one that sends blocks, one that drafts
// does not.
func TestADP8AnUnmappedOperationIsHeldToDraft(t *testing.T) {
	ops := map[string]string{"odd": ""}
	if op, why := Mismatch(ops, []DemoRun{{Operation: "odd", Effects: []string{Send}}}); why == "" || op != "odd" {
		t.Fatalf("unmapped that sends: got %q %q", op, why)
	}
	if _, why := Mismatch(ops, []DemoRun{{Operation: "odd", Effects: []string{Draft}}}); why != "" {
		t.Fatalf("unmapped that drafts blocked: %s", why)
	}
}
