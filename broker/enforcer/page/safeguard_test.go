package page

// REQ: NET-2, NET-4

import (
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// NET-2 Safety devices (#3872): naming a garage door's close shows, on the
// screen the owner signs, that the door stops and reverses when something
// is in its way and warns before it closes, and dropping either says so,
// so the owner states what the policy then relies on. Revert mutant:
// describeSafeguards writing nothing fails every case.
func TestSafeguardsShown(t *testing.T) {
	rev, warn := policy.SafeguardObstructionReversal, policy.SafeguardPreCloseWarning
	door := func(secure string, g ...string) policy.Document {
		d := home(1)
		d.Devices = append(d.Devices, policy.Device{ID: "garage", Network: policy.NetDevices, Class: policy.ClassGarageDoor, Secure: secure, Safeguards: g})
		return d
	}
	const (
		reverses = "Record that garage stops and reverses when something is in its way: check it does before you sign."
		warns    = "Record that garage warns before it closes: check it does before you sign."
		closes   = "Let garage's command close apply at once, with no passkey."
	)
	for _, c := range []struct {
		name      string
		old, next policy.Document
		want      []string
	}{
		{"added and named", home(1), door("close", rev, warn), []string{reverses, warns, closes}},
		{"named later", door("", rev, warn), door("close", rev, warn), []string{"Change garage's one secure command from none to close."}},
		{"both recorded and named", door(""), door("close", rev, warn), []string{reverses, warns, "Change garage's one secure command from none to close."}},
		{"one dropped", door("", rev, warn), door("", rev), []string{"Stop recording that garage warns before it closes."}},
		{"unnamed, both dropped", door("close", rev, warn), door(""), []string{
			"Stop recording that garage stops and reverses when something is in its way.",
			"Stop recording that garage warns before it closes.",
			"Change garage's one secure command from close to none.",
		}},
	} {
		if _, err := policy.Encode(c.next); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := Describe(c.old, c.next, zone)
		for _, w := range c.want {
			if !slices.Contains(got, w) {
				t.Errorf("%s: no line %q in %q", c.name, w, got)
			}
		}
		// Each safeguard line comes before the naming it allows.
		if i, j := slices.Index(got, warns), slices.Index(got, closes); i >= 0 && j >= 0 && i > j {
			t.Errorf("%s: the naming is shown before its safeguards: %q", c.name, got)
		}
	}
}

// Describe reads documents no check has passed yet, so a safeguard off the
// closed list is still shown, in printable ASCII, and the caller's document
// is not rewritten while it is. Revert mutants: safeguardWords dropping an
// unknown name, or clone not copying the set.
func TestUnknownSafeguardShownPlain(t *testing.T) {
	odd := "light\u202ecurtain"
	next := home(1)
	next.Devices = append(next.Devices, policy.Device{ID: "garage", Network: policy.NetDevices, Class: policy.ClassGarageDoor, Safeguards: []string{odd}})
	got := Describe(home(1), next, zone)
	want := `Record that garage has the safeguard "light\u202ecurtain": check it does before you sign.`
	if !slices.Contains(got, want) {
		t.Errorf("no line %q in %q", want, got)
	}
	if g := next.Devices[len(next.Devices)-1].Safeguards[0]; g != odd {
		t.Errorf("Describe rewrote the caller's safeguard to %q", g)
	}
}
