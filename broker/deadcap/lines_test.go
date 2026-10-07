package deadcap

import (
	"strings"
	"testing"
)

// REQ: OP-9

func TestOP9StatusNamesEveryDeadCapability(t *testing.T) {
	caps := []Cap{
		{Name: "Learning", Kind: Host, Fix: "this PC needs more memory", Sticky: true},
		{Name: "Mail", Kind: Config, Fix: "connect mail on the Wi-Fi page", Sticky: true},
		{Name: "Security update 12", Kind: Held, Fix: "install it from the digest", Sticky: true},
		{Name: "Spare-time work", Kind: OwnerOpt, Fix: "text LOOPS ON", Sticky: false},
	}
	for _, c := range caps {
		line := StatusLine(c)
		if !strings.Contains(line, c.Name) || !strings.Contains(line, "off") {
			t.Fatalf("status: %q", line)
		}
		if c.Fix != "" && !strings.Contains(line, c.Fix) {
			t.Fatalf("missing fix: %q", line)
		}
	}
	d := DigestLines(caps, nil)
	if len(d) != 4 {
		t.Fatalf("digest %v", d)
	}
	// Owner opt not repeated once said.
	d2 := DigestLines(caps, map[string]bool{"Spare-time work": true})
	if len(d2) != 3 {
		t.Fatalf("owner opt repeated: %v", d2)
	}
}
