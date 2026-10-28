package loops

import (
	"testing"
)

// REQ: UPD-4, UPD-5
//
// The update channel and cadence are owner settings (UPD-4, UPD-5):
// texted like the loop settings.

func TestUpdateTextsParse(t *testing.T) {
	for msg, want := range map[string]Request{
		"UPDATES STABLE":          {Kind: KindChannel, Channel: ChannelStable},
		"updates fast":            {Kind: KindChannel, Channel: ChannelFast},
		"Updates pinned.":         {Kind: KindChannel, Channel: ChannelPinned},
		"UPDATE SOAK 14":          {Kind: KindSoak, Days: 14},
		"update soak 30 days":     {Kind: KindSoak, Days: 30},
		"UPDATE SOAK 1 DAY":       {Kind: KindSoak, Days: 1},
		"UPDATE SOAK 99999999999": {Kind: KindSoak, Days: MaxSoakDays + 1},
		"SECURITY UPDATES ASK":    {Kind: KindSecurity},
		"security updates auto":   {Kind: KindSecurity, On: true},
		"HELP UPDATES":            {Kind: KindHelpUpdates},
		// UX-130-1: UPDATE and UPDATES alike.
		"UPDATE PINNED":       {Kind: KindChannel, Channel: ChannelPinned},
		"updates soak 14":     {Kind: KindSoak, Days: 14},
		"SECURITY UPDATE ASK": {Kind: KindSecurity},
	} {
		got, ok := ParseText(msg)
		if !ok || got != want {
			t.Fatalf("%q: %+v %v", msg, got, ok)
		}
	}
	for _, msg := range []string{"UPDATES", "UPDATES SLOW", "are updates fast", "UPDATE SOAK", "UPDATE SOAK X",
		"UPDATE SOAK 014", "UPDATE SOAK 14 WEEKS", "SECURITY UPDATES", "SECURITY UPDATES OFF"} {
		if r, ok := ParseText(msg); ok {
			t.Fatalf("%q read as %+v", msg, r)
		}
	}
}
