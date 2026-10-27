package maintain

// REQ: OSS-10, OSS-9

import (
	"testing"
	"time"
)

// UX wording for the page, the alert and the evidence (OSS-9 Q-C).
func TestOSS9FollowWording(t *testing.T) {
	at := time.Date(2026, 10, 5, 13, 52, 0, 0, time.UTC)
	for got, want := range map[string]string{
		FollowPrompt("Acme", "AgentOS"):   "Follow Acme? After this, Acme decides what software I install, instead of AgentOS. Do this only if you trust Acme and got these details from them directly.",
		FollowCheckHeading("Acme"):        "Check these match what Acme published.",
		FollowNameLabel:                   "the name you gave it",
		FollowAlert("Acme", at):           "Updates now come from Acme, set on my Wi-Fi page at 13:52. Not you? Switch back there and change your codes.",
		EvidenceLine("Acme", 2, 1, true):  "Checked by 2 independent builders, by Acme, and rebuilt here to the same result.",
		EvidenceLine("Acme", 1, 0, false): "Checked by 1 independent builder.",
		EvidenceLine("Acme", 1, 0, true):  "Checked by 1 independent builder and rebuilt here to the same result.",
		EvidenceLine("Acme", 0, 1, true):  "No independent check yet; only Acme's own. Rebuilt here to the same result.",
		EvidenceLine("Acme", 0, 3, false): "No independent check yet; only Acme's own.",
		EvidenceLine("Acme", 0, 0, false): "No independent check yet; only Acme's own.",
	} {
		if got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	}
}
