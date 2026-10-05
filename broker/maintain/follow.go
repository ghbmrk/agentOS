package maintain

import (
	"fmt"
	"strings"
	"time"
)

// Owner text for following a fork (OSS-10), in the UX lens's wording (Q-C
// on the OSS-9 design). The local page (P2-2) shows FollowPrompt, then the
// root's fingerprints, thresholds and expiry under FollowCheckHeading,
// with the owner's name for the fork labelled FollowNameLabel; switching
// back uses the same layout with the names swapped. The updater sends
// FollowAlert at once, coalesced with other alerts, when a switch runs.

// FollowNameLabel labels the name the owner typed for the fork.
const FollowNameLabel = "the name you gave it"

// FollowPrompt leads the page that switches the box to name from current.
func FollowPrompt(name, current string) string {
	return fmt.Sprintf("Follow %s? After this, %s decides what software I install, instead of %s. Do this only if you trust %s and got these details from them directly.",
		name, name, current, name)
}

// FollowCheckHeading heads the root's details on that page.
func FollowCheckHeading(name string) string {
	return fmt.Sprintf("Check these match what %s published.", name)
}

// FollowAlert is the immediate alert after a switch made at at.
func FollowAlert(name string, at time.Time) string {
	return fmt.Sprintf("Updates now come from %s, set on my Wi-Fi page at %s. Not you? Switch back there and change your codes.", name, at.Format("15:04"))
}

// EvidenceLine says in plain words who checked a release (OSS-9: evidence,
// weighted, never authority): listed independent builders, the source's
// own maintainer-operated testers (named as the source), and a rebuild on
// this box. Reports from unlisted keys are never counted or mentioned
// (Q-A).
func EvidenceLine(source string, independent, maintainer int, rebuilt bool) string {
	if independent == 0 {
		line := fmt.Sprintf("No independent check yet; only %s's own.", source)
		if rebuilt {
			line += " Rebuilt here to the same result."
		}
		return line
	}
	builders := "builders"
	if independent == 1 {
		builders = "builder"
	}
	by := []string{fmt.Sprintf("by %d independent %s", independent, builders)}
	if maintainer > 0 {
		by = append(by, "by "+source)
	}
	line := "Checked " + strings.Join(by, ", ")
	switch {
	case rebuilt && len(by) > 1:
		line += ", and rebuilt here to the same result"
	case rebuilt:
		line += " and rebuilt here to the same result"
	}
	return line + "."
}
