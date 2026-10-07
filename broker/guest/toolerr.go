package guest

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"regexp"
	"strings"
)

// hostPathRE matches agent-visible text that names a host path (SR2-3g).
// Fixed broker reasons never include these shapes.
var hostPathRE = regexp.MustCompile(`(?i)(/home/|/Users/|/tmp/|/var/|/usr/|/etc/|/root/|/opt/|[A-Za-z]:\\)`)

// guestFacingErr is what a guest may see of an error tool result (SR2-3g,
// security F5 on SR2-3f): allowlisted fixed text passes; anything that
// names a host path becomes a ref, with the detail only in the broker log.
func guestFacingErr(tool, text string) string {
	text = strings.TrimSpace(text)
	if text == "" || !hostPathRE.MatchString(text) {
		return text
	}
	ref := newGuestRef()
	log.Printf("guest: tool %s: ref %s: %s", tool, ref, text)
	return "failed (ref " + ref + "); the broker's log has the detail"
}

func newGuestRef() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b)
}
