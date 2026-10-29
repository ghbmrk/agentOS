package policy

// REQ: NET-2, NET-4

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/hostiletext"
)

// A policy token (a device, rule or host name, a command, a Wi-Fi identity)
// refuses the hostile-text corpus (#3901), so none splits a serial or shows
// as another on the page; the Wi-Fi identity is #3871's.
func TestNameCheckRefusesHostileText(t *testing.T) {
	t.Run("token", func(t *testing.T) { hostiletext.Run(t, name) })
	t.Run("Wi-Fi identity", func(t *testing.T) {
		// An empty identity is none at all, which a device may have.
		hostiletext.Run(t, func(s string) bool {
			if s == "" {
				return false
			}
			_, err := Encode(edit(1, func(d *Document) { dev(d, "plug").WiFi = s }))
			return err == nil
		})
	})
}
