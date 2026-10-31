package policy

// REQ: NET-2, NET-4

import (
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
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

// A token is at most 253 bytes, a DNS name's length; a multi-byte letter
// counts by its bytes.
func TestNameIsAtMost253Bytes(t *testing.T) {
	for s, want := range map[string]bool{
		strings.Repeat("a", 253):            true,
		strings.Repeat("a", 254):            false,
		strings.Repeat("a", 251) + "\u00e9": true,
		strings.Repeat("a", 252) + "\u00e9": false,
	} {
		if name(s) != want {
			t.Errorf("name(%d bytes) = %v, want %v", len(s), !want, want)
		}
	}
}

// The word the channel log puts before an unsigned name's hash is no
// token, in any case, so a signed device never reads as that marker on the
// owner's line (#4185); a token that only starts with it is a name.
// Revert mutant: name without the Unknown check.
func TestUnknownIsReserved(t *testing.T) {
	for s, want := range map[string]bool{
		"unknown": false, "Unknown": false, "UNKNOWN": false,
		"unknown-plug": true, "unknowns": true, "unknow": true,
	} {
		if name(s) != want {
			t.Errorf("name(%q) = %v, want %v", s, !want, want)
		}
	}
	d := edit(1, func(d *Document) {
		u := *dev(d, "tv")
		u.ID = Unknown
		d.Devices = append(d.Devices, u)
	})
	if _, err := Encode(d); !errors.Is(err, ErrMalformed) {
		t.Errorf("a device named %q signed: %v", Unknown, err)
	}
}
