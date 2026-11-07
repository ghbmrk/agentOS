package recovery

// REQ: BAK-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A backup destination's name goes to the owner and into the digest, so
// validName refuses every hostile shape: a Hangul filler is a letter to
// unicode.IsLetter but shows nothing (#3953).
func TestValidNameRefusesHostileText(t *testing.T) {
	hostiletext.Run(t, func(s string) bool { return validName(s) == nil })
}
