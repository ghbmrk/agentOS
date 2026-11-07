package boxname

// REQ: CH-21

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A box name shows in texts, so Shape refuses every hostile shape: a Hangul
// filler is a letter to unicode.IsLetter but shows nothing (#3953).
func TestShapeRefusesHostileText(t *testing.T) {
	hostiletext.Run(t, Shape)
	for _, n := range []string{"ㅤ", "DaveㅤSmith", "ᅟᅠ", "ﾠAnn"} {
		if _, err := Check(n, ""); err != ErrShape {
			t.Errorf("Check(%q): %v, want ErrShape", n, err)
		}
	}
}
