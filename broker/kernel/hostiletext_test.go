package kernel

// REQ: BAK-1, HW-16, HW-17, LOG-4

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/hostiletext"
)

// Every name the kernel shapes refuses the hostile-text corpus (#3901): a
// backup destination's name and locator, which the anchor's signer reads on
// the page (#3284), and the label Named looks for (#3438). Named keeps the
// two joiners its labels may hold, as STATUS lines do (#2740).
func TestNameCheckRefusesHostileText(t *testing.T) {
	t.Run("backup target name", func(t *testing.T) {
		hostiletext.Run(t, func(s string) bool { return BackupTarget{Name: s, Kind: KindDir, Locator: "/mnt/usb"}.shape() })
	})
	t.Run("backup target locator", func(t *testing.T) {
		hostiletext.Run(t, func(s string) bool { return BackupTarget{Name: "usb", Kind: KindDir, Locator: "/mnt/" + s}.addable() })
	})
	t.Run("named label", func(t *testing.T) {
		hostiletext.Run(t, func(s string) bool {
			_, _, err := (&Kernel{}).Named(s)
			return !errors.Is(err, ErrLabel)
		}, hostiletext.Except{
			"zero-width non-joiner U+200C": "shapes Persian and Indic names a label may hold (#2740)",
			"zero-width joiner U+200D":     "builds an emoji a label may hold (#2740)",
		})
	})
}
