package kernel

// REQ: BAK-1, HW-16, HW-17, LOG-4

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/hostiletext"
)

// Every name the kernel shapes refuses the hostile-text corpus (#3901): a
// backup destination's name and locator, which the anchor's signer reads on
// the page (#3284), and the label Named looks for (#3438). Named keeps what
// a STATUS line shows (the joiners, #2740, an emoji's variation selector),
// since its match is exact; a label with nothing to see is still refused.
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
			"zero-width non-joiner U+200C":     "shapes Persian and Indic names a label may hold (#2740)",
			"zero-width joiner U+200D":         "builds an emoji a label may hold (#2740)",
			"variation selector 16":            "an emoji's presentation (U+2764 U+FE0F); STATUS shows it and sameLabel is exact",
			"variation selector 17":            "an ideographic variant of a name's character; STATUS shows it and sameLabel is exact",
			"NBSP":                             "a pasted space, which sameLabel folds as whitespace",
			"combining grapheme joiner U+034F": "STATUS shows it and sameLabel is exact, so it widens no match",
			"hangul filler U+3164":             "STATUS shows it and sameLabel is exact; a label of fillers alone is refused",
			"hangul choseong filler U+115F":    "STATUS shows it and sameLabel is exact; a label of fillers alone is refused",
			"halfwidth hangul filler U+FFA0":   "STATUS shows it and sameLabel is exact; a label of fillers alone is refused",
			"Khmer vowel inherent U+17B4":      "STATUS shows it and sameLabel is exact, so it widens no match",
		})
	})
}

// A label STATUS shows is a label Named looks for: an emoji with its
// variation selector, a flag built with the joiner, a pasted no-break space
// (UX on #3957). One with nothing to see stays refused.
func TestNamedTakesWhatStatusShows(t *testing.T) {
	for _, q := range []string{"Mum \u2764\ufe0f", "\U0001f3f3\ufe0f\u200d\U0001f308 club", "Alice\u00a0Smith", "\u8fbb\U000e0100"} {
		if !shown(q) {
			t.Fatalf("%q is not a STATUS line", q)
		}
		if _, _, err := (&Kernel{}).Named(q); errors.Is(err, ErrLabel) {
			t.Errorf("named %q: %v", q, err)
		}
	}
	for _, q := range []string{"\u3164", "\u3164\u115f", "\u00a0\u3164", "\ufe0f", " \u034f "} {
		if _, _, err := (&Kernel{}).Named(q); !errors.Is(err, ErrLabel) {
			t.Errorf("named %q: %v, want ErrLabel", q, err)
		}
	}
}
