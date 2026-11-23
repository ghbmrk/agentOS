package enflist

import (
	"errors"
	"strings"
	"testing"
)

// REQ: NET-2

// TestCanonicalHostFoldsCaseAndOneDot (#6478): ASCII case folds and one
// trailing dot drops; nothing else changes.
func TestCanonicalHostFoldsCaseAndOneDot(t *testing.T) {
	for in, want := range map[string]string{
		"time.cloudflare.com":   "time.cloudflare.com",
		"TIME.cloudflare.com":   "time.cloudflare.com",
		"time.cloudflare.com.":  "time.cloudflare.com",
		"TIME.Cloudflare.COM.":  "time.cloudflare.com",
		"time.cloudflare.com..": "time.cloudflare.com.",
		"AZaz09-.example":       "azaz09-.example",
		"@[`{.example":          "@[`{.example", // the bytes around A-Z and a-z stay
		"K.example":             "K.example",    // the Kelvin sign is not ASCII: not folded
		"":                      "",
	} {
		if got := CanonicalHost(in); got != want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestProposeRefusesANonCanonicalHost (#6478): a destination whose host is
// not its canonical form is refused by its quoted name and gives no link,
// whatever its basis, so two spellings of one name never get two caps; a
// canonical host still signs.
func TestProposeRefusesANonCanonicalHost(t *testing.T) {
	for _, h := range []string{"TIME.cloudflare.com", "time.cloudflare.com.", "TIME.cloudflare.com.", "time.cloudflare.com.."} {
		for _, b := range []Basis{Declared, Image, Backup} {
			ds := []Dest{{"time.cloudflare.com", Image, 2 << 20}, {h, b, 1}}
			_, err := Propose(cur(), Inputs{Dests: ds, EdgeDeclaredBytes: 1})
			if !errors.Is(err, ErrInput) || !strings.Contains(err.Error(), `"`+h+`"`) {
				t.Errorf("%q as %s beside the canonical name: %v, want ErrInput naming it", h, b, err)
			}
			if _, err := Propose(cur(), Inputs{Dests: ds[1:], EdgeDeclaredBytes: 1}); !errors.Is(err, ErrInput) {
				t.Errorf("%q as %s alone: %v, want ErrInput", h, b, err)
			}
		}
	}
	if _, err := Propose(cur(), Inputs{Dests: []Dest{{"time.cloudflare.com", Image, 2 << 20}}, EdgeDeclaredBytes: 1}); err != nil {
		t.Fatalf("a canonical host: %v", err)
	}
}

// TestProposeNamesAnOffListBasis: a basis off the list is refused by
// Propose itself, naming the host and the basis, before the policy sees it.
func TestProposeNamesAnOffListBasis(t *testing.T) {
	_, err := Propose(cur(), Inputs{Dests: []Dest{{"a.example", "guess", 1}}, EdgeDeclaredBytes: 1})
	if !errors.Is(err, ErrInput) || !strings.Contains(err.Error(), `"a.example" has basis "guess"`) {
		t.Fatalf("an off-list basis: %v, want ErrInput naming the host and basis", err)
	}
}
