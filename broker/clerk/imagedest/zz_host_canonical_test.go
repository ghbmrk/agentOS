package imagedest

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/enflist"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// REQ: NET-2

// TestJoinFoldsEachSpellingOfAStatedHost (#6478): a declared or backup
// destination spelling a stated host in another case, with a trailing
// dot, or both, is that host: Join refuses it as *Shared, naming the
// spelling given. A canonical declared host still joins and signs.
func TestJoinFoldsEachSpellingOfAStatedHost(t *testing.T) {
	tab, err := Shipped()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(tab.Hosts(), "time.cloudflare.com") {
		t.Fatal("the shipped statement no longer names time.cloudflare.com; pick another stated host")
	}
	for _, h := range []string{"TIME.cloudflare.com", "time.cloudflare.com.", "TIME.cloudflare.com."} {
		for _, b := range []enflist.Basis{enflist.Declared, enflist.Backup} {
			_, err := tab.Join([]enflist.Dest{{Host: h, Basis: b, DailyBytes: 1}})
			var sh *Shared
			if !errors.Is(err, ErrShared) || !errors.As(err, &sh) || sh.Host != h {
				t.Errorf("%q as %s: %v, want *Shared naming it", h, b, err)
				continue
			}
			if !strings.Contains(err.Error(), strconv.QuoteToASCII(h)) {
				t.Errorf("%q as %s: refusal %q does not name the host", h, b, err)
			}
		}
	}
	mail := enflist.Dest{Host: "mail.agentos.dev", Basis: enflist.Declared, DailyBytes: 64 << 20}
	ds, err := tab.Join([]enflist.Dest{mail})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enflist.Propose(policy.Document{Version: 1}, enflist.Inputs{Dests: ds, EdgeDeclaredBytes: 1}); err != nil {
		t.Fatalf("a canonical declared host does not sign: %v", err)
	}
}

// TestNoSpellingGivesOneNameTwoCaps (#6478 failure path): whatever a
// caller passes, Join then Propose never signs two caps for one DNS name.
// A spelling Join does not fold (two trailing dots) is refused by Propose.
func TestNoSpellingGivesOneNameTwoCaps(t *testing.T) {
	tab, err := Shipped()
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"TIME.cloudflare.com", "time.cloudflare.com.", "TIME.cloudflare.com.", "time.cloudflare.com.."} {
		for _, b := range []enflist.Basis{enflist.Declared, enflist.Backup} {
			ds, err := tab.Join([]enflist.Dest{{Host: h, Basis: b, DailyBytes: 1}})
			if err != nil {
				continue
			}
			if _, err := enflist.Propose(policy.Document{Version: 1}, enflist.Inputs{Dests: ds, EdgeDeclaredBytes: 1}); err == nil {
				t.Errorf("%q as %s joins and signs beside time.cloudflare.com", h, b)
			}
		}
	}
}
