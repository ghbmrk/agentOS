package guesterr

// REQ: RES-4, CAP-8
//
// SR2-3k (finding 4, L3 on #324): a Guest value is shown only when it
// fits ^[A-Za-z0-9._-]{1,64}$, the request-ID shape; anything else, a
// host path passed as guest text included, is replaced by fixed text.

import (
	"strings"
	"testing"
)

func TestOnlyIDShapedGuestValuesAreShown(t *testing.T) {
	for _, v := range []string{"r1", "effect_request", "A.b-c_9", strings.Repeat("x", 64)} {
		if got := Newf("no request %s", Guest(v)).GuestText(); got != "no request "+v {
			t.Fatalf("%q shown as %q", v, got)
		}
	}
	for _, v := range []string{"", canary, "a b", "x\n", "é", strings.Repeat("x", 65), "r1…", "../x"} {
		got := Newf("no request %s; at most %d", Guest(v), Num(3)).GuestText()
		if got != "no request "+unshown+"; at most 3" {
			t.Fatalf("%q shown as %q", v, got)
		}
	}
}

// embedsGuest embeds Guest, so it is an Arg by the promoted method; its
// value is still checked (release 1, L3 on #398).
type embedsGuest struct{ Guest }

func TestAnEmbeddedGuestValueIsCheckedToo(t *testing.T) {
	got := Newf("no request %s", embedsGuest{Guest(canary)}).GuestText()
	if strings.Contains(got, canary) || got != "no request "+unshown {
		t.Fatalf("embedded path shown as %q", got)
	}
	if got := Newf("no request %s", embedsGuest{Guest("r1")}).GuestText(); got != "no request r1" {
		t.Fatalf("embedded ID shown as %q", got)
	}
}
