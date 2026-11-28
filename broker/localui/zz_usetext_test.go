package localui

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
)

// The use detail names its cause (#3014): the confirmed use always came
// from an earlier Begin that a newer one for another use replaced, even
// when the pasted address is the confirmed use's own landing.
func TestConnectUseTextNamesTheReplacingSignIn(t *testing.T) {
	got := connectText(clerk.DUse)
	if !strings.Contains(got, "replaced by a newer one for a different use") || strings.Contains(got, "address is from") {
		t.Fatalf("use detail: %q", got)
	}
}
