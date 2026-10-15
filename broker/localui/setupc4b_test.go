package localui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ONB-3, CRED-1

// P2-2w c4b acceptance test 7: with a list, the network step shows each
// name as an option and a field to type one that is not listed; a typed
// name wins over the selected one.
func TestNetworkStepListsNetworksAndTakesATypedName(t *testing.T) {
	r := newRig(t)
	page := r.get("/setup")
	for _, w := range []string{`<select name="ssid">`, `<option value="Home">Home</option>`, `<option value="Neighbor">Neighbor</option>`, `name="other"`} {
		if !strings.Contains(page, w) {
			t.Fatalf("network step lacks %q: %s", w, page)
		}
	}
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "other": {"Upstairs 5G"}, "password": {"home-pass"}})
	if r.hooks.joined != "Upstairs 5G" {
		t.Fatalf("joined %q, want the typed name", r.hooks.joined)
	}
}

func TestNetworkStepJoinsTheSelectedNameWhenNoneIsTyped(t *testing.T) {
	r := newRig(t)
	r.get("/setup")
	r.post("/setup/network", url.Values{"ssid": {"Neighbor"}, "other": {""}, "password": {"home-pass"}})
	if r.hooks.joined != "Neighbor" {
		t.Fatalf("joined %q", r.hooks.joined)
	}
}

// AgentosdSetup.Networks carries agentosd's list; an error, or a list
// over the bound, gives none.
func TestAgentosdNetworksCarriesTheList(t *testing.T) {
	answer := func(v any, err error) AgentosdSetup {
		return AgentosdSetup{Owner: InProcess{localapi.OpSetupNetworks: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return v, err
		}}}
	}
	if got := answer(localapi.Networks{SSIDs: []string{"Home", "Cafe"}}, nil).Networks(); !reflect.DeepEqual(got, []string{"Home", "Cafe"}) {
		t.Fatalf("Networks = %q", got)
	}
	if got := answer(nil, errors.New("down")).Networks(); got != nil {
		t.Fatalf("an error gave %q", got)
	}
	if got := (AgentosdSetup{Owner: InProcess{}}).Networks(); got != nil {
		t.Fatalf("no op gave %q", got)
	}
	many := make([]string, localapi.MaxNetworks+1)
	for i := range many {
		many[i] = fmt.Sprintf("n%d", i)
	}
	if got := answer(localapi.Networks{SSIDs: many}, nil).Networks(); got != nil {
		t.Fatalf("an over-long list gave %d names", len(got))
	}
}

// spaced lists names a browser would strip or collapse as option text.
type spaced struct{ *fakeHooks }

func (spaced) Networks() []string { return []string{" Lead", "Trail ", "Two  Spaces"} }

// UX B1: each option's value is the exact name, so leading, trailing and
// double spaces survive the form (the browser strips and collapses option
// text that has no value).
func TestNetworkStepJoinsTheExactListedName(t *testing.T) {
	for _, name := range (spaced{}).Networks() {
		r := newRig(t)
		r.via = spaced{r.hooks}
		r.srv = r.open(&MemStore{})
		page := r.get("/setup")
		m := regexp.MustCompile(`<option value="([^"]*)">` + regexp.QuoteMeta(html.EscapeString(name)) + `</option>`).FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("no valued option for %q: %s", name, page)
		}
		picked := html.UnescapeString(m[1])
		r.post("/setup/network", url.Values{"ssid": {picked}, "other": {""}, "password": {"home-pass"}})
		if r.hooks.joined != name {
			t.Fatalf("joined %q, want %q", r.hooks.joined, name)
		}
	}
}
