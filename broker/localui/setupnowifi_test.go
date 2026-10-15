package localui

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ONB-3, CH-12

// #1429 (UX U-1 on #1407): when the box cannot join Wi-Fi at all, the
// network step says so in the first person and points to the Ethernet
// button, rather than asking for the password again.
func TestNoWiFiJoinPointsToEthernet(t *testing.T) {
	for _, c := range []struct {
		name    string
		station func() bool
		joinErr error
		asks    int // JoinNetwork calls expected
	}{
		{"helper cannot join", nil, ErrWiFiUnavailable, 1},
		{"no station device", func() bool { return false }, nil, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.srv.cfg.Station = c.station
			r.hooks.joinErr = c.joinErr
			r.get("/setup")
			r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
			got := html.UnescapeString(r.setupErr())
			if got != noWiFiJoin {
				t.Fatalf("error %q, want %q", got, noWiFiJoin)
			}
			ch12(t, got)
			for _, w := range []string{"I cannot join Wi-Fi yet", "Ethernet", ethernetButton} {
				if !strings.Contains(got, w) {
					t.Fatalf("error lacks %q: %q", w, got)
				}
			}
			if strings.Contains(got, "password") {
				t.Fatalf("error blames the password: %q", got)
			}
			if r.hooks.joins != c.asks {
				t.Fatalf("JoinNetwork called %d times, want %d", r.hooks.joins, c.asks)
			}
			if page := r.get("/setup"); !strings.Contains(page, `name="ethernet"`) || !strings.Contains(page, ethernetButton) {
				t.Fatalf("the network step lost the Ethernet button: %s", page)
			}
		})
	}
}

// Any other refusal still shows the network error, and a station device
// present still lets the owner join.
func TestNotJoinedStillAsksForThePassword(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Station = func() bool { return true }
	r.hooks.joinErr = errors.New("not joined")
	r.get("/setup")
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
	if got := html.UnescapeString(r.setupErr()); got != "Could not join that Wi-Fi. Check the password and try again." {
		t.Fatalf("error %q", got)
	}
	r.hooks.joinErr = nil
	r.post("/setup/network", url.Values{"ssid": {"Home"}, "password": {"home-pass"}})
	if got := r.setupErr(); got != "" || r.hooks.joined != "Home" {
		t.Fatalf("join with a station device: error %q, joined %q", got, r.hooks.joined)
	}
}

// agentosd's own code for a join that cannot happen reaches the page as
// ErrWiFiUnavailable; not joined does not.
func TestJoinNetworkUnavailableIsNamed(t *testing.T) {
	answer := localapi.ErrJoinUnavailable
	a := AgentosdSetup{Owner: InProcess{localapi.OpSetupJoin: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
		return nil, sockets.Code(answer)
	}}}
	err := a.JoinNetwork("home", joinCanary)
	if !errors.Is(err, ErrWiFiUnavailable) || !refused(err, localapi.ErrJoinUnavailable) || strings.Contains(err.Error(), joinCanary) {
		t.Fatalf("got %v", err)
	}
	answer = localapi.ErrNotJoined
	if err := a.JoinNetwork("home", joinCanary); err == nil || errors.Is(err, ErrWiFiUnavailable) {
		t.Fatalf("not joined gave %v", err)
	}
}
