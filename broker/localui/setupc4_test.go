package localui

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ONB-4, CH-12

// P2-2w c4: the offline phase crosses from agentosd's progress to the
// page's.
func TestAgentosdProgressCarriesThePhase(t *testing.T) {
	for _, c := range []struct {
		in   localapi.SetupProgress
		want Progress
	}{
		{localapi.SetupProgress{Phase: "offline"}, Progress{Phase: "offline"}},
		{localapi.SetupProgress{Phase: "ready", Updated: true, Online: true}, Progress{Phase: "ready", Updated: true, Online: true}},
	} {
		a := AgentosdSetup{Owner: InProcess{localapi.OpSetupProgress: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return c.in, nil
		}}}
		if got := a.Progress(); got != c.want {
			t.Errorf("%+v gave %+v", c.in, got)
		}
	}
}

func ch12(t *testing.T, s string) {
	t.Helper()
	if n, gsm := modem.Segments(s); !gsm || n > 3 {
		t.Fatalf("note breaks CH-12 (%d segments, gsm7 %v): %q", n, gsm, s)
	}
	for _, w := range []string{"netjoin", "agentosd", "helper", "socket", "NetworkManager", "saved state", "uplink"} {
		if strings.Contains(s, w) {
			t.Fatalf("note names %q: %q", w, s)
		}
	}
}
