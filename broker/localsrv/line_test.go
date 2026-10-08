package localsrv

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CH-7, CH-1

var testLine = localapi.Line{
	Note:     "I can't reach my phone modem.",
	Outage:   &localapi.Outage{From: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 10, 5, 10, 30, 0, 0, time.UTC), Missed: 5, Requests: 2},
	Others:   3,
	TimedOut: 1,
	Dropped:  true,
}

// P2-2w d2a under Security D1: the owner line's last outage and the
// bridge's counts go only to a signed-in page; the untokened status keeps
// the fixed note and nothing counted.
func TestTheLineCountsNeedAToken(t *testing.T) {
	r := newRig(t)
	out, err := r.call(localapi.OpStatus, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if out.(localapi.Status).LineNote != testLine.Note {
		t.Fatalf("status note: %s", b)
	}
	for _, leak := range []string{"missed", "requests", "others", "timed_out", "dropped", "outage", "2026-10-05T09"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("status before sign-in carries %q: %s", leak, b)
		}
	}
	if _, err := r.call(localapi.OpLine, localapi.Auth{}); code(err) != localapi.ErrUnauthorized {
		t.Fatalf("line without a token: %v", err)
	}
	out, err = r.call(localapi.OpLine, localapi.Auth{Token: r.signIn()})
	if err != nil {
		t.Fatal(err)
	}
	if got := out.(localapi.Line); !reflect.DeepEqual(got, testLine) {
		t.Fatalf("line %+v, want %+v", got, testLine)
	}
}

// Without the modem bridge there is no line: no note, nothing counted.
func TestNoBridgeNoLine(t *testing.T) {
	r := newRig(t)
	r.srv.cfg.Line = nil
	out, err := r.call(localapi.OpStatus, struct{}{})
	if err != nil || out.(localapi.Status).LineNote != "" {
		t.Fatalf("status %+v %v", out, err)
	}
	out, err = r.call(localapi.OpLine, localapi.Auth{Token: r.signIn()})
	if err != nil || !reflect.DeepEqual(out, localapi.Line{}) {
		t.Fatalf("line %+v %v", out, err)
	}
}
