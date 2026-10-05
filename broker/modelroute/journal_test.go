package modelroute

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: ADP-10

type notes struct {
	got  []journal.EgressNote
	fail bool
}

func (n *notes) RecordEgress(e journal.EgressNote) error {
	if n.fail {
		return errors.New("disk")
	}
	n.got = append(n.got, e)
	return nil
}

// TestADP10ReportedDenialsAreCoalesced: the vault process's denial reports
// reach the broker's journal under the machine the broker forwarded for,
// coalesced the way the proxy's own are (egress E6): one record per
// machine and reason class a minute, the next one carrying the count.
func TestADP10ReportedDenialsAreCoalesced(t *testing.T) {
	rec := &notes{}
	now := time.Unix(1_800_000_000, 0)
	j := journalWith(rec, nil, func() time.Time { return now })
	for i := 0; i < 500; i++ {
		j("m1", Denial{Machine: "forged", Adapter: "router", Method: "GET", Status: 404, Reason: "only POST /v1/chat/completions is served"})
	}
	j("m2", Denial{Adapter: "router", Method: "GET", Status: 404, Reason: "only POST /v1/chat/completions is served"})
	for i := 0; i < 50; i++ {
		j("m1", Denial{Adapter: "router", Method: "POST", Status: 400, Reason: fmt.Sprintf("message role %q is not accepted", fmt.Sprint("r", i))})
	}
	// The router quotes the parser's error, numbers included (route
	// TestADP10DenialReasonClassIsFixed): one class.
	for _, num := range []string{"123456789012345678901", "987654321098765432109"} {
		j("m1", Denial{Adapter: "router", Method: "POST", Status: 400, Reason: fmt.Sprintf("request not accepted: %q",
			"json: cannot unmarshal number "+num+" into Go struct field chatRequest.max_tokens of type int")})
	}
	j("m1", Denial{Status: 403})
	if len(rec.got) != 5 {
		t.Fatalf("journaled %d notes, want 5: %+v", len(rec.got), rec.got)
	}
	if n := rec.got[0]; n.Machine != "m1" || n.Adapter != "router" || n.Method != "GET" || n.Status != 404 {
		t.Fatalf("note: %+v", n)
	}
	if rec.got[4].Reason != "denied" {
		t.Fatalf("a denial without a reason: %+v", rec.got[4])
	}
	now = now.Add(61 * time.Second)
	j("m1", Denial{Adapter: "router", Method: "GET", Status: 404, Reason: "only POST /v1/chat/completions is served"})
	if n := rec.got[len(rec.got)-1]; len(rec.got) != 6 || n.Suppressed != 499 {
		t.Fatalf("after the window: %+v", rec.got)
	}

	var logged strings.Builder
	journalWith(&notes{fail: true}, func(f string, a ...any) { fmt.Fprintf(&logged, f, a...) }, nil)("m1", Denial{Status: 404, Reason: "x"})
	if logged.Len() == 0 {
		t.Fatal("a failed journal write went unreported")
	}
}
