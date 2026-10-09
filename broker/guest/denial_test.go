package guest

// SR2-3j: a denial's reason reaches the guest only as the policy's guest
// text; any other reason is a ref, its detail on a broker-log line.
//
// REQ: RES-4, CAP-8

import (
	"bytes"
	"context"
	"errors"
	"log"
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/guesterr"
	"github.com/ghbmrk/agentos/broker/journal"
)

// denialCanary is a synthetic host path; it is no real path on any box.
const denialCanary = "/var/lib/agentos-canary-7f3a/grants.db"

// denyByID refuses r-plain with text naming the canary, and r-safe with
// fixed guest text; it allows the rest.
type denyByID struct{}

func (denyByID) Check(_ context.Context, _ journal.Phase, in journal.Intent) error {
	switch {
	case strings.HasSuffix(in.ID, "/r-plain"):
		return errors.New("cannot read " + denialCanary)
	case strings.HasSuffix(in.ID, "/r-safe"):
		return guesterr.New("needs the owner's approval")
	}
	return nil
}

var denialRef = regexp.MustCompile(`^effect_(request|status) failed \(ref ([0-9a-f]{8})\); the broker's log has the detail$`)

func TestDenialReasonsReachTheGuestOnlyAsFixedText(t *testing.T) {
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })

	eng, err := journal.Open(&journal.MemStore{}, denyByID{}, map[string]journal.Executor{"mail": &exec{runs: map[string]int{}}}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(c *Config) { c.Effects = eng })
	for _, tool := range []string{"effect_request", "effect_status"} {
		args := map[string]any{"request_id": "r-plain"}
		if tool == "effect_request" {
			args = send("r-plain")
		}
		buf.Reset()
		st, e := r.tool("m1", tool, args)
		m := denialRef.FindStringSubmatch(st.Reason)
		if e != "" || st.State != "denied" || m == nil || strings.Contains(st.Reason, "canary") {
			t.Fatalf("%s: %+v %q", tool, st, e)
		}
		if !strings.Contains(buf.String(), "ref "+m[2]) || !strings.Contains(buf.String(), denialCanary) {
			t.Fatalf("%s: the log has no line for ref %s:\n%s", tool, m[2], buf.String())
		}
	}
	if st, e := r.tool("m1", "effect_request", send("r-safe")); e != "" || st.State != "denied" || st.Reason != "needs the owner's approval" {
		t.Fatalf("safe: %+v %q", st, e)
	}
}
