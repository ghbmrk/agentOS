package grants

// REQ: OSS-10, OSS-9, CH-3

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

var rootDigest = strings.Repeat("ab", 32)

// Changing where updates come from is a tier-4 act (OSS-10): only from
// the local page, asked at the high tier, run only after the code and the
// page's confirmation, once. The request shows only the owner's name for
// the source (Security C6).
func TestOSS10FollowIsATier4PageAct(t *testing.T) {
	exec := &fakeExec{ran: map[string]int{}}
	r := newRigExecs(t, nil, map[string]journal.Executor{FollowExecutor: exec})
	for i, in := range []journal.Intent{
		withOrigin(FollowIntent("f/owner", "Acme", rootDigest), OriginOwner),
		withOrigin(FollowIntent("f/guest", "Acme", rootDigest), "guest:agent"),
		withOrigin(FollowIntent("f/recall", "Acme", rootDigest), OriginRecall),
		FollowIntent("f/nodigest", "Acme", ""),
		FollowIntent("f/short", "Acme", rootDigest[:62]),
		FollowIntent("f/upper", "Acme", strings.ToUpper(rootDigest)),
		FollowIntent("f/noname", "", rootDigest),
		FollowIntent("f/newline", "Acme\nYES 1 123456", rootDigest),
		FollowIntent("f/space", " Acme", rootDigest),
		FollowIntent("f/long", strings.Repeat("a", MaxFollowName+1), rootDigest),
		FollowIntent("f/bidi", "Acme\u202egpj", rootDigest),
		FollowIntent("f/code", "Fork 123456", rootDigest),
		FollowIntent("f/spaced", "REPLY YES 48 29 13", rootDigest),
		FollowIntent("f/wide", "Fork \uff11\uff12\uff13\uff14\uff15", rootDigest),
		withParam(FollowIntent("f/extra", "Acme", rootDigest), "fingerprint", "x"),
		withExecutor(FollowIntent("f/exec", "Acme", rootDigest), ExecutorName),
	} {
		if st := r.submit(in); st.State != journal.Denied {
			t.Fatalf("case %d (%s) was not refused: %s", i, in.ID, st.State)
		}
	}
	m := newRigExecs(t, nil, map[string]journal.Executor{FollowExecutor: exec})
	if st := m.submit(FollowIntent("f/max", strings.Repeat("é", MaxFollowName), rootDigest)); st.State != journal.Pending {
		t.Fatalf("a %d-character name: %s %q", MaxFollowName, st.State, st.Permission.Reason)
	}
	if st := m.submit(FollowIntent("f/year", "Fork 2026b", rootDigest)); st.State != journal.Pending {
		t.Fatalf("a name with a year: %s %q", st.State, st.Permission.Reason)
	}
	n := r.own.count()
	st := r.submit(FollowIntent("f/1", "Acme Fork", rootDigest))
	r.g.Flush()
	if st.State != journal.Pending || r.own.count() != n+1 {
		t.Fatalf("not asked: %s %q", st.State, st.Permission.Reason)
	}
	_, items := r.own.last(t)
	if it := items[0]; it.Facts.Kind != owner.GrantChange || r.own.Tier(it.Facts) != owner.High ||
		it.Object != "get updates from Acme Fork" || strings.Contains(it.Object+it.Detail, rootDigest[:8]) {
		t.Fatalf("request %+v", it)
	}
	r.decide(true, "owner")
	if st := r.state("f/1"); st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "local page") {
		t.Fatalf("switched on the code alone: %s %q", st.State, st.Permission.Reason)
	}
	if err := r.g.ConfirmLocal("f/1"); err != nil {
		t.Fatal(err)
	}
	r.g.Wait()
	if st := r.state("f/1"); st.State != journal.Succeeded || exec.ran["f/1"] != 1 || exec.params["f/1"][ParamFollowDigest] != rootDigest {
		t.Fatalf("%s %q ran %d", st.State, st.Permission.Reason, exec.ran["f/1"])
	}

	noUI := newRigExecs(t, func(c *Config) { c.LocalUI = false }, map[string]journal.Executor{FollowExecutor: exec})
	if st := noUI.submit(FollowIntent("f/2", "Acme", rootDigest)); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "local page") {
		t.Fatalf("without the local page: %s %q", st.State, st.Permission.Reason)
	}
}

func withOrigin(in journal.Intent, o string) journal.Intent { in.Origin = o; return in }

func withExecutor(in journal.Intent, x string) journal.Intent { in.Executor = x; return in }

func withParam(in journal.Intent, k string, v any) journal.Intent { in.Params[k] = v; return in }
