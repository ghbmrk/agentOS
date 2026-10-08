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
		withOrigin(FollowIntent("f01", "Acme", rootDigest), OriginOwner),
		withOrigin(FollowIntent("f02", "Acme", rootDigest), "guest:agent"),
		withOrigin(FollowIntent("f03", "Acme", rootDigest), OriginRecall),
		FollowIntent("f04", "Acme", ""),
		FollowIntent("f05", "Acme", rootDigest[:62]),
		FollowIntent("f06", "Acme", strings.ToUpper(rootDigest)),
		FollowIntent("f07", "Acme\nYES 1 123456", rootDigest),
		FollowIntent("f08", " Acme", rootDigest),
		// A name may not read as switching back (security 323-1).
		FollowIntent("f08b", "the AgentOS project again", rootDigest),
		FollowIntent("f08c", "THE agentos PROJECT", rootDigest),
		FollowIntent("f09", strings.Repeat("a", MaxFollowName+1), rootDigest),
		FollowIntent("f0a", "Acme\u202egpj", rootDigest),
		FollowIntent("f0b", "Fork 123456", rootDigest),
		FollowIntent("f0c", "REPLY YES 48 29 13", rootDigest),
		FollowIntent("f0d", "Fork \uff11\uff12\uff13\uff14\uff15", rootDigest),
		withParam(FollowIntent("f0e", "Acme", rootDigest), "fingerprint", "x"),
		withExecutor(FollowIntent("f0f", "Acme", rootDigest), ExecutorName),
		// A nonce is hex (OSS-10w L3).
		FollowIntent("f-nothex", "Acme", rootDigest),
		FollowIntent("", "Acme", rootDigest),
	} {
		if st := r.submit(in); st.State != journal.Denied {
			t.Fatalf("case %d (%s) was not refused: %s", i, in.ID, st.State)
		}
	}
	m := newRigExecs(t, nil, map[string]journal.Executor{FollowExecutor: exec})
	if st := m.submit(FollowIntent("f11", strings.Repeat("é", MaxFollowName), rootDigest)); st.State != journal.Pending {
		t.Fatalf("a %d-character name: %s %q", MaxFollowName, st.State, st.Permission.Reason)
	}
	if st := m.submit(FollowIntent("f12", "Fork 2026b", rootDigest)); st.State != journal.Pending {
		t.Fatalf("a name with a year: %s %q", st.State, st.Permission.Reason)
	}
	// An empty name switches back to the project; the updater admits it
	// only for the root the image ships (WF1).
	m.g.Flush()
	if st := m.submit(FollowIntent("f13", "", rootDigest)); st.State != journal.Pending {
		t.Fatalf("switching back: %s %q", st.State, st.Permission.Reason)
	}
	m.g.Flush()
	if _, items := m.own.last(t); items[0].Object != "get updates from the AgentOS project again" || items[0].Detail != "root fingerprint "+FollowPrint(rootDigest) {
		t.Fatalf("switching back asks %+v", items[0])
	}
	n := r.own.count()
	in := FollowIntent("f14", "Acme Fork", rootDigest)
	st := r.submit(in)
	r.g.Flush()
	if st.State != journal.Pending || r.own.count() != n+1 {
		t.Fatalf("not asked: %s %q", st.State, st.Permission.Reason)
	}
	_, items := r.own.last(t)
	if it := items[0]; it.Facts.Kind != owner.GrantChange || r.own.Tier(it.Facts) != owner.High ||
		it.Object != "get updates from Acme Fork" || it.Detail != "root fingerprint "+rootDigest[:4]+"-"+rootDigest[4:8] {
		t.Fatalf("request %+v", it)
	}
	r.decide(true, "owner")
	if st := r.state(in.ID); st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "Wi-Fi page") {
		t.Fatalf("switched on the code alone: %s %q", st.State, st.Permission.Reason)
	}
	if err := r.g.ConfirmLocal(in.ID); err != nil {
		t.Fatal(err)
	}
	r.g.Wait()
	if st := r.state(in.ID); st.State != journal.Succeeded || exec.ran[in.ID] != 1 {
		t.Fatalf("%s %q ran %d", st.State, st.Permission.Reason, exec.ran[in.ID])
	}

	noUI := newRigExecs(t, func(c *Config) { c.LocalUI = false }, map[string]journal.Executor{FollowExecutor: exec})
	if st := noUI.submit(FollowIntent("f15", "Acme", rootDigest)); st.State != journal.Denied || st.Permission.Reason != NoPageFollow {
		t.Fatalf("without the local page: %s %q", st.State, st.Permission.Reason)
	}
}

func withOrigin(in journal.Intent, o string) journal.Intent { in.Origin = o; return in }

func withExecutor(in journal.Intent, x string) journal.Intent { in.Executor = x; return in }

func withParam(in journal.Intent, k string, v any) journal.Intent {
	if in.Params == nil {
		in.Params = map[string]any{}
	}
	in.Params[k] = v
	return in
}

// The journal redacts params (agentosd's redactor keeps no free text), so
// the follow intent's name and digest ride in its ID, as a forget's goal
// does: the gate and the updater read them from there (GR26 wiring).
func TestOSS10FollowSurvivesARedactingJournal(t *testing.T) {
	exec := &fakeExec{ran: map[string]int{}}
	r := newRigExecs(t, nil, map[string]journal.Executor{FollowExecutor: exec})
	r.redact = func(s string) string { return "[redacted]" }
	r.open()
	in := FollowIntent("f16", "Acme Fork", rootDigest)
	if len(in.Params) != 0 {
		t.Fatalf("params %v: the journal would redact them", in.Params)
	}
	st := r.submit(in)
	r.g.Flush()
	if st.State != journal.Pending {
		t.Fatalf("refused under a redacting journal: %s %q", st.State, st.Permission.Reason)
	}
	_, items := r.own.last(t)
	if items[0].Object != "get updates from Acme Fork" {
		t.Fatalf("request %+v", items[0])
	}
	r.decide(true, "owner")
	if err := r.g.ConfirmLocal(in.ID); err != nil {
		t.Fatal(err)
	}
	r.g.Wait()
	if st := r.state(in.ID); st.State != journal.Succeeded || exec.ran[in.ID] != 1 {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
	if d, name, ok := FollowOf(in.ID); !ok || d != rootDigest || name != "Acme Fork" {
		t.Fatalf("FollowOf(%q) = %q %q %v", in.ID, d, name, ok)
	}
	for _, id := range []string{"", "follow/", "follow//" + rootDigest + "/A", "follow/n/" + rootDigest, "forget/n/" + rootDigest + "/A", "follow/n/" + rootDigest + "A"} {
		if _, _, ok := FollowOf(id); ok {
			t.Fatalf("FollowOf(%q) parsed", id)
		}
	}
}

// A follow nonce is lower-case hex (OSS-10w L3): FollowID with a nonce
// holding "/" built an ID whose parse shifted, reading the nonce's tail as
// the digest and the real digest into the name. FollowID makes such a
// nonce unparseable and FollowOf refuses any nonce that is not hex.
func TestOSS10FollowNonceIsHex(t *testing.T) {
	other := strings.Repeat("cd", 32)
	for _, nonce := range []string{"f1/" + rootDigest, "f1/" + rootDigest + "/x", "F1", "f1 ", "g", "", strings.Repeat("a", MaxFollowNonce+1)} {
		if d, name, ok := FollowOf(FollowID(nonce, other, "Acme")); ok {
			t.Fatalf("nonce %q: FollowOf read digest %q name %q", nonce, d, name)
		}
	}
	for _, id := range []string{"follow/zz/" + rootDigest + "/A", "follow/A1/" + rootDigest + "/A"} {
		if _, _, ok := FollowOf(id); ok {
			t.Fatalf("FollowOf(%q) parsed", id)
		}
	}
	if d, name, ok := FollowOf(FollowID(strings.Repeat("0f", MaxFollowNonce/2), rootDigest, "Acme/Fork")); !ok || d != rootDigest || name != "Acme/Fork" {
		t.Fatalf("a hex nonce: %q %q %v", d, name, ok)
	}
}

// The card's fingerprint never carries a run of digits that reads as a
// code, even for an all-digit digest (security R1 on #180, 323-1).
func TestOSS10w2FollowPrintCarriesNoCode(t *testing.T) {
	d := strings.Repeat("1234567890", 6) + "1234"
	if p := FollowPrint(d); p != "1234-5678" || FollowPrint("") != "" {
		t.Fatalf("%q", p)
	}
}
