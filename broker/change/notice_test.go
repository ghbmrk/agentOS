package change

import (
	"fmt"
	"testing"
)

// REQ: CH-15, CHG-6

// W3-route (UX-108-1): a broker notice is a digest line, never a text of
// its own. Notice keeps it once per key, across a restart; the digest
// lists it once; the kept keys are bounded.
func TestNoticesAreDigestLinesOncePerKey(t *testing.T) {
	e := newEnv(t, nil)
	e.p.Digest()
	if err := e.p.Notice("routing:a", "Line A."); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Notice("routing:a", "Line A."); err != nil {
		t.Fatal(err)
	}
	if got := e.p.Digest(); len(got) != 1 || got[0] != "Line A." {
		t.Fatalf("digest: %q", got)
	}
	if got := e.p.Digest(); len(got) != 0 {
		t.Fatalf("listed twice: %q", got)
	}
	// After a restart the same key is still known: no second line.
	p, err := New(Config{Store: e.store, Evaluator: e.ev})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Notice("routing:a", "Line A."); err != nil {
		t.Fatal(err)
	}
	if got := p.Digest(); len(got) != 0 {
		t.Fatalf("a restart repeated a notice: %q", got)
	}
	// A notice not yet listed survives a restart.
	if err := p.Notice("routing:b", "Line B."); err != nil {
		t.Fatal(err)
	}
	p, err = New(Config{Store: e.store, Evaluator: e.ev})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Digest(); len(got) != 1 || got[0] != "Line B." {
		t.Fatalf("after a restart: %q", got)
	}
	for i := 0; i < 2*MaxNotices; i++ {
		if err := p.Notice(fmt.Sprintf("k%d", i), "x"); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(p.st.Notices); n > MaxNotices {
		t.Fatalf("%d notices kept", n)
	}
}
