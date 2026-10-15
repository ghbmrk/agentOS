package owner

import (
	"crypto/rand"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

// REQ: CH-18, CH-11

// codeRand serves the 6-digit code draws (reads of 3 or more bytes) from
// script, then from the real source; shorter reads (request IDs) are real.
// Each script entry is the fill byte of one draw: 0 draws "000000", 1 draws
// 65793 ("065793").
type codeRand struct {
	script []byte
	n      atomic.Int32
	loop   bool
}

func (r *codeRand) Read(p []byte) (int, error) {
	if len(p) < 3 {
		return rand.Read(p)
	}
	i := int(r.n.Add(1)) - 1
	if i >= len(r.script) {
		if !r.loop {
			return rand.Read(p)
		}
		i = len(r.script) - 1
	}
	for j := range p {
		p[j] = r.script[i]
	}
	return len(p), nil
}

var _ io.Reader = (*codeRand)(nil)

func lowCodeOf(t *testing.T, ch *Channel, id string) string {
	t.Helper()
	ch.mu.Lock()
	defer ch.mu.Unlock()
	r := ch.open[id]
	if r == nil || r.tier != Low {
		t.Fatalf("request %s: not an open low-tier request", id)
	}
	return r.code
}

// A low-tier code is redrawn while it collides with an open low-tier code,
// so an ID-less YES cannot approve the other request.
func TestLowCodesAreUniqueAmongOpenRequests(t *testing.T) {
	cr := &codeRand{script: []byte{0, 0, 1}}
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.Rand = cr }
	r.ch = r.open()
	a, err := r.ch.Request([]Item{lowItem("a")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.ch.Request([]Item{lowItem("b")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	ca, cb := lowCodeOf(t, r.ch, a), lowCodeOf(t, r.ch, b)
	if ca != "000000" || cb != "065793" {
		t.Fatalf("codes %q and %q, want 000000 redrawn to 065793", ca, cb)
	}
}

// A source that keeps colliding is refused after a bounded number of draws.
func TestLowCodeCollisionIsBounded(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.Rand = &codeRand{script: []byte{0}, loop: true} }
	r.ch = r.open()
	if _, err := r.ch.Request([]Item{lowItem("a")}, 0); err != nil {
		t.Fatal(err)
	}
	if id, err := r.ch.Request([]Item{lowItem("b")}, 0); err == nil {
		t.Fatalf("second request %s opened with a colliding code", id)
	}
	// The refusal leaves no state: no Pending entry a restart would re-issue.
	r.ch.mu.Lock()
	open, pending := len(r.ch.open), len(r.ch.codes.st.Pending)
	r.ch.mu.Unlock()
	if open != 1 || pending != 1 {
		t.Fatalf("%d requests open and %d pending, want 1 and 1", open, pending)
	}
}

// An ID-less YES <code> with two low-tier requests open approves exactly
// the one whose code it names and leaves the other open.
func TestIDLessYesApprovesNamedRequestOnly(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.Rand = &codeRand{script: []byte{0, 1}} }
	r.ch = r.open()
	a, err := r.ch.Request([]Item{lowItem("a")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.ch.Request([]Item{lowItem("b")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cb := lowCodeOf(t, r.ch, b); cb != "065793" {
		t.Fatalf("code of %s is %q, want 065793", b, cb)
	}
	r.decisions()
	// A code that names neither request binds to none of them.
	if got := r.say("YES 999999"); !strings.HasPrefix(got, "Wrong code.") {
		t.Fatalf("YES 999999: %q, want a reply starting \"Wrong code.\"", got)
	}
	if ds := r.decisions(); len(ds) != 0 {
		t.Fatalf("YES 999999 recorded decisions %+v, want none", ds)
	}
	if got := r.say("YES 065793"); got != "Approved "+b+"." {
		t.Fatalf("YES 065793: %q, want approval of %s", got, b)
	}
	ds := r.decisions()
	if len(ds) != 1 || ds[0].Request != b || ds[0].Ref != "b" || !ds[0].Approved {
		t.Fatalf("decisions %+v, want one approval of %s", ds, b)
	}
	r.ch.mu.Lock()
	_, aOpen := r.ch.open[a]
	_, bOpen := r.ch.open[b]
	r.ch.mu.Unlock()
	if !aOpen || bOpen {
		t.Fatalf("open after YES: %s=%v %s=%v, want only %s open", a, aOpen, b, bOpen, a)
	}
}
