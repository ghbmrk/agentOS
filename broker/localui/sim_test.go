package localui

import (
	"html"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
)

// REQ: CH-1, CH-7, CH-19

const simTag = "0123456789abcdef"

// simRig serves the home page with a swapped owner line whose modem holds
// a SIM the owner may adopt; adopted records each SIM agentosd took.
func simRig(t *testing.T) (*rig, *[]string) {
	r := newRig(t)
	r.runSetup()
	r.startChannel(nil)
	var adopted []string
	line := localapi.Line{Note: "The SIM in my phone modem changed. Texts to and from you are paused until you confirm it below.", SIM: simTag, SIMEnds: "2345"}
	r.srv.SetOwner(InProcess(localsrv.New(localsrv.Config{Owner: r.ch, Now: r.clock,
		Line: func() localapi.Line { return line },
		AdoptSIM: func(tag string) error {
			if tag != simTag {
				return localsrv.ErrStaleSIM
			}
			adopted = append(adopted, tag)
			return nil
		}}).Ops()))
	return r, &adopted
}

// P2-2w d2b: the home page's "below" is a form to adopt the SIM it names
// by its last four digits, and it always asks for a code (CH-19: a SIM
// swapper holds none).
func TestHomeOffersTheSIMToConfirm(t *testing.T) {
	r, adopted := simRig(t)
	r.post("/unlock", url.Values{"code": {r.code()}})
	p := r.get("/home")
	for _, s := range []string{`action="/line/sim"`, `value="` + simTag + `"`, "Use the SIM ending in 2345 for my number", `name="code"`, html.EscapeString("only if you put")} {
		if !strings.Contains(p, s) {
			t.Errorf("home lacks %q:\n%s", s, p)
		}
	}
	// Fresh from sign-in, still no code: no SIM is adopted.
	p = r.post("/line/sim", url.Values{"sim": {simTag}}).Body.String()
	if !strings.Contains(p, html.EscapeString(simCodeText)) || len(*adopted) != 0 {
		t.Fatalf("adopted without a code (%v):\n%s", *adopted, p)
	}
	p = r.post("/line/sim", url.Values{"sim": {simTag}, "code": {"000000"}}).Body.String()
	if !strings.Contains(p, html.EscapeString(wrongCodeText)) || len(*adopted) != 0 {
		t.Fatalf("adopted on a wrong code (%v):\n%s", *adopted, p)
	}
	p = r.post("/line/sim", url.Values{"sim": {simTag}, "code": {r.code()}}).Body.String()
	if !strings.Contains(p, html.EscapeString(localsrv.SIMAdopted)) || len(*adopted) != 1 {
		t.Fatalf("not adopted (%v):\n%s", *adopted, p)
	}
}

// A SIM other than the one shown is refused as an out-of-date page.
func TestAStaleSIMFormSaysReload(t *testing.T) {
	r, adopted := simRig(t)
	r.post("/unlock", url.Values{"code": {r.code()}})
	p := r.post("/line/sim", url.Values{"sim": {"fedcba9876543210"}, "code": {r.code()}}).Body.String()
	if !strings.Contains(p, html.EscapeString(simStaleText)) || len(*adopted) != 0 {
		t.Fatalf("stale SIM (%v):\n%s", *adopted, p)
	}
}

// Signed out, the form is not served and a post adopts nothing; only POST
// is taken.
func TestTheSIMFormNeedsASignIn(t *testing.T) {
	r, adopted := simRig(t)
	if w := r.post("/line/sim", url.Values{"sim": {simTag}, "code": {r.code()}}); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/unlock") {
		t.Fatalf("signed out: %d %s", w.Code, w.Header().Get("Location"))
	}
	r.post("/unlock", url.Values{"code": {r.code()}})
	if w := r.do(http.MethodGet, "/line/sim", nil); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", w.Code)
	}
	if len(*adopted) != 0 {
		t.Fatalf("adopted: %v", *adopted)
	}
}
