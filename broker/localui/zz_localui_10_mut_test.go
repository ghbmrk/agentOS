package localui

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"math/rand"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: HW-10, CH-7, CH-9, ONB-3, HW-15
// MUT-kill-localui-10 (#6774): the claim.go, accountplan.go, plansignin.go
// and ifaddrs_linux.go statements that mutgate left alive on #6597, each
// pinned by a test that fails without it.

// mut10Claim is a box claim whose Claim answers tok and err.
type mut10Claim struct {
	tok string
	err error
}

func (c *mut10Claim) Status() claim.Status                  { return claim.Status{TriesLeft: 5} }
func (c *mut10Claim) Claim(string) (string, error)          { return c.tok, c.err }
func (c *mut10Claim) Claimant(tok string) bool              { return tok != "" && tok == c.tok }
func (c *mut10Claim) set(tok string, err error) *mut10Claim { c.tok, c.err = tok, err; return c }

// mut10ClaimRig is a rig whose box claim is c.
func mut10ClaimRig(t *testing.T, c BoxClaim) *rig {
	t.Helper()
	r := newRig(t)
	s, err := New(Config{Page: testPage(), Hooks: r.hooks, SetupSecret: r.card.SetupSecret, Store: &MemStore{},
		Claim: c, Now: r.clock, Rand: rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	r.srv = s
	return r
}

// A setup post before the claim is refused, and only refused: no redirect
// rides on the refusal.
func TestMut10SetupPostBeforeTheClaimIsOnlyRefused(t *testing.T) {
	r := newClaimRig(t)
	w := r.post("/setup/number", url.Values{"number": {ownerNum}})
	if w.Code != http.StatusForbidden || w.Header().Get("Location") != "" {
		t.Fatalf("setup post before the claim: %d, Location %q", w.Code, w.Header().Get("Location"))
	}
}

// Once claimed, the home path is not setup's: another phone is not told
// setup continues elsewhere there.
func TestMut10TheRootIsNotGatedOnceClaimed(t *testing.T) {
	r := newClaimRig(t)
	if w := r.post("/claim", url.Values{"code": {claimCode}}); w.Code != http.StatusSeeOther {
		t.Fatalf("claim: %d", w.Code)
	}
	r.otherPhone()
	if w := r.do("GET", "/", nil); w.Code == http.StatusForbidden || strings.Contains(w.Body.String(), "already claimed") {
		t.Fatalf("GET / on another phone: %d\n%s", w.Code, w.Body.String())
	}
}

// A claim post's body is bounded: a code behind 4 KiB of form is not read.
func TestMut10AClaimPostsBodyIsBounded(t *testing.T) {
	r := newClaimRig(t)
	w := r.post("/claim", url.Values{"code": {claimCode}, "pad": {strings.Repeat("a", 5<<10)}})
	if w.Code == http.StatusSeeOther || r.srv.cfg.Claim.Status().Claimed {
		t.Fatalf("an oversized post claimed the box: %d", w.Code)
	}
}

// A busy answer says when to try again and why.
func TestMut10ABusyClaimSaysSo(t *testing.T) {
	r, c := newFloodRig(t)
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	w := r.do("POST", "/claim", wrongCode, func(q *http.Request) { *q = *q.WithContext(gone) })
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "5" ||
		!strings.Contains(w.Body.String(), html.EscapeString(claimBusy)) || !strings.Contains(w.Body.String(), `name="code"`) {
		t.Fatalf("busy: %d, Retry-After %q\n%s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
	if c.calls.Load() != 0 {
		t.Fatal("a busy post ran Claim")
	}
}

// A claim that succeeds goes to setup and nowhere else, with or without a
// token; a claimed box whose card step failed goes to setup too.
func TestMut10AClaimGoesToSetup(t *testing.T) {
	for _, c := range []*mut10Claim{new(mut10Claim).set("", nil), new(mut10Claim).set("t0k", nil), new(mut10Claim).set("t0k", errors.New("card step"))} {
		r := mut10ClaimRig(t, c)
		w := r.post("/claim", url.Values{"code": {claimCode}})
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/setup" || strings.Contains(w.Body.String(), "could not check") {
			t.Fatalf("claim answering %q, %v: %d %q\n%s", c.tok, c.err, w.Code, w.Header().Get("Location"), w.Body.String())
		}
		if got := len(w.Result().Cookies()) == 1; got != (c.tok != "") {
			t.Fatalf("claim answering %q, %v set cookies %v", c.tok, c.err, w.Result().Cookies())
		}
	}
}

// A refused code shows the claim page once.
func TestMut10ARefusedCodeShowsThePageOnce(t *testing.T) {
	r := newClaimRig(t)
	w := r.post("/claim", url.Values{"code": {"AAAA-BBBB-CCCC-DDDD"}})
	if n := strings.Count(w.Body.String(), `name="code"`); w.Code != http.StatusUnprocessableEntity || n != 1 {
		t.Fatalf("wrong code: %d, %d forms\n%s", w.Code, n, w.Body.String())
	}
}

// Another method is refused with no page after the refusal.
func TestMut10TheClaimPageTakesOnlyGetAndPost(t *testing.T) {
	r := newClaimRig(t)
	w := r.do("PUT", "/claim", nil)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, POST" || strings.Contains(w.Body.String(), `name="code"`) {
		t.Fatalf("PUT: %d %q\n%s", w.Code, w.Header().Get("Allow"), w.Body.String())
	}
}

// The plan screen is its mount's root only, and takes GET and POST only.
func TestMut10ThePlanScreenIsOnlyItsRoot(t *testing.T) {
	r, c := accountPlanRig(t, GmailConnect)
	r.signIn()
	if w := r.do("GET", "/account-plan/other", nil); w.Code != http.StatusNotFound || c.plans != 0 {
		t.Fatalf("GET /account-plan/other: %d, %d plan calls", w.Code, c.plans)
	}
	w := r.do("PUT", "/account-plan/", nil)
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, POST" || strings.Contains(w.Body.String(), "Your accounts") || c.plans != 0 {
		t.Fatalf("PUT: %d %q, %d plan calls\n%s", w.Code, w.Header().Get("Allow"), c.plans, w.Body.String())
	}
}

// A plan post's body is bounded: a choice behind 4 KiB of form is not read.
func TestMut10APlanPostsBodyIsBounded(t *testing.T) {
	r, _ := accountPlanRig(t, GmailConnect)
	r.signIn()
	w := r.post("/account-plan/", url.Values{"id": {"electric-utility"}, "choice": {"later"}, "pad": {strings.Repeat("a", 5<<10)}})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an oversized post: %d\n%s", w.Code, w.Body.String())
	}
	if p := html.UnescapeString(r.get("/account-plan/")); strings.Contains(p, planLater) {
		t.Fatalf("an oversized post was read:\n%s", p)
	}
}

// Set up with a link only redirects: no screen follows the redirect.
func TestMut10SetUpWithALinkOnlyRedirects(t *testing.T) {
	r, _ := accountPlanRig(t, GmailConnect)
	r.signIn()
	w := r.post("/account-plan/", url.Values{"id": {"gmail"}, "choice": {"setup"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/accounts/gmail" || strings.Contains(w.Body.String(), "Your accounts") {
		t.Fatalf("set up Gmail: %d %q\n%s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
}

// An item the table gives no oauth route is listed, even when the box
// declares a Connect step under its ID: the step is not its route.
func TestMut10AConnectStepIsNotARouteTheTableLacks(t *testing.T) {
	d := GmailConnect
	d.ID, d.Name = "payment-wallet", "Payment wallet"
	r, _ := accountPlanRig(t, d)
	r.signIn()
	w := r.post("/account-plan/", url.Values{"id": {"payment-wallet"}, "choice": {"setup"}})
	if p := html.UnescapeString(w.Body.String()); w.Code != 200 || !strings.Contains(p, planListed) || strings.Contains(p, planRefused) {
		t.Fatalf("set up the wallet: %d %q\n%s", w.Code, w.Header().Get("Location"), p)
	}
}

// mut10PlanStart replaces the plan sign-in start in r's owner with answer.
func mut10PlanStart(r *rig, p *pagePlan, answer func() (any, error)) {
	ops := localsrv.New(localsrv.Config{Owner: r.ch, Now: r.clock, PlanSignIn: p}).Ops()
	ops[localapi.OpPlanSignIn] = func(context.Context, sockets.Peer, json.RawMessage) (any, error) { return answer() }
	r.srv.SetOwner(InProcess(ops))
}

// The vault unlock's proof, or a code past MaxCode, is a wrong code here:
// it never reaches agentosd.
func TestMut10APlanSignInTakesNoUnlockProof(t *testing.T) {
	p := &pagePlan{ready: true}
	r := planRig(t, p)
	r.post("/unlock", url.Values{"code": {r.code()}})
	for _, c := range []string{owner.UnlockProofPrefix + "ticket", strings.Repeat("1", localapi.MaxCode+1)} {
		if pg := r.post("/plan/signin", url.Values{"code": {c}}).Body.String(); !strings.Contains(pg, html.EscapeString(wrongCodeText)) || p.started != 0 {
			t.Fatalf("code %.12q… (%d):\n%s", c, p.started, pg)
		}
	}
}

// A start whose call fails says so, even where part of its answer decoded,
// and so does one that answers no link.
func TestMut10APlanSignInWithoutALinkFailed(t *testing.T) {
	for name, answer := range map[string]func() (any, error){
		// The refusal decodes, the link does not: the call fails.
		"a failed call": func() (any, error) {
			return map[string]any{"refusal": localapi.RefusedCodeNeeded, "link": 5}, nil
		},
		"no link": func() (any, error) { return localapi.PlanSignInStarted{}, nil },
	} {
		p := &pagePlan{ready: true}
		r := planRig(t, p)
		mut10PlanStart(r, p, answer)
		r.post("/unlock", url.Values{"code": {r.code()}})
		pg := r.post("/plan/signin", url.Values{"code": {r.code()}}).Body.String()
		if !strings.Contains(pg, html.EscapeString(planFailedText)) || strings.Contains(pg, html.EscapeString(planCodeText)) {
			t.Fatalf("%s:\n%s", name, pg)
		}
	}
}

// mut10Fds is how many descriptors this process holds.
func mut10Fds(t *testing.T) int {
	t.Helper()
	es, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// boxAddrs closes its socket.
func TestMut10BoxAddrsClosesItsSocket(t *testing.T) {
	before := mut10Fds(t)
	for i := 0; i < 32; i++ {
		if _, err := boxAddrs(); err != nil {
			t.Fatal(err)
		}
	}
	if after := mut10Fds(t); after-before >= 32 {
		t.Fatalf("%d descriptors before 32 lists, %d after", before, after)
	}
}

// mut10Ifreq is one struct ifreq of family fam and IPv4 address a.
func mut10Ifreq(fam uint16, a [4]byte) []byte {
	b := make([]byte, ifreqSize)
	copy(b, "eth0")
	b[16], b[17] = byte(fam), byte(fam>>8)
	copy(b[20:24], a[:])
	return b
}

// ifconfAddrs reports the ioctl's error, asks again while the answer fills
// the room given, and lists only IPv4 entries.
func TestMut10IfconfAddrsReadsTheKernelsAnswer(t *testing.T) {
	if _, err := ifconfAddrs(func(*ifconf) syscall.Errno { return syscall.EPERM }); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("a refused ioctl: %v", err)
	}
	calls := 0
	as, err := ifconfAddrs(func(c *ifconf) syscall.Errno {
		calls++
		buf := unsafe.Slice(c.buf, c.len)
		if calls == 1 { // full: maybe cut short
			return 0
		}
		ents := append(mut10Ifreq(syscall.AF_INET6, [4]byte{10, 9, 9, 9}), mut10Ifreq(syscall.AF_INET, [4]byte{10, 42, 0, 1})...)
		c.len = int32(copy(buf, ents))
		return 0
	})
	if err != nil || calls != 2 || len(as) != 1 || as[0] != netip.AddrFrom4([4]byte{10, 42, 0, 1}) {
		t.Fatalf("ifconfAddrs: %v %v after %d calls", as, err, calls)
	}
}
