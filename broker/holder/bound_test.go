package holder

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/checker/checkersock"
	"github.com/ghbmrk/agentos/broker/egress"
)

// REQ: CH-10, CRED-1, ADP-10

// An approval names the account whose login spends it: account A's
// approval for an act is refused by account B's holder for the same bytes,
// even with one checker and one redeem socket shared by both (CH-10).
func TestApprovalIsBoundToTheAccount(t *testing.T) {
	c, seed := seededChecker(t)
	up := &upstream{reply: answer(200, nil, "{}")}
	redeem := func(_ context.Context, act string) (bool, error) { return c.Redeem(act), nil }
	hA := approvingHolder(t, up, redeem)
	b := planAdapter()
	b.Credential = "plan-login-b"
	hB, err := New(Config{Adapters: []egress.Adapter{b}, Transport: up, Swapper: &swapper{}, Redeem: redeem})
	if err != nil {
		t.Fatal(err)
	}
	hB.Hand([]byte(canary(t, "sk-canary-b-")))

	body := `{"to":"canary@example.invalid"}`
	actA := checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(body))
	if _, ok, err := c.Verify(totp(seed, time.Now()), 0, true, []checkersock.Act{{Act: actA}}); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if w := do(hB, req("POST", "/v1/send", body)); w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrUnapproved {
		t.Fatalf("account B spent A's approval: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	if up.calls() != 0 {
		t.Fatalf("provider reached %d times through the wrong account", up.calls())
	}
	if w := do(hA, req("POST", "/v1/send", body)); w.Code != http.StatusOK {
		t.Fatalf("account A's own approval: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
}

// A redeem that fails, or that the checker answers with anything but its
// two words, sends nothing upstream (CH-10).
func TestRedeemErrorSendsNothing(t *testing.T) {
	up := &upstream{reply: answer(200, nil, "{}")}
	h := approvingHolder(t, up, func(context.Context, string) (bool, error) {
		return true, errors.New("checker: redeem: 500 Internal Server Error")
	})
	if w := do(h, req("POST", "/v1/send", `{"to":"canary@example.invalid"}`)); w.Code != http.StatusServiceUnavailable || w.Header().Get(ErrorHeader) != ErrUnapproved {
		t.Fatalf("redeem error: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	if up.calls() != 0 {
		t.Fatalf("provider reached %d times after a redeem error", up.calls())
	}
}

// Over a real socket a checker answering 500 is no approval, end to end.
func TestRedeemAnswered500SendsNothing(t *testing.T) {
	dir := socketDir(t)
	path := dir + "/redeem.sock"
	ln, err := checker.Listen(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })}
	go srv.Serve(ln)
	defer srv.Close()
	up := &upstream{reply: answer(200, nil, "{}")}
	h := approvingHolder(t, up, checker.Redeemer(path))
	if w := do(h, req("POST", "/v1/send", `{"to":"canary@example.invalid"}`)); w.Code == http.StatusOK {
		t.Fatalf("a 500 from the checker approved: %d", w.Code)
	}
	if up.calls() != 0 {
		t.Fatalf("provider reached %d times after a 500 redeem", up.calls())
	}
}

func modelHolder(t *testing.T, up *upstream, publicFetch bool) *Holder {
	t.Helper()
	h, err := New(Config{Adapters: []egress.Adapter{egress.OpenAI("openai-key")}, Transport: up, PublicFetch: publicFetch})
	if err != nil {
		t.Fatal(err)
	}
	h.Hand([]byte(canary(t, "sk-canary-")))
	return h
}

func chatReq(body, label string) *http.Request {
	r := httptest.NewRequest("POST", "http://api.openai.com/v1/chat/completions", strings.NewReader(body))
	r.Host = "api.openai.com"
	r.Header.Set("Content-Type", "application/json")
	if label != "" {
		r.Header.Set(egress.LabelHeader, label)
	}
	return r
}

// The holder holds the body to the operation's rule itself (ADP-10): a body
// switching on provider-side tools is refused even when egress forwards it,
// and even when egress claims the machine is public, unless the owner let
// public machines fetch with this login. A login so opened still serves a
// public machine what egress serves it, so the holder narrows nothing.
func TestHolderAppliesTheBodyRule(t *testing.T) {
	model := `"model":"m","messages":[{"role":"user","content":"hi"}]`
	tools := map[string]string{
		"mcp_servers":        `{` + model + `,"mcp_servers":[{"url":"https://attacker.invalid"}]}`,
		"web_search_options": `{` + model + `,"web_search_options":{}}`,
		"server tool":        `{` + model + `,"tools":[{"type":"web_search"}]}`,
		"denied key":         `{` + model + `,"background":true}`,
		"not an object":      `[1]`,
		"trailing data":      `{` + model + `} {}`,
	}
	up := &upstream{reply: answer(200, nil, "{}")}
	strict := modelHolder(t, up, false)
	for name, body := range tools {
		for _, label := range []string{"", "private", egress.LabelPublic} {
			if w := do(strict, chatReq(body, label)); w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrRefused {
				t.Errorf("%s labelled %q: %d %q", name, label, w.Code, w.Header().Get(ErrorHeader))
			}
		}
	}
	if up.calls() != 0 {
		t.Fatalf("provider reached %d times with a refused body", up.calls())
	}

	// What is sent is the holder's own encoding, with the rule's fields set.
	if w := do(strict, chatReq(`{`+model+`}`, "")); w.Code != http.StatusOK {
		t.Fatalf("plain chat: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	got := up.bodies[len(up.bodies)-1]
	if !strings.Contains(got, `"store":false`) {
		t.Fatalf("sent body skipped the rule: %s", got)
	}
	if v := up.seen[len(up.seen)-1].Header.Get(egress.LabelHeader); v != "" {
		t.Fatalf("label header forwarded upstream: %q", v)
	}

	open := modelHolder(t, up, true)
	before := up.calls()
	if w := do(open, chatReq(tools["web_search_options"], egress.LabelPublic)); w.Code != http.StatusOK {
		t.Fatalf("public machine on an opened login: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	for _, label := range []string{"", "private", "PUBLIC"} {
		if w := do(open, chatReq(tools["mcp_servers"], label)); w.Code != http.StatusForbidden {
			t.Errorf("label %q on an opened login: %d", label, w.Code)
		}
	}
	if w := do(open, chatReq(tools["denied key"], egress.LabelPublic)); w.Code != http.StatusForbidden {
		t.Errorf("denied key from a public machine: %d", w.Code)
	}
	if up.calls() != before+1 {
		t.Fatalf("provider reached %d times, want %d", up.calls(), before+1)
	}
}
