package holder

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CH-4, CH-10, CRED-1, ADP-10

// approvals stands in for the checker's approval store, which a verified
// owner code or the broker's allow fills: each approval is redeemed at
// most once, and an allowed one never serves a secret act (CH-10, ADP-9).
type approvals struct {
	mu sync.Mutex
	m  map[string]bool // act -> allowed rather than code-approved
}

func newApprovals() *approvals { return &approvals{m: map[string]bool{}} }

func (a *approvals) approve(act string) { a.mu.Lock(); a.m[act] = false; a.mu.Unlock() }
func (a *approvals) allow(act string)   { a.mu.Lock(); a.m[act] = true; a.mu.Unlock() }

// redeem is a holder's Redeem, served in process.
func (a *approvals) redeem(_ context.Context, act string, secret bool) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	allowed, ok := a.m[act]
	if !ok || (secret && allowed) {
		return false, nil
	}
	delete(a.m, act)
	return true, nil
}

// serve serves the redeem socket's POST /redeem at path: 204 spends an
// approval, 403 means none.
func (a *approvals) serve(t *testing.T, path string) {
	t.Helper()
	ln, err := sockets.ListenPeers(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /redeem", func(w http.ResponseWriter, r *http.Request) {
		var req checker.RedeemRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if ok, _ := a.redeem(r.Context(), req.Act, req.Secret); !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

func approvingHolder(t *testing.T, up *upstream, redeem func(context.Context, string, bool) (bool, error)) *Holder {
	t.Helper()
	a := planAdapter()
	a.Operations = append(a.Operations,
		egress.Operation{Name: "draft", Verb: egress.VerbDraft, Method: "POST", Path: "/v1/draft"},
		egress.Operation{Name: "reveal", Verb: egress.VerbRevealSecret, Method: "POST", Path: "/v1/keys"})
	h, err := New(Config{Adapters: []egress.Adapter{a}, Transport: up, Swapper: &swapper{}, Redeem: redeem})
	if err != nil {
		t.Fatal(err)
	}
	h.Hand([]byte(canary(t, "sk-canary-")))
	return h
}

func do(h *Holder, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// A high-risk act reaches the provider only with the checker's approval for
// that exact request, once: no approval, or an approval for another body,
// sends nothing (CH-4, CH-10). A compromised egress that holds no owner
// code, and so gets no approval, cannot spend the login on a send.
func TestHighRiskActNeedsACheckerVerifiedCode(t *testing.T) {
	c := newApprovals()
	up := &upstream{reply: answer(200, nil, "{}")}
	h := approvingHolder(t, up, c.redeem)
	body := `{"to":"canary@example.invalid"}`
	act := checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(body))

	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrUnapproved {
		t.Fatalf("no approval: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	c.approve(checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(`{"to":"other@example.invalid"}`)))
	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusForbidden {
		t.Fatalf("approval for another body: %d", w.Code)
	}
	if up.calls() != 0 {
		t.Fatalf("provider reached %d times before an approval", up.calls())
	}
	c.approve(act)
	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusOK {
		t.Fatalf("approved act: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrUnapproved {
		t.Fatalf("replayed act: %d", w.Code)
	}
	if up.calls() != 1 {
		t.Fatalf("provider reached %d times, want 1", up.calls())
	}
	got := up.seen[0]
	if got.Header.Get("Authorization") == "" || got.URL.Path != "/v1/send" {
		t.Fatalf("sent %s %v", got.URL.Path, got.Header)
	}
}

// REQ: CH-4, ADP-9
// An allowed approval (the broker's record of a low-tier or grid answer)
// serves an irreversible act but never a secret one: a broker taken over
// can let a send through but cannot reveal a secret.
func TestAllowedApprovalServesNoSecretAct(t *testing.T) {
	c := newApprovals()
	up := &upstream{reply: answer(200, nil, "{}")}
	h := approvingHolder(t, up, c.redeem)
	send := checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte("{}"))
	reveal := checker.Act("plan-login", "plan.example", "POST", "/v1/keys", []byte("{}"))
	c.allow(send)
	c.allow(reveal)
	if w := do(h, req("POST", "/v1/keys", "{}")); w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrUnapproved {
		t.Fatalf("allowed secret act: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	if w := do(h, req("POST", "/v1/send", "{}")); w.Code != http.StatusOK {
		t.Fatalf("allowed irreversible act: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	if up.calls() != 1 || up.seen[0].URL.Path != "/v1/send" {
		t.Fatalf("provider reached %d times", up.calls())
	}
}

// Reads need no approval; draft and organize are still not the holder's to
// serve, approval or not.
func TestApprovalCoversHighRiskVerbsOnly(t *testing.T) {
	c := newApprovals()
	up := &upstream{reply: answer(200, nil, "{}")}
	asked := 0
	h := approvingHolder(t, up, func(ctx context.Context, act string, secret bool) (bool, error) {
		asked++
		return c.redeem(ctx, act, secret)
	})
	if w := do(h, req("POST", "/v1/messages", "{}")); w.Code != http.StatusOK {
		t.Fatalf("read: %d", w.Code)
	}
	if w := do(h, req("POST", "/v1/draft", "{}")); w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrRefused {
		t.Fatalf("draft: %d", w.Code)
	}
	if asked != 0 {
		t.Fatalf("checker consulted %d times for verbs it does not gate", asked)
	}
}

// Over a redeem socket, through the production client: an approval is
// spent by the holder once, and an unreachable checker sends nothing.
func TestHolderRedeemsOverTheCheckerSocket(t *testing.T) {
	c := newApprovals()
	dir := socketDir(t)
	path := filepath.Join(dir, "redeem.sock")
	c.serve(t, path)

	up := &upstream{reply: answer(200, nil, "{}")}
	h := approvingHolder(t, up, checker.Redeemer(path))
	body := `{"to":"canary@example.invalid"}`
	c.approve(checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(body)))
	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusOK {
		t.Fatalf("approved act: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrUnapproved {
		t.Fatalf("replayed act: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}

	down := approvingHolder(t, up, checker.Redeemer(filepath.Join(dir, "absent.sock")))
	if w := do(down, req("POST", "/v1/send", body)); w.Code != http.StatusServiceUnavailable || w.Header().Get(ErrorHeader) != ErrUnapproved {
		t.Fatalf("checker down: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	if up.calls() != 1 {
		t.Fatalf("provider reached %d times, want 1", up.calls())
	}
}

// REQ: CH-4, ADP-9
// The holder classes a request by the first operation that matches, so a
// broader operation declared before a secret one could carry a secret
// request as irreversible, which an allowed approval serves. An adapter
// whose secret operation can match the same request as another one is
// refused at load (#2514 L3 blocker 1).
func TestASecretOperationCannotBeShadowed(t *testing.T) {
	for name, ops := range map[string][]egress.Operation{
		"broader first": {
			{Name: "send", Verb: egress.VerbSend, Method: "POST", Path: "/v1/{thing}"},
			{Name: "reveal", Verb: egress.VerbRevealSecret, Method: "POST", Path: "/v1/keys"},
		},
		"broader after": {
			{Name: "reveal", Verb: egress.VerbRevealSecret, Method: "POST", Path: "/v1/keys"},
			{Name: "send", Verb: egress.VerbSend, Method: "POST", Path: "/v1/{thing}"},
		},
		"same path": {
			{Name: "send", Verb: egress.VerbSend, Method: "POST", Path: "/v1/keys"},
			{Name: "reveal", Verb: egress.VerbRevealSecret, Method: "POST", Path: "/v1/keys"},
		},
	} {
		a := planAdapter()
		a.Operations = append(a.Operations, ops...)
		if _, err := New(Config{Adapters: []egress.Adapter{a}, Transport: &upstream{}, Swapper: &swapper{}}); err == nil {
			t.Errorf("%s: an adapter with a shadowable secret operation loaded", name)
		}
	}
	// Another method, or another path length, cannot match the same request.
	a := planAdapter()
	a.Operations = append(a.Operations,
		egress.Operation{Name: "send", Verb: egress.VerbSend, Method: "PUT", Path: "/v1/{thing}"},
		egress.Operation{Name: "list", Verb: egress.VerbRead, Method: "POST", Path: "/v1/keys/{id}"},
		egress.Operation{Name: "reveal", Verb: egress.VerbRevealSecret, Method: "POST", Path: "/v1/keys"})
	if _, err := New(Config{Adapters: []egress.Adapter{a}, Transport: &upstream{}, Swapper: &swapper{}}); err != nil {
		t.Fatalf("disjoint operations: %v", err)
	}
}
