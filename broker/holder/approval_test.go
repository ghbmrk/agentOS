package holder

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/checker/checkersock"
	"github.com/ghbmrk/agentos/broker/egress"
)

// REQ: CH-4, CH-10, CRED-1, ADP-10

// totp is the owner's code-generator code at t (RFC 6238, SHA-1, 30 s).
func totp(seed []byte, t time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

func seededChecker(t *testing.T) (*checker.Checker, []byte) {
	t.Helper()
	c, err := checker.New(checker.Config{StatePath: filepath.Join(t.TempDir(), "checker.json")})
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	c.Hand(seed)
	return c, seed
}

func approvingHolder(t *testing.T, up *upstream, redeem func(context.Context, string) (bool, error)) *Holder {
	t.Helper()
	a := planAdapter()
	a.Operations = append(a.Operations, egress.Operation{Name: "draft", Verb: egress.VerbDraft, Method: "POST", Path: "/v1/draft"})
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
// that exact request, once: no code, a wrong code, or a code for another
// body sends nothing (CH-4, CH-10). A compromised egress that holds no
// owner code cannot spend the login on a send.
func TestHighRiskActNeedsACheckerVerifiedCode(t *testing.T) {
	c, seed := seededChecker(t)
	up := &upstream{reply: answer(200, nil, "{}")}
	h := approvingHolder(t, up, func(_ context.Context, act string) (bool, error) { return c.Redeem(act), nil })
	body := `{"to":"canary@example.invalid"}`
	act := checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(body))

	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrUnapproved {
		t.Fatalf("no code: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	wrong := "000000"
	if wrong == totp(seed, time.Now()) {
		wrong = "000001"
	}
	if _, ok, _ := c.Verify(wrong, 0, true, []checkersock.Act{{Act: act}}); ok {
		t.Fatal("a wrong code verified")
	}
	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusForbidden {
		t.Fatalf("wrong code: %d", w.Code)
	}
	other := checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(`{"to":"other@example.invalid"}`))
	if _, ok, err := c.Verify(totp(seed, time.Now()), 0, true, []checkersock.Act{{Act: other}}); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusForbidden {
		t.Fatalf("code for another body: %d", w.Code)
	}
	if up.calls() != 0 {
		t.Fatalf("provider reached %d times before an approval", up.calls())
	}
	// That code's step is spent, so the owner's code for this act is the
	// next one; a second checker stands in for it rather than waiting a step.
	c2, seed2 := seededChecker(t)
	h2 := approvingHolder(t, up, func(_ context.Context, act string) (bool, error) { return c2.Redeem(act), nil })
	if _, ok, err := c2.Verify(totp(seed2, time.Now()), 0, true, []checkersock.Act{{Act: act}}); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if w := do(h2, req("POST", "/v1/send", body)); w.Code != http.StatusOK {
		t.Fatalf("approved act: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	if w := do(h2, req("POST", "/v1/send", body)); w.Code != http.StatusForbidden || w.Header().Get(ErrorHeader) != ErrUnapproved {
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

// Reads need no approval; draft and organize are still not the holder's to
// serve, approval or not.
func TestApprovalCoversHighRiskVerbsOnly(t *testing.T) {
	c, _ := seededChecker(t)
	up := &upstream{reply: answer(200, nil, "{}")}
	asked := 0
	h := approvingHolder(t, up, func(_ context.Context, act string) (bool, error) { asked++; return c.Redeem(act), nil })
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

// Over the checker's real redeem socket: an approval made through the
// verify socket is spent by the holder, and an unreachable checker sends
// nothing.
func TestHolderRedeemsOverTheCheckerSocket(t *testing.T) {
	c, seed := seededChecker(t)
	dir, err := os.MkdirTemp("", "hchk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	me := os.Getuid()
	hand, err := checker.Listen(filepath.Join(dir, checker.HandSocket), me)
	if err != nil {
		t.Fatal(err)
	}
	verify, err := checker.Listen(filepath.Join(dir, checker.VerifySocket), me)
	if err != nil {
		t.Fatal(err)
	}
	redeem, err := checker.Listen(filepath.Join(dir, checker.RedeemSocket), me)
	if err != nil {
		t.Fatal(err)
	}
	go c.Serve(hand, verify, redeem)

	up := &upstream{reply: answer(200, nil, "{}")}
	h := approvingHolder(t, up, checker.Redeemer(filepath.Join(dir, checker.RedeemSocket)))
	body := `{"to":"canary@example.invalid"}`
	act := checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(body))
	if _, ok, err := checkersock.VerifyClient(filepath.Join(dir, checker.VerifySocket)).VerifyTOTP(totp(seed, time.Now()), 0, true, checkersock.Act{Act: act}); !ok || err != nil {
		t.Fatalf("verify: %v %v", ok, err)
	}
	if w := do(h, req("POST", "/v1/send", body)); w.Code != http.StatusOK {
		t.Fatalf("approved act: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}

	down := approvingHolder(t, up, checker.Redeemer(filepath.Join(dir, "absent.sock")))
	if w := do(down, req("POST", "/v1/send", body)); w.Code != http.StatusServiceUnavailable || w.Header().Get(ErrorHeader) != ErrUnapproved {
		t.Fatalf("checker down: %d %q", w.Code, w.Header().Get(ErrorHeader))
	}
	if up.calls() != 1 {
		t.Fatalf("provider reached %d times, want 1", up.calls())
	}
}
