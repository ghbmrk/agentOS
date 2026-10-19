package main

import (
	"context"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/checker/checkersock"
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/holder"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-4, CH-10, ADP-10

// countingUpstream is the provider: it counts the requests that reach it.
type countingUpstream struct{ n atomic.Int32 }

func (u *countingUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	u.n.Add(1)
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
}

// SIM-split-wire part 4: the owner approves a high-risk request with a
// code-generator code; the broker sends the code to the checker with the
// act over the exact bytes egress will forward, and the credential holder
// spends that approval once, for those bytes only. A body changed after
// approval is refused and never reaches the provider (CH-4, CH-10).
func TestApprovedActPassesOnlyForItsExactBytes(t *testing.T) {
	dir := t.TempDir()
	ck, err := checker.New(checker.Config{StatePath: filepath.Join(dir, "checker.json")})
	if err != nil {
		t.Fatal(err)
	}
	var ls []net.Listener
	for _, name := range []string{checker.HandSocket, checker.VerifySocket, checker.RedeemSocket} {
		l, err := checker.Listen(filepath.Join(dir, name), os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		ls = append(ls, l)
	}
	go ck.Serve(ls[0], ls[1], ls[2])
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	ck.Hand(seed)

	up := &countingUpstream{}
	h, err := holder.New(holder.Config{
		Adapters: []egress.Adapter{{
			Name: "plan", Host: "plan.example", Credential: "plan-login",
			Inject:     egress.Injection{Header: "Authorization", Prefix: "Bearer "},
			Operations: []egress.Operation{{Name: "send", Verb: egress.VerbSend, Method: "POST", Path: "/v1/send"}},
		}},
		Transport: up,
		Redeem:    checker.Redeemer(filepath.Join(dir, checker.RedeemSocket)),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Hand([]byte("CANARY-holder-secret-0001"))

	carrier := modem.NewCarrier()
	box := carrier.Line("+15550000100")
	phone := carrier.Line(ownerNum)
	ch, err := owner.New(owner.Config{
		Owner: ownerNum, Modem: box, Engine: pacingEngine{}, Store: &owner.MemStore{},
		Verifier: ownerVerifier{checker: checkersock.VerifyClient(filepath.Join(dir, checker.VerifySocket))},
		Limits:   owner.Limits{Hold: time.Hour, AmountLimit: 10000},
		Location: time.UTC,
	})
	if err != nil {
		t.Fatal(err)
	}

	approved, changed := `{"to":"acct-4821","amount":25000}`, `{"to":"acct-9999","amount":25000}`
	it := owner.Item{Ref: "pay-1", Object: "invoice 77", Recipient: "acct ...4821", Amount: "$250.00",
		Act: checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(approved)),
		Facts: owner.Facts{Verb: "pay", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true,
			HasAmount: true, Amount: 25000}}
	id, err := ch.Request([]owner.Item{it}, 0)
	if err != nil {
		t.Fatal(err)
	}
	ch.WaitSends()
	select {
	case <-phone.Inbox():
	case <-time.After(2 * time.Second):
		t.Fatal("no approval text")
	}

	send := func(body string) *http.Response {
		req := httptest.NewRequest("POST", "http://plan.example/v1/send", strings.NewReader(body))
		req.Host = "plan.example"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Result()
	}
	// Before the owner answers, nothing is approved.
	if r := send(approved); r.StatusCode != http.StatusForbidden || r.Header.Get(holder.ErrorHeader) != holder.ErrUnapproved {
		t.Fatalf("before approval: %d %q", r.StatusCode, r.Header.Get(holder.ErrorHeader))
	}

	if got := strings.Join(ch.Handle(context.Background(), ownerNum, "YES "+id+" "+code(seed, time.Now())), " | "); got != "Approved "+id+"." {
		t.Fatalf("YES: %q", got)
	}
	if r := send(changed); r.StatusCode != http.StatusForbidden || r.Header.Get(holder.ErrorHeader) != holder.ErrUnapproved {
		t.Fatalf("changed body: %d %q", r.StatusCode, r.Header.Get(holder.ErrorHeader))
	}
	if r := send(approved); r.StatusCode != http.StatusOK {
		t.Fatalf("approved body: %d %q", r.StatusCode, r.Header.Get(holder.ErrorHeader))
	}
	if r := send(approved); r.StatusCode != http.StatusForbidden || r.Header.Get(holder.ErrorHeader) != holder.ErrUnapproved {
		t.Fatalf("approval spent twice: %d", r.StatusCode)
	}
	if n := up.n.Load(); n != 1 {
		t.Fatalf("%d requests reached the provider, want 1", n)
	}
}
