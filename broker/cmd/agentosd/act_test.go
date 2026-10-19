package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
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
// actRig is a running checker, a holder for one send operation that
// spends its approvals, and an owner channel that verifies with it.
type actRig struct {
	seed  []byte
	h     *holder.Holder
	up    *countingUpstream
	ch    *owner.Channel
	phone *modem.Line
}

func newActRig(t *testing.T) *actRig {
	t.Helper()
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

	return &actRig{seed: seed, h: h, up: up, ch: ch, phone: phone}
}

// send is the agent's request through the holder.
func (a *actRig) send(body string) *http.Response {
	req := httptest.NewRequest("POST", "http://plan.example/v1/send", strings.NewReader(body))
	req.Host = "plan.example"
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, req)
	return w.Result()
}

func (a *actRig) text(t *testing.T) string {
	t.Helper()
	a.ch.WaitSends()
	select {
	case m := <-a.phone.Inbox():
		return m.Text
	case <-time.After(2 * time.Second):
		t.Fatal("no text")
	}
	return ""
}

func TestApprovedActPassesOnlyForItsExactBytes(t *testing.T) {
	a := newActRig(t)
	approved, changed := `{"to":"acct-4821","amount":25000}`, `{"to":"acct-9999","amount":25000}`
	it := owner.Item{Ref: "pay-1", Object: "invoice 77", Recipient: "acct ...4821", Amount: "$250.00",
		Act: checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(approved)),
		Facts: owner.Facts{Verb: "pay", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true,
			HasAmount: true, Amount: 25000}}
	id, err := a.ch.Request([]owner.Item{it}, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.text(t)
	send := a.send
	// Before the owner answers, nothing is approved.
	if r := send(approved); r.StatusCode != http.StatusForbidden || r.Header.Get(holder.ErrorHeader) != holder.ErrUnapproved {
		t.Fatalf("before approval: %d %q", r.StatusCode, r.Header.Get(holder.ErrorHeader))
	}

	if got := strings.Join(a.ch.Handle(context.Background(), ownerNum, "YES "+id+" "+code(a.seed, time.Now())), " | "); got != "Approved "+id+"." {
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
	if n := a.up.n.Load(); n != 1 {
		t.Fatalf("%d requests reached the provider, want 1", n)
	}
}

// A held act cannot be spent while its UNDO can still stop it: the checker
// opens its approval only as the undo window ends, and UNDO withdraws it,
// so a cancelled effect never reaches the provider (REV-3, CH-4).
func TestAHeldActRunsOnlyAfterItsWindowAndNotAfterUndo(t *testing.T) {
	a := newActRig(t)
	kept, undone := `{"to":"acct-4821","amount":25000}`, `{"to":"acct-4821","amount":25001}`
	item := func(ref, body string) owner.Item {
		return owner.Item{Ref: ref, Object: "invoice 77", Recipient: "acct ...4821", Amount: "$250.00",
			Act:        checker.Act("plan-login", "plan.example", "POST", "/v1/send", []byte(body)),
			UndoWindow: 2 * time.Second,
			Facts: owner.Facts{Verb: "pay", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true,
				HasAmount: true, Amount: 25000}}
	}
	id, err := a.ch.Request([]owner.Item{item("keep", kept), item("undo", undone)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	a.text(t)
	got := strings.Join(a.ch.Handle(context.Background(), ownerNum, "YES "+id+" "+code(a.seed, time.Now())), " | ")
	m := regexp.MustCompile(`([A-Z][0-9]{1,2}) for 2`).FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("confirmation: %q", got)
	}
	if r := a.send(kept); r.StatusCode != http.StatusForbidden {
		t.Fatalf("held act spent inside its window: %d", r.StatusCode)
	}
	if got := strings.Join(a.ch.Handle(context.Background(), ownerNum, "UNDO "+m[1]), " | "); got != "Cancelled "+m[1]+". It did not run." {
		t.Fatalf("undo: %q", got)
	}
	time.Sleep(1500 * time.Millisecond)
	if r := a.send(undone); r.StatusCode != http.StatusForbidden || r.Header.Get(holder.ErrorHeader) != holder.ErrUnapproved {
		t.Fatalf("undone act: %d %q", r.StatusCode, r.Header.Get(holder.ErrorHeader))
	}
	if r := a.send(kept); r.StatusCode != http.StatusOK {
		t.Fatalf("held act after its window: %d %q", r.StatusCode, r.Header.Get(holder.ErrorHeader))
	}
	if n := a.up.n.Load(); n != 1 {
		t.Fatalf("%d requests reached the provider, want 1", n)
	}
}

// Without a checker nothing can record an act, so a code that carries one
// is not checked at all, and there is nothing to withdraw (CH-4).
func TestNoCheckerChecksNoActs(t *testing.T) {
	_, ok, err := ownerVerifier{}.VerifyTOTP("123456", 0, true, owner.CheckerAct{Act: "act-a"})
	var ve *owner.VerifyError
	if ok || !errors.As(err, &ve) || ve.Kind != owner.VaultDown {
		t.Fatalf("no checker: ok %v, err %v", ok, err)
	}
	if err := (ownerVerifier{}).RevokeActs("act-a"); err != nil {
		t.Fatal(err)
	}
}
