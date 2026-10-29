package line

// REQ: CLK-8, CLK-1

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/sipsign"
)

// The clerk signs a MESSAGE only for a send it admitted, once, with that
// send's recipient as its Request-URI: a second signature for the same send,
// another recipient, another host and a MESSAGE no send admitted are all
// refused and counted, so the line process has no signing oracle.
func TestSignsMessageOnlyForAnAdmittedSendOnce(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()
	var asks []error
	var mu sync.Mutex
	try := func(uri string) error {
		c := challenge("MESSAGE", uri)
		auth, err := r.signer.Sign(ctx, c)
		if err == nil && !verifies(t, c, auth) {
			t.Fatalf("%s: the answer does not verify", uri)
		}
		mu.Lock()
		asks = append(asks, err)
		mu.Unlock()
		return err
	}
	// While the line holds the admitted send, it asks for more than its one
	// signature.
	r.line.before = func(context.Context) error {
		for _, uri := range []string{"sip:" + stranger + "@" + domain, "sip:" + shopNum + "@evil.test", "sip:" + shopNum + "@" + domain} {
			if err := try(uri); uri == "sip:"+shopNum+"@"+domain {
				if err != nil {
					t.Fatalf("the admitted send's signature: %v", err)
				}
			} else if !errors.Is(err, ErrUnbound) {
				t.Fatalf("%s: %v", uri, err)
			}
		}
		return nil
	}
	// The fake line then asks for the same send's signature again, as a
	// line that re-sends would.
	if res := r.text(t, "m1", shopNum, "hello"); res.Outcome != "failed" || res.Detail != RNotTaken {
		t.Fatalf("second signature for the same send was given: %+v", res)
	}
	r.line.before = nil
	// After the send, nothing is admitted.
	if err := try("sip:" + shopNum + "@" + domain); !errors.Is(err, ErrUnbound) {
		t.Fatalf("unadmitted MESSAGE: %v", err)
	}
	// Calls wait for part d.
	if _, err := r.signer.Sign(ctx, challenge("INVITE", "sip:"+shopNum+"@"+domain)); !errors.Is(err, sipsign.ErrMethod) {
		t.Fatalf("INVITE: %v", err)
	}
	// An admitted send signs and is sent.
	if res := r.text(t, "m2", dentist, "see you"); res.Outcome != "ok" {
		t.Fatalf("admitted send: %+v", res)
	}
	if got := r.c.Status().SignRefused; got != 5 {
		t.Fatalf("refusals counted %d, want 5", got)
	}
}

// The clerk signs REGISTER only for its own registrar, at most once per
// RegisterEvery, and learns the realm from the first one within the window
// after setup; texts are signed only once the owner confirms that realm.
func TestRegisterSigningIsRateLimited(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	if err := r.c.Account().Set(sipsign.Settings{Server: "sip.voip.test", Domain: domain, User: user, Number: lineNum}, password); err != nil {
		t.Fatal(err)
	}
	reg := challenge("REGISTER", "sip:"+domain)
	auth, err := r.signer.Sign(ctx, reg)
	if err != nil || !verifies(t, reg, auth) {
		t.Fatalf("first registration: %v", err)
	}
	if rec, _ := r.c.Account().Record(); rec.Realm != realm || rec.RealmConfirmed {
		t.Fatalf("record %+v", rec)
	}
	r.now += RegisterEvery - 1
	if _, err := r.signer.Sign(ctx, reg); !errors.Is(err, ErrRegisterRate) {
		t.Fatalf("within %d ms: %v", RegisterEvery, err)
	}
	r.now++
	if _, err := r.signer.Sign(ctx, reg); err != nil {
		t.Fatalf("after %d ms: %v", RegisterEvery, err)
	}
	r.now += RegisterEvery
	if _, err := r.signer.Sign(ctx, challenge("REGISTER", "sip:other.test")); !errors.Is(err, ErrUnbound) {
		t.Fatalf("another registrar: %v", err)
	}
	// Unconfirmed, a text is refused before the line and its MESSAGE too.
	if res := r.text(t, "u1", shopNum, "hi"); res.Detail != RUnconfirmed {
		t.Fatalf("unconfirmed realm: %+v", res)
	}
	if err := r.c.Account().ConfirmRealm("other"); !errors.Is(err, ErrRealm) {
		t.Fatalf("confirming another realm: %v", err)
	}
	if err := r.c.Account().ConfirmRealm(realm); err != nil {
		t.Fatal(err)
	}
	if res := r.text(t, "u2", shopNum, "hi"); res.Outcome != "ok" {
		t.Fatalf("confirmed: %+v", res)
	}

	// Past the window after a fresh setup, no realm is learned.
	if err := r.c.Account().Set(sipsign.Settings{Server: "sip.voip.test", Domain: domain, User: user, Number: lineNum}, password); err != nil {
		t.Fatal(err)
	}
	r.now += RealmWindow + 1
	if _, err := r.signer.Sign(ctx, reg); !errors.Is(err, sipsign.ErrRealm) {
		t.Fatalf("past the window: %v", err)
	}
	if rec, _ := r.c.Account().Record(); rec.Realm != "" {
		t.Fatalf("learned %q past the window", rec.Realm)
	}
}
