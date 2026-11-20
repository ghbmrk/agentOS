package inbox

// REQ: VRB-2, D-154

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

// Two mails signed under one key name look it up once, in first-seen
// order: KeyNames keeps each name once across the read.
func TestKeyNamesOnceAcrossMails(t *testing.T) {
	mail := func(s string) []byte {
		return []byte("DKIM-Signature: v=1; d=shop.test; s=" + s + "; h=from\r\nFrom: a@shop.test\r\n\r\nHi\r\n")
	}
	got := KeyNames([][]byte{mail("a"), mail("b"), mail("a"), mail("b")})
	if want := []string{"a._domainkey.shop.test", "b._domainkey.shop.test"}; !slices.Equal(got, want) {
		t.Fatalf("KeyNames gave %q, want %q", got, want)
	}
}

// stopCountCtx is a parent context that counts the cancel hooks its
// children register (context's AfterFunc path) and how many were stopped,
// which a child does when it is cancelled.
type stopCountCtx struct {
	context.Context
	mu         sync.Mutex
	registered int
	stopped    int
}

func (c *stopCountCtx) Value(any) any { return nil }

func (c *stopCountCtx) AfterFunc(func()) func() bool {
	c.mu.Lock()
	c.registered++
	c.mu.Unlock()
	return func() bool {
		c.mu.Lock()
		c.stopped++
		c.mu.Unlock()
		return true
	}
}

// LookupDKIM cancels the read's own context before it returns: the read
// bound's timer and its hook on the caller's context end with the read.
func TestLookupDKIMCancelsItsContext(t *testing.T) {
	never, cancel := context.WithCancel(context.Background())
	defer cancel()
	parent := &stopCountCtx{Context: never}
	LookupDKIM(parent, &fakeTXT{answers: map[string][]string{}}, []string{"a._domainkey.shop.test"})
	parent.mu.Lock()
	defer parent.mu.Unlock()
	if parent.registered != 1 || parent.stopped != 1 {
		t.Fatalf("read context registered %d hooks and stopped %d; want 1 and 1", parent.registered, parent.stopped)
	}
}

// ctxTXT answers every name with one usable key record (or err with it),
// first calling hook with the lookup's context.
type ctxTXT struct {
	hook func(ctx context.Context)
	err  error
}

func (r ctxTXT) LookupTXT(ctx context.Context, _ string) ([]string, error) {
	if r.hook != nil {
		r.hook(ctx)
	}
	return []string{"v=DKIM1; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"}, r.err
}

// A read whose context has ended asks nothing; one lookup's context ends
// when it returns; a resolver that ignores its context does not hold the
// lookup past its bound; an answer that comes with an error is not kept,
// whatever records come with it.
func TestLookupOneBounds(t *testing.T) {
	asked := make(chan struct{}, 1)
	done, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := lookupOne(done, ctxTXT{hook: func(context.Context) { asked <- struct{}{} }}, "a._domainkey.shop.test"); ok {
		t.Fatal("a lookup after the read ended kept a key")
	}
	select {
	case <-asked:
		t.Fatal("a lookup after the read ended asked the resolver")
	case <-time.After(time.Second):
	}

	var seen context.Context
	if _, ok := lookupOne(context.Background(), ctxTXT{hook: func(ctx context.Context) { seen = ctx }}, "a._domainkey.shop.test"); !ok {
		t.Fatal("a usable key record was not kept")
	}
	if seen == nil || seen.Err() == nil {
		t.Fatal("the lookup's context was still live after the lookup returned")
	}

	if _, ok := lookupOne(context.Background(), ctxTXT{err: errors.New("partial")}, "a._domainkey.shop.test"); ok {
		t.Fatal("an answer that came with an error was kept")
	}

	prev := dkimLookupWait
	dkimLookupWait = 50 * time.Millisecond
	defer func() { dkimLookupWait = prev }()
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	if _, ok := lookupOne(context.Background(), ctxTXT{hook: func(context.Context) { <-release }}, "a._domainkey.shop.test"); ok {
		t.Fatal("a resolver that ignored its context had its answer kept")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("a resolver that ignores its context held the lookup %v", d)
	}
}

// With no lookup taking names, the read still ends at its own bound.
func TestLookupDKIMEndsWithNoTaker(t *testing.T) {
	prevAtOnce, prevRead := dkimLookupsAtOnce, dkimReadWait
	dkimLookupsAtOnce, dkimReadWait = 0, 50*time.Millisecond
	defer func() { dkimLookupsAtOnce, dkimReadWait = prevAtOnce, prevRead }()
	ended := make(chan map[string]string, 1)
	go func() {
		ended <- LookupDKIM(context.Background(), &fakeTXT{answers: map[string][]string{}}, []string{"a._domainkey.shop.test"})
	}()
	select {
	case got := <-ended:
		if len(got) != 0 {
			t.Fatalf("a read with no lookups kept %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a read with no lookups did not end at its bound")
	}
}

// A label holding any byte other than a letter, digit, hyphen or underscore
// is not a name to look up.
func TestDNSNameBytes(t *testing.T) {
	for _, n := range []string{"s*._domainkey.shop.test", "s t._domainkey.shop.test", "s/._domainkey.shop.test", "s\x00._domainkey.shop.test", "sé._domainkey.shop.test"} {
		if dnsName(n) {
			t.Errorf("%q passed as a name", n)
		}
	}
	if !dnsName("s-1_x._domainkey.Shop9.test") {
		t.Error("a name of letters, digits, hyphens and underscores was refused")
	}
}

// A key record's tag list (RFC 6376 section 3.2): whitespace around tags
// and an empty last part are allowed; a part with no tag name or no "=",
// and a repeated tag, refuse the record.
func TestKeyRecordTagList(t *testing.T) {
	const p = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
	for _, rec := range []string{"v=DKIM1; p=" + p + ";", "v=DKIM1; p=" + p + "; ", "v=DKIM1;;p=" + p, "v=DKIM1; p =" + p, " v = DKIM1 ; p = " + p} {
		if got, ok := keyRecord([]string{rec}); !ok || got != p {
			t.Errorf("%q gave %q %v; want its key", rec, got, ok)
		}
	}
	for _, rec := range []string{"v=DKIM1; junk; p=" + p, "v=DKIM1; =rsa; p=" + p, "v=DKIM1; p=; p=" + p, "v=DKIM1; p=" + p + "; p=" + p} {
		if got, ok := keyRecord([]string{rec}); ok {
			t.Errorf("%q was kept as %q", rec, got)
		}
	}
}

// DKIMNames reads only DKIM-Signature fields whose tag list parses (empty
// parts allowed, a repeated tag refuses it) and that name both s= and d=.
func TestDKIMNamesFields(t *testing.T) {
	raw := []byte("X-Sig: v=1; d=shop.test; s=other\r\n" +
		"DKIM-Signature: v=1; d=shop.test; s=dup; s=evil\r\n" +
		"DKIM-Signature: v=1; d=shop.test\r\n" +
		"DKIM-Signature: v=1; s=nod\r\n" +
		"DKIM-Signature: v=1;; d=shop.test; s=a;\r\n" +
		"From: a@shop.test\r\n\r\nHi\r\n")
	if got, want := DKIMNames(raw), []string{"a._domainkey.shop.test"}; !slices.Equal(got, want) {
		t.Fatalf("DKIMNames gave %q, want %q", got, want)
	}
}
