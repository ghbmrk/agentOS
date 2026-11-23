package run

// REQ: CLK-9, CLK-1, VRB-2

import (
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
)

// readMetadataGets counts the fake's metadata gets of read mail.
func readMetadataGets(calls []string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, "GET /gmail/v1/users/me/messages/") {
			n++
		}
	}
	return n
}

// The host keeps one Gmail API and read cache for its account (#3010): a
// re-read and a change check reuse the access token, so the grant is
// redeemed once, and a re-read gets no read mail's metadata again. A change
// of account drops both, so the next read redeems the grant the account
// has now.
func TestTheHostReusesItsGmailTokenAndReadCache(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Open(srv.Deliver(gmailMail("news@shop.test", "<a@shop.test>")))
	h := NewMailHost(context.Background(), dir, sec, gmailConfig(srv))
	if h.why != "" || h.cur == nil {
		t.Fatalf("the first read failed: %q", h.why)
	}
	if n := srv.Tokens(); n != 1 {
		t.Fatalf("the first read redeemed the grant %d times, want 1", n)
	}
	before := len(srv.Calls())
	for range 2 {
		if _, err := h.listing(true); err != nil {
			t.Fatal(err)
		}
	}
	h.mu.Lock()
	read, _, err := recheck(context.Background(), h.mark, h.day, false, h.dir, h.sec, h.cfg)
	h.mu.Unlock()
	if read || err != nil {
		t.Fatalf("recheck = %v, %v", read, err)
	}
	if n := srv.Tokens(); n != 1 {
		t.Fatalf("re-reads and a change check redeemed the grant %d times in all, want 1", n)
	}
	if n := readMetadataGets(srv.Calls()[before:]); n > 2 {
		// Each re-read gets the one inbox mail raw; neither gets its
		// read metadata again.
		t.Fatalf("re-reads made %d message gets, want only the raw ones", n)
	}
	h.mu.Lock()
	h.changed()
	h.mu.Unlock()
	if _, err := h.listing(true); err != nil {
		t.Fatal(err)
	}
	if n := srv.Tokens(); n != 2 {
		t.Fatalf("after a change of account the grant was redeemed %d times in all, want 2", n)
	}
}

// A box the host keeps is for its own store and slot only (CLK-1): a box
// asked for another slot, or another store, is built afresh, and a dropped
// one is never handed back.
func TestTheKeptGmailBoxIsForItsSlotOnly(t *testing.T) {
	srv, _, sec := newGmailAccount(t)
	c := gmailConfig(srv)
	k := &gmailKept{}
	c.kept = k
	slot := GmailSlot(gmailtest.User)
	a, err := k.box(sec, slot, c)
	if err != nil {
		t.Fatal(err)
	}
	api := k.api
	if b, err := k.box(sec, slot, c); err != nil || k.api != api || b == a {
		t.Fatalf("a second box: %v, same API %v, same box %v; want a new box over the same API", err, k.api == api, b == a)
	}
	other, err := OpenSecrets(shortDir(t), testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Put(slot, clerk.KindGrant, gmailtest.Grant()); err != nil {
		t.Fatal(err)
	}
	if _, err := k.box(other, slot, c); err != nil || k.api == api {
		t.Fatalf("another store's box shares the API: %v", err)
	}
	k.drop()
	if k.api != nil || k.reads != nil {
		t.Fatal("drop kept the API or its cache")
	}
	var none *gmailKept
	if _, err := none.box(sec, slot, c); err != nil {
		t.Fatalf("a host with nothing kept: %v", err)
	}
	none.drop()
}
