package inbox

// REQ: VRB-2, CLK-9

import (
	"context"
	"strings"
	"testing"
)

// metadataGets counts the metadata gets among calls: each read mail's
// From, Message-ID and internalDate.
func metadataGets(calls []string) int {
	n := 0
	for _, c := range calls {
		if strings.HasPrefix(c, "GET /gmail/v1/users/me/messages/") && !strings.HasSuffix(c, "/messages") {
			n++
		}
	}
	return n
}

// A read mail's metadata is got once (#3010): a later Opened lists the
// read mail and gets only the mail it has not seen read, with the same
// answer as a first read; a mail read before that is gone is left out.
func TestGmailOpenedGetsEachReadMailOnce(t *testing.T) {
	box, srv := newGmail(t)
	ctx := context.Background()
	a := srv.Deliver([]byte(crlfMail("<a@x.test>", "News <news@shop.test>", "read")))
	b := srv.Deliver([]byte(crlfMail("<b@x.test>", "old@shop.test", "read")))
	srv.Open(a)
	srv.Open(b)
	_, log, err := box.Opened(ctx, "2026-10-19", SeenLog{})
	if err != nil {
		t.Fatal(err)
	}
	first := len(srv.Calls())
	if n := metadataGets(srv.Calls()); n != 2 {
		t.Fatalf("a first Opened got %d mails' metadata, want 2", n)
	}
	c := srv.Deliver([]byte(crlfMail("<c@x.test>", "pat@example.test", "read later")))
	srv.Open(c)
	srv.Erase(b)
	got, log2, err := box.Opened(ctx, "2026-10-20", log)
	if err != nil {
		t.Fatal(err)
	}
	if n := metadataGets(srv.Calls()[first:]); n != 1 {
		t.Fatalf("a later Opened got %d mails' metadata, want only the newly read one", n)
	}
	// The same answer as a box that never read before.
	fresh := &Gmail{api: box.api, refs: map[string]string{}, labels: map[string]string{}}
	want, wantLog, err := fresh.Opened(ctx, "2026-10-20", log)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || got["news@shop.test"] != want["news@shop.test"] || got["pat@example.test"] != "2026-10-20" || got["old@shop.test"] != want["old@shop.test"] {
		t.Fatalf("cached LastOpened = %v, uncached %v", got, want)
	}
	if len(log2.Seen) != len(wantLog.Seen) {
		t.Fatalf("cached log %+v, uncached %+v", log2, wantLog)
	}
}

// The cache is bounded (#3010): past gReadCacheMax, a read mail is got
// again on each Opened, and the answer is the same.
func TestGmailReadCacheIsBounded(t *testing.T) {
	old := gReadCacheMax
	t.Cleanup(func() { gReadCacheMax = old })
	box, srv := newGmail(t)
	ctx := context.Background()
	for _, id := range []string{"<a@x.test>", "<b@x.test>", "<c@x.test>"} {
		srv.Open(srv.Deliver([]byte(crlfMail(id, "news@shop.test", "read"))))
	}
	if _, _, err := box.Opened(ctx, "2026-10-19", SeenLog{}); err != nil {
		t.Fatal(err)
	}
	// Room for one of the three, which are the same size.
	gReadCacheMax = box.reads.spent / 3
	box.WithReadCache(NewReadCache())
	for range 2 {
		first := len(srv.Calls())
		got, _, err := box.Opened(ctx, "2026-10-19", SeenLog{})
		if err != nil || got["news@shop.test"] != "2026-10-19" {
			t.Fatalf("LastOpened = %v, %v", got, err)
		}
		if n := metadataGets(srv.Calls()[first:]); n < 2 {
			t.Fatalf("with room for one, an Opened got %d, want at least 2", n)
		}
		if box.reads.Len() != 1 || box.reads.spent > gReadCacheMax {
			t.Fatalf("the cache holds %d mails in %d bytes, want 1 within %d", box.reads.Len(), box.reads.spent, gReadCacheMax)
		}
	}
}

// A cache shared through WithReadCache serves a new box over the same
// account: the run package keeps one per account across reads (#3010).
func TestGmailReadCacheIsShared(t *testing.T) {
	box, srv := newGmail(t)
	ctx := context.Background()
	srv.Open(srv.Deliver([]byte(crlfMail("<a@x.test>", "news@shop.test", "read"))))
	rc := NewReadCache()
	box.WithReadCache(rc)
	if _, _, err := box.Opened(ctx, "2026-10-19", SeenLog{}); err != nil {
		t.Fatal(err)
	}
	first := len(srv.Calls())
	other := NewGmail(box.api).WithReadCache(rc)
	if _, _, err := other.Opened(ctx, "2026-10-19", SeenLog{}); err != nil {
		t.Fatal(err)
	}
	if n := metadataGets(srv.Calls()[first:]); n != 0 {
		t.Fatalf("a box sharing the cache got %d mails' metadata, want 0", n)
	}
}

// An Opened that fails part way still keeps what it read (#3010), so an
// account whose listing keeps failing is not got in full each time; and a
// whole listing later drops a mail gone from the account.
func TestGmailReadCacheKeepsAFailedPassAndForgetsGoneMail(t *testing.T) {
	defer func(n int) { gPagesMax = n }(gPagesMax)
	gPagesMax = 3
	box, srv := newGmail(t)
	ctx := context.Background()
	a := srv.Deliver([]byte(crlfMail("<a@x.test>", "news@shop.test", "read")))
	srv.Open(a)
	srv.Endless(10)
	if _, _, err := box.Opened(ctx, "2026-10-19", SeenLog{}); err == nil {
		t.Fatal("a listing that does not end passed")
	}
	if box.reads.Len() != 1 {
		t.Fatalf("a failed Opened cached %d mails, want 1", box.reads.Len())
	}
	srv.Endless(0)
	first := len(srv.Calls())
	if _, _, err := box.Opened(ctx, "2026-10-19", SeenLog{}); err != nil {
		t.Fatal(err)
	}
	if n := metadataGets(srv.Calls()[first:]); n != 0 {
		t.Fatalf("after a failed pass, Opened got %d, want 0", n)
	}
	srv.Erase(a)
	if _, _, err := box.Opened(ctx, "2026-10-19", SeenLog{}); err != nil {
		t.Fatal(err)
	}
	if box.reads.Len() != 0 {
		t.Fatalf("a mail gone from the account stays cached: %d", box.reads.Len())
	}
}
