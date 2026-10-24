package inbox

// REQ: VRB-2, CLK-9

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// LastOpened over Gmail's read state (#2925): a read mail in any label, spam
// and trash too, opens its sender; an unread one does not; and nothing the
// clerk calls marks a mail read.
func TestGmailOpenedReadsGmailsReadState(t *testing.T) {
	box, srv := newGmail(t)
	ctx := context.Background()
	read := srv.Deliver([]byte(crlfMail("<r@x.test>", "News <news@shop.test>", "read")))
	srv.Deliver([]byte(crlfMail("<u@x.test>", "pat@example.test", "unread")))
	trashed := srv.Deliver([]byte(crlfMail("<t@x.test>", "old@shop.test", "read, then trashed")), "TRASH")
	if _, err := box.Read(ctx); err != nil {
		t.Fatal(err)
	}
	srv.Open(read)
	got, log, err := box.Opened(ctx, "2026-10-19", SeenLog{})
	if err != nil {
		t.Fatal(err)
	}
	if got["news@shop.test"] != "2026-10-19" || got["old@shop.test"] != "2026-10-19" || got["pat@example.test"] != "" {
		t.Fatalf("LastOpened = %v; want the read mail's senders only", got)
	}
	if len(log.Seen) != 2 || log.Since != "2026-10-19" {
		t.Fatalf("log = %+v", log)
	}
	for _, s := range log.Seen {
		if strings.Contains(s.ID, "@") {
			t.Fatalf("the log keeps a Message-ID: %+v", s)
		}
	}
	if m, _ := srv.Get(trashed); len(m.Labels) != 1 {
		t.Fatalf("Opened changed a mail: %v", m.Labels)
	}
	for _, c := range srv.Calls() {
		if !strings.HasPrefix(c, "GET ") {
			t.Fatalf("Opened made a write: %s", c)
		}
	}

	// The owner deletes the read mail for good: the log keeps its sender
	// opened, on the day first seen read.
	srv.Erase(read)
	got, _, err = box.Opened(ctx, "2026-10-20", log)
	if err != nil || got["news@shop.test"] != "2026-10-19" {
		t.Fatalf("after the delete, LastOpened = %v, %v", got, err)
	}
}

// A failing listing fails the whole answer and hands back the log it began
// with, so no partial answer passes for a full one.
func TestGmailOpenedFailsClosed(t *testing.T) {
	box, srv := newGmail(t)
	ctx := context.Background()
	srv.Open(srv.Deliver([]byte(crlfMail("<r@x.test>", "news@shop.test", "read"))))
	_, log, err := box.Opened(ctx, "2026-10-19", SeenLog{})
	if err != nil {
		t.Fatal(err)
	}
	srv.Fail("/messages", http.StatusInternalServerError)
	got, kept, err := box.Opened(ctx, "2026-10-20", log)
	if err == nil || got != nil {
		t.Fatalf("Opened over a failing list = %v, %v", got, err)
	}
	if kept.Seen != nil {
		t.Fatalf("a read that logged nothing handed back %+v; the caller keeps its own", kept)
	}
}

// A header the API gives across lines is not read as two fields, so no
// answer can forge a From.
func TestGmailHeaderAcrossLinesIsRefused(t *testing.T) {
	var h gHeaders
	h.Payload.Headers = append(h.Payload.Headers, struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}{"Message-ID", "<a@x.test>\r\nFrom: friend@x.test"})
	if _, _, err := h.header(); err == nil {
		t.Fatal("a header across lines was read")
	}
}

// Gmail's Mark is its history id: the same with nothing changed, moved by a
// read-state change outside the inbox, and never the same as another
// account's empty Mark.
func TestGmailMarkMovesWithReadState(t *testing.T) {
	box, srv := newGmail(t)
	ctx := context.Background()
	id := srv.Deliver([]byte(crlfMail("<a@x.test>", "news@shop.test", "a")), "Label_9", "UNREAD")
	m1, err := box.Mark(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := box.Mark(ctx)
	if !m1.Same(m2) {
		t.Fatalf("Marks with nothing changed differ: %v %v", m1, m2)
	}
	srv.Open(id)
	m3, _ := box.Mark(ctx)
	if m1.Same(m3) || m1.Same(nil) {
		t.Fatalf("a read outside the inbox left the Mark the same: %v %v", m1, m3)
	}
	srv.Fail("/profile", http.StatusInternalServerError)
	if m, err := box.Mark(ctx); err == nil || m != nil {
		t.Fatalf("Mark over a failing profile = %v, %v", m, err)
	}
}
