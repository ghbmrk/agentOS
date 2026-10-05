package mail_test

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/events"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/recall"
)

// pipe is a recall index and an event bus sharing its keyer, with the
// bus's recall trigger, as the broker wires them (recall K5).
type pipe struct {
	ix      *recall.Index
	bus     *events.Bus
	deleted [][]string
}

func newPipe(t *testing.T) *pipe {
	t.Helper()
	dir := t.TempDir()
	rst, err := recall.OpenDir(filepath.Join(dir, "recall"))
	if err != nil {
		t.Fatal(err)
	}
	ix, err := recall.Open(rst)
	if err != nil {
		t.Fatal(err)
	}
	b, err := events.Open(events.Config{Log: &recall.MemStore{}, Seen: &recall.MemStore{}, Keyer: ix.Keyer(),
		Triggers: []events.Trigger{events.IndexInto(ix)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := ix.OnDelete(b.ForgetSource); err != nil {
		t.Fatal(err)
	}
	return &pipe{ix: ix, bus: b}
}

// recallOnly is the default deletion until Mark decides (M7): the item
// leaves recall and the bus.
func (p *pipe) recallOnly(ids []string) error {
	p.deleted = append(p.deleted, ids)
	_, err := p.ix.Delete(ids...)
	return err
}

func (p *pipe) find(text string) []recall.Result {
	return p.ix.Lookup(recall.Query{Text: text})
}

func (x *h) watcher(t *testing.T, p *pipe, st recall.Store, edit func(*mail.WatchConfig)) *mail.Watcher {
	t.Helper()
	cfg := mail.WatchConfig{Publisher: p.bus, Keyer: p.ix.Keyer(), State: st, Deleted: p.recallOnly}
	if edit != nil {
		edit(&cfg)
	}
	w, err := x.a.Watch(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func poll(t *testing.T, w *mail.Watcher, p *pipe) mail.PollReport {
	t.Helper()
	r, err := w.Poll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.bus.Pump(ctx)
	return r
}

// REQ: CAP-3, CAP-4

// TestNewMailReachesTheBusAndRecall: each new message is published once
// as a private mail event, which the bus's recall trigger indexes with
// its provenance; watching never marks mail read.
func TestNewMailReachesTheBusAndRecall(t *testing.T) {
	x := newH(t, nil)
	p := newPipe(t)
	st := &recall.MemStore{}
	w := x.watcher(t, p, st, nil)
	x.deliver("INBOX", msg{id: "<lab@clinic.example>", from: "Clinic <results@clinic.example>", to: me,
		subject: "Lab results", body: "Your quokkafruit panel is normal."})
	x.news(1)
	if r := poll(t, w, p); r.Published != 2 || !r.Complete {
		t.Fatalf("first poll %+v", r)
	}
	rs := p.find("quokkafruit")
	if len(rs) != 1 || rs[0].Label != recall.Private || rs[0].Source.Kind != "mail" || rs[0].Source.Account != "mail" ||
		!strings.HasPrefix(rs[0].Source.Ref, "<lab@clinic.example> #") || rs[0].ID != p.ix.SourceID("mail", "mail", rs[0].Source.Ref) {
		t.Fatalf("recall %+v", rs)
	}
	if got := x.srv.Messages("INBOX"); len(got[0].Flags) != 0 {
		t.Fatalf("watching marked mail read: %v", got[0].Flags)
	}
	if r := poll(t, w, p); r.Published != 0 || r.Deleted != 0 {
		t.Fatalf("second poll %+v", r)
	}
	// A restart reads the saved state: nothing is published again.
	w = x.watcher(t, p, st, nil)
	x.news(2)
	if r := poll(t, w, p); r.Published != 1 {
		t.Fatalf("after restart %+v", r)
	}
}

// TestSourceDeletionIsRecallOnly: a message moved between folders (by the
// agent or the owner) or renumbered is not a deletion; one deleted at the
// source, or moved to trash, leaves recall through the wiring's
// recall-only deletion; and an outage never reads as deletion.
func TestSourceDeletionIsRecallOnly(t *testing.T) {
	x := newH(t, nil)
	p := newPipe(t)
	w := x.watcher(t, p, &recall.MemStore{}, nil)
	x.deliver("INBOX", msg{id: "<lab@clinic.example>", from: "results@clinic.example", to: me, subject: "Lab", body: "quokkafruit"})
	x.deliver("INBOX", msg{id: "<memo@work.example>", from: "boss@work.example", to: me, subject: "Memo", body: "wombatberry"})
	poll(t, w, p)
	lab := p.find("quokkafruit")[0].ID
	x.mustRun(x.intent(mail.OpArchive, rec("<lab@clinic.example>")))
	x.srv.Renumber("INBOX")
	if r := poll(t, w, p); r.Deleted != 0 || r.Published != 0 || len(p.find("quokkafruit")) != 1 {
		t.Fatalf("move or renumber read as deletion: %+v", r)
	}
	// The archive cannot be listed: no deletion is concluded.
	x.srv.Remove("Archive", "<lab@clinic.example>")
	x.srv.FailList("Archive", true)
	if r, err := w.Poll(ctx); err == nil || r.Complete || r.Deleted != 0 || len(p.find("quokkafruit")) != 1 {
		t.Fatalf("outage read as deletion: %+v %v", r, err)
	}
	x.srv.FailList("Archive", false)
	if r := poll(t, w, p); r.Deleted != 1 || len(p.find("quokkafruit")) != 0 {
		t.Fatalf("source deletion: %+v", r)
	}
	if len(p.deleted) != 1 || p.deleted[0][0] != lab {
		t.Fatalf("deleted %v", p.deleted)
	}
	// Trash is a deletion from the owner's view.
	x.mustRun(x.intent(mail.OpDelete, rec("<memo@work.example>")))
	if r := poll(t, w, p); r.Deleted != 1 || len(p.find("wombatberry")) != 0 {
		t.Fatalf("trash: %+v", r)
	}
}

// TestBackfillIsBounded: a folder's first poll publishes only its newest
// messages; the rest are recorded unpublished.
func TestBackfillIsBounded(t *testing.T) {
	x := newH(t, nil)
	p := newPipe(t)
	for i := 0; i < 5; i++ {
		x.news(i)
	}
	w := x.watcher(t, p, &recall.MemStore{}, func(c *mail.WatchConfig) { c.Backfill = 2; c.Batch = 1 })
	if r := poll(t, w, p); r.Published != 2 {
		t.Fatalf("backfill %+v", r)
	}
	var refs []string
	for _, r := range p.find("boots") {
		refs = append(refs, strings.SplitN(r.Source.Ref, " ", 2)[0])
	}
	slices.Sort(refs)
	if !slices.Equal(refs, []string{"<news-3@shop.example>", "<news-4@shop.example>"}) || p.ix.Len() != 2 {
		t.Fatal("backfill took the wrong messages")
	}
	if n, total := w.Coverage(); n != 2 || total != 5 {
		t.Fatalf("coverage %d of %d", n, total)
	}
	x.news(5)
	if r := poll(t, w, p); r.Published != 1 {
		t.Fatalf("after backfill %+v", r)
	}
}

// TestAllMailViewIsWatchedAlone: with a Gmail-style all-mail folder, only
// it is watched, so an archived message (in no other folder) stays.
func TestAllMailViewIsWatchedAlone(t *testing.T) {
	x := newH(t, nil)
	x.srv.AddFolder("All Mail", `\All`)
	p := newPipe(t)
	w := x.watcher(t, p, &recall.MemStore{}, nil)
	x.deliver("All Mail", msg{id: "<n@x.example>", from: "a@x.example", to: me, subject: "S", body: "numbatplum"})
	x.deliver("INBOX", msg{id: "<n@x.example>", from: "a@x.example", to: me, subject: "S", body: "numbatplum"})
	if r := poll(t, w, p); r.Published != 1 {
		t.Fatalf("poll %+v", r)
	}
	x.srv.Remove("INBOX", "<n@x.example>")
	if r := poll(t, w, p); r.Deleted != 0 {
		t.Fatalf("archived in all-mail read as deleted: %+v", r)
	}
}

// TestBrokenListingsNeverReadAsDeletion: a listing without the inbox
// concludes nothing; a known folder missing from the listing keeps its
// mail present, and one that leaves the listing never makes its mail read
// as deleted.
func TestBrokenListingsNeverReadAsDeletion(t *testing.T) {
	x := newH(t, nil)
	p := newPipe(t)
	w := x.watcher(t, p, &recall.MemStore{}, nil)
	x.deliver("Receipts", msg{id: "<r@shop.example>", from: "a@shop.example", to: me, subject: "Receipt", body: "quollnut"})
	x.news(1)
	poll(t, w, p)
	for _, f := range []string{"INBOX", "Archive", "Drafts", "Sent", "Trash", "Junk", "Receipts", "Team", "Legal"} {
		x.srv.Hide(f, true)
	}
	if r, err := w.Poll(ctx); err == nil || r.Deleted != 0 {
		t.Fatalf("empty listing: %+v %v", r, err)
	}
	for _, f := range []string{"INBOX", "Archive", "Drafts", "Sent", "Trash", "Junk", "Team", "Legal"} {
		x.srv.Hide(f, false)
	}
	for i := 0; i < 4; i++ {
		if r, _ := w.Poll(ctx); r.Deleted != 0 || r.Complete != (i >= 2) || len(p.find("quollnut")) != 1 {
			t.Fatalf("poll %d without Receipts: %+v", i, r)
		}
	}
}

// TestRenumberedFolderReadIsBounded: after a UID validity reset the
// re-read is bounded like a first read, and what it leaves unread stays
// present.
func TestRenumberedFolderReadIsBounded(t *testing.T) {
	x := newH(t, nil)
	p := newPipe(t)
	for i := 0; i < 5; i++ {
		x.news(i)
	}
	fetches := 0
	w := x.watcher(t, p, &recall.MemStore{}, func(c *mail.WatchConfig) { c.Backfill = 5 })
	poll(t, w, p)
	w = x.watcher(t, p, &recall.MemStore{}, func(c *mail.WatchConfig) { c.Backfill = 2 })
	_ = fetches
	poll(t, w, p) // fresh state: bounded first read
	x.srv.Renumber("INBOX")
	if r := poll(t, w, p); r.Deleted != 0 || p.ix.Len() != 5 {
		t.Fatalf("renumbered: %+v, %d in recall", r, p.ix.Len())
	}
	if n, total := w.Coverage(); n != 2 || total != 5 {
		t.Fatalf("coverage %d of %d", n, total)
	}
}

// TestWatchedSetChangesNeverReadAsDeletion: when the all-mail view loses
// its role for a poll, the watcher reads the other folders instead, and
// nothing it saw only in the view counts as deleted (Security C3).
func TestWatchedSetChangesNeverReadAsDeletion(t *testing.T) {
	x := newH(t, nil)
	x.srv.AddFolder("All Mail", `\All`)
	p := newPipe(t)
	w := x.watcher(t, p, &recall.MemStore{}, nil)
	x.deliver("All Mail", msg{id: "<a@x.example>", from: "a@x.example", to: me, subject: "S", body: "bilbyroot"})
	poll(t, w, p)
	x.srv.SetAttr("All Mail", "")
	x.srv.Hide("All Mail", true)
	for i := 0; i < 4; i++ {
		if r, _ := w.Poll(ctx); r.Deleted != 0 || len(p.find("bilbyroot")) != 1 {
			t.Fatalf("poll %d without the view: %+v", i, r)
		}
	}
	x.srv.Hide("All Mail", false)
	x.srv.SetAttr("All Mail", `\All`)
	if r := poll(t, w, p); r.Deleted != 0 || len(p.find("bilbyroot")) != 1 {
		t.Fatalf("view back: %+v", r)
	}
}

// TestReusedMessageIDsAreSeparateItems: a Message-ID is the sender's to
// choose, so a second message reusing one is its own recall item and
// cannot replace or shadow the first (Security C4).
func TestReusedMessageIDsAreSeparateItems(t *testing.T) {
	x := newH(t, nil)
	p := newPipe(t)
	w := x.watcher(t, p, &recall.MemStore{}, nil)
	x.deliver("INBOX", msg{id: "<lab@clinic.example>", from: "results@clinic.example", to: me, subject: "Lab", body: "quokkafruit normal"})
	poll(t, w, p)
	x.deliver("Receipts", msg{id: "<lab@clinic.example>", from: "eve@evil.example", to: me, subject: "Lab", body: "quokkafruit call this number"})
	if r := poll(t, w, p); r.Published != 1 || len(p.find("quokkafruit")) != 2 {
		t.Fatalf("reused ID: %+v, %d items", r, len(p.find("quokkafruit")))
	}
	// Without a Message-ID a message is still named by its location.
	x.srv.Deliver("INBOX", "From: a@x.example\nTo: "+me+"\nSubject: n\nDate: Mon, 05 Oct 2026 08:00:00 +0000\n\nwallabyseed\n")
	poll(t, w, p)
	if rs := p.find("wallabyseed"); len(rs) != 1 || !strings.HasPrefix(rs[0].Source.Ref, "nomid: #") {
		t.Fatalf("no Message-ID: %+v", rs)
	}
}
