package mail_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/recall"
)

// REQ: ADP-2, OP-3, REV-2, OP-2, OP-4

// SR3-5: a message's remote identity is folder + UID validity + UID. A
// mailbox rebuilt between a read and a mutation can give an old UID to a
// different message; every selected session checks the validity it
// expects before it acts.

// between is the real IMAP store with a hook run once, just before the
// first call of the named method: the moment a provider rebuilds the
// mailbox between the read and the mutation's own connection.
type between struct {
	mail.Store
	at   string
	hook func()
}

func (b *between) fire(m string) {
	if b.hook != nil && b.at == m {
		f := b.hook
		b.hook = nil
		f()
	}
}

func (b *between) SetFlags(ctx context.Context, r mail.Ref, add, remove []string) error {
	b.fire("SetFlags")
	return b.Store.SetFlags(ctx, r, add, remove)
}

func (b *between) Move(ctx context.Context, r mail.Ref, to string) error {
	b.fire("Move")
	return b.Store.Move(ctx, r, to)
}

func (b *between) Fetch(ctx context.Context, folder string, validity uint32, uids []uint32) ([]mail.Message, error) {
	b.fire("Fetch")
	return b.Store.Fetch(ctx, folder, validity, uids)
}

// newBetween is a harness whose adapter reaches the server through a
// between store.
func newBetween(t *testing.T) (*h, *between) {
	t.Helper()
	b := &between{}
	x := newH(t, func(c *mail.Config) { b.Store = c.Store; c.Store = b })
	return x, b
}

const alertID = "<pw-change@bank.example>"

// rebuild resets folder and delivers a synthetic password-change alert,
// which takes UID 1 again in the new epoch.
func (x *h) rebuild(folder string) func() {
	return func() {
		x.srv.Reset(folder)
		x.deliver(folder, msg{id: alertID, from: "security@bank.example", to: me,
			subject: "Your password was changed", body: "If this was not you, call us. wombatcall"})
	}
}

func (x *h) alertUntouched(t *testing.T, folder string) {
	t.Helper()
	got, flags, ok := x.srv.Find(alertID)
	if !ok || got != folder || len(flags) != 0 {
		t.Fatalf("alert changed: in %q (found %v) flags %v", got, ok, flags)
	}
}

// TestStoreRefusesAStaleValidity: the IMAP store's mutations and fetches
// select the folder and compare its UID validity with the one the
// message was read under, so an old UID never reaches the replacement.
func TestStoreRefusesAStaleValidity(t *testing.T) {
	x := newH(t, nil)
	id := x.news(0)
	ms, err := x.store.Find(ctx, "INBOX", id)
	if err != nil || len(ms) != 1 || ms[0].Validity == 0 {
		t.Fatalf("find: %+v %v", ms, err)
	}
	r := ms[0].Ref()
	if r != (mail.Ref{Folder: "INBOX", Validity: ms[0].Validity, UID: ms[0].UID}) {
		t.Fatalf("ref: %+v", r)
	}
	x.rebuild("INBOX")()
	if err := x.store.SetFlags(ctx, r, []string{mail.Seen}, nil); !errors.Is(err, mail.ErrValidity) {
		t.Fatalf("set flags across the reset: %v", err)
	}
	if err := x.store.Move(ctx, r, "Archive"); !errors.Is(err, mail.ErrValidity) {
		t.Fatalf("move across the reset: %v", err)
	}
	if _, err := x.store.Fetch(ctx, "INBOX", r.Validity, []uint32{r.UID}); !errors.Is(err, mail.ErrValidity) {
		t.Fatalf("fetch across the reset: %v", err)
	}
	x.alertUntouched(t, "INBOX")
	// A ref without a validity is never acted on.
	if err := x.store.SetFlags(ctx, mail.Ref{Folder: "INBOX", UID: 1}, []string{mail.Seen}, nil); !errors.Is(err, mail.ErrValidity) {
		t.Fatalf("no validity: %v", err)
	}
	x.alertUntouched(t, "INBOX")
}

// TestSameEpochMutationsStillRun: deliveries and removals of unrelated
// messages leave the validity unchanged, so they never refuse a mutation
// (only a reset does; the M9 same-message race is separate).
func TestSameEpochMutationsStillRun(t *testing.T) {
	x := newH(t, nil)
	keep := x.news(0)
	gone := x.news(1)
	ms, _ := x.store.Find(ctx, "INBOX", keep)
	r := ms[0].Ref()
	x.news(2)
	x.srv.Remove("INBOX", gone)
	if err := x.store.SetFlags(ctx, r, []string{mail.Flagged}, nil); err != nil {
		t.Fatal(err)
	}
	if fs, err := x.store.Fetch(ctx, "INBOX", r.Validity, []uint32{r.UID}); err != nil || len(fs) != 1 || fs[0].MessageID != keep || fs[0].Ref() != r {
		t.Fatalf("fetch: %+v %v", fs, err)
	}
	if err := x.store.Move(ctx, r, "Archive"); err != nil {
		t.Fatal(err)
	}
	if folder, flags, _ := x.srv.Find(keep); folder != "Archive" || !slices.Equal(flags, []string{mail.Flagged}) {
		t.Fatalf("moved: %s %v", folder, flags)
	}
}

// TestExecutorNeverMutatesAReplacedUID is the F5 regression: the guard
// and the executor read a newsletter, the inbox is rebuilt and its UID
// reused for a password-change alert before the mutation's connection.
// Neither the flag change nor the move touches the alert, and no evidence
// names the newsletter as done.
func TestExecutorNeverMutatesAReplacedUID(t *testing.T) {
	for _, tc := range []struct {
		name, op, at string
		flags        []string // the newsletter's flags before
		want         journal.Result
	}{
		// The keyword is added first: the reset lands before it.
		{"archive", mail.OpArchive, "SetFlags", nil, journal.ResultNotApplied},
		{"mark read", mail.OpMarkRead, "SetFlags", nil, journal.ResultNotApplied},
		// Already labelled: the move is the only command.
		{"move only", mail.OpArchive, "Move", []string{mail.Keyword}, journal.ResultNotApplied},
		// The keyword landed on the newsletter, then the reset: the move
		// is refused and the outcome is left to reconciliation.
		{"after flags", mail.OpArchive, "Move", nil, journal.ResultUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, b := newBetween(t)
			id := x.news(0)
			if tc.flags != nil {
				x.srv.SetFlags(id, tc.flags...)
			}
			in := x.intent(tc.op, rec(id))
			if _, err := x.a.Escalate(ctx, in); err != nil {
				t.Fatal(err)
			}
			b.at, b.hook = tc.at, x.rebuild("INBOX")
			out := x.run(in)
			if b.hook != nil {
				t.Fatal("the reset did not happen")
			}
			if out.Result != tc.want || strings.Contains(out.Evidence, id) {
				t.Fatalf("outcome %s %q", out.Result, out.Evidence)
			}
			// The evidence must not claim nothing changed once flags did.
			if tc.want == journal.ResultUnknown && strings.Contains(out.Evidence, "nothing changed") {
				t.Fatalf("unknown outcome claims nothing changed: %q", out.Evidence)
			}
			x.alertUntouched(t, "INBOX")
			if tc.want == journal.ResultUnknown {
				// Reconciliation re-resolves by Message-ID in the new
				// epoch; the newsletter is gone, so nothing is claimed.
				if r := x.a.Reconcile(ctx, in, 1); r.Result == journal.ResultSucceeded {
					t.Fatalf("reconciled: %q", r.Evidence)
				}
				x.alertUntouched(t, "INBOX")
			}
		})
	}
}

// TestQueuedActionAfterRestartAcrossAReset: an organize authorized
// before a restart and a mailbox rebuild re-resolves on dispatch; the
// alert that took the newsletter's UID is not moved. If the same
// newsletter is back in the new epoch, it is the message acted on, and
// the evidence names its new location.
func TestQueuedActionAfterRestartAcrossAReset(t *testing.T) {
	x := newH(t, nil)
	id := x.news(0)
	in := x.intent(mail.OpArchive, rec(id))
	if _, err := x.a.Escalate(ctx, in); err != nil {
		t.Fatal(err)
	}
	x.rebuild("INBOX")()
	restarted, err := mail.New(x.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if out := restarted.Execute(ctx, in, 1); out.Result != journal.ResultNotApplied {
		t.Fatalf("after restart: %s %q", out.Result, out.Evidence)
	}
	x.alertUntouched(t, "INBOX")
	x.news(0) // the newsletter, redelivered into the new epoch as UID 2
	out := restarted.Execute(ctx, in, 2)
	c := change(t, out)
	if c.Record != id || c.From != "INBOX" || c.Validity != 101 || c.UID != 2 {
		t.Fatalf("evidence: %+v", c)
	}
	if folder, _, _ := x.srv.Find(id); folder != "Archive" {
		t.Fatalf("newsletter in %s", folder)
	}
	x.alertUntouched(t, "INBOX")
}

// TestEvidenceCarriesTheIdentity: an organize change records the folder,
// UID validity and UID of the message it acted on.
func TestEvidenceCarriesTheIdentity(t *testing.T) {
	x := newH(t, nil)
	x.news(0)
	id := x.news(1)
	c := change(t, x.mustRun(x.intent(mail.OpStar, rec(id))))
	if c.From != "INBOX" || c.Validity != 1 || c.UID != 2 {
		t.Fatalf("evidence: %+v", c)
	}
}

// TestUndoAcrossAReset: undo resolves the item again and mutates it only
// under the validity it was read with. An item whose folder was rebuilt
// (gone, or a flag change recorded under another epoch) is skipped, and
// a reset between undo's read and its restore is refused, never applied
// to the message that took the UID.
func TestUndoAcrossAReset(t *testing.T) {
	t.Run("moved item's folder rebuilt", func(t *testing.T) {
		x := newH(t, nil)
		id := x.news(0)
		c := change(t, x.mustRun(x.intent(mail.OpArchive, rec(id))))
		x.rebuild("Archive")()
		if r := x.a.Undo(ctx, []mail.Change{c}); r.Restored != 0 || r.Skipped != 1 {
			t.Fatalf("undo: %+v", r)
		}
		x.alertUntouched(t, "Archive")
	})
	t.Run("flag change under an old epoch", func(t *testing.T) {
		x := newH(t, nil)
		id := x.news(0)
		c := change(t, x.mustRun(x.intent(mail.OpStar, rec(id))))
		// Rebuilt with a same-ID message carrying the flags the agent
		// set: it is not shown to be the message the agent changed.
		x.srv.Reset("INBOX")
		x.deliver("INBOX", msg{id: id, from: "Shop <deals@shop.example>", to: me, subject: "Autumn sale 0", body: "Twenty percent off boots."},
			mail.Flagged, mail.Keyword)
		if r := x.a.Undo(ctx, []mail.Change{c}); r.Restored != 0 || r.Skipped != 1 {
			t.Fatalf("undo: %+v", r)
		}
		if _, flags, _ := x.srv.Find(id); !slices.Equal(flags, []string{mail.Keyword, mail.Flagged}) {
			t.Fatalf("flags: %v", flags)
		}
	})
	t.Run("reset between read and restore", func(t *testing.T) {
		x, b := newBetween(t)
		id := x.news(0)
		c := change(t, x.mustRun(x.intent(mail.OpArchive, rec(id))))
		b.at, b.hook = "SetFlags", x.rebuild("Archive")
		if r := x.a.Undo(ctx, []mail.Change{c}); r.Restored != 0 || r.Skipped != 1 {
			t.Fatalf("undo: %+v", r)
		}
		x.alertUntouched(t, "Archive")
	})
	t.Run("same epoch", func(t *testing.T) {
		x := newH(t, nil)
		id := x.news(0)
		c := change(t, x.mustRun(x.intent(mail.OpStar, rec(id))))
		x.news(1) // unrelated delivery: validity unchanged
		if r := x.a.Undo(ctx, []mail.Change{c}); r.Restored != 1 {
			t.Fatalf("undo: %+v", r)
		}
		if _, flags, _ := x.srv.Find(id); len(flags) != 0 {
			t.Fatalf("flags: %v", flags)
		}
	})
}

// TestWatcherFetchesUnderTheListedValidity: a reset between the
// watcher's listing and its fetch fails that folder's read for the poll
// instead of recording the new epoch's messages under the old validity;
// the next poll reads the new epoch.
func TestWatcherFetchesUnderTheListedValidity(t *testing.T) {
	x, b := newBetween(t)
	p := newPipe(t)
	w := x.watcher(t, p, &recall.MemStore{}, nil)
	x.deliver("INBOX", msg{id: "<n@shop.example>", from: "deals@shop.example", to: me, subject: "Sale", body: "numbatsale"})
	poll(t, w, p)
	x.deliver("INBOX", msg{id: "<m@shop.example>", from: "deals@shop.example", to: me, subject: "Sale 2", body: "numbatsale two"})
	b.at, b.hook = "Fetch", x.rebuild("INBOX")
	r, err := w.Poll(ctx)
	if !errors.Is(err, mail.ErrValidity) || r.Complete || r.Published != 0 || r.Deleted != 0 {
		t.Fatalf("poll across the reset: %+v %v", r, err)
	}
	p.bus.Pump(ctx)
	if r := poll(t, w, p); r.Published != 1 || r.Deleted != 0 || len(p.find("wombatcall")) != 1 {
		t.Fatalf("next poll: %+v", r)
	}
}
