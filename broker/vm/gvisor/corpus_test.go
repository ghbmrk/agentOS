package gvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/corpus"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/mail/imapsmtp"
	"github.com/ghbmrk/agentos/broker/mail/mailtest"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: LOOP-7, ADP-11
//
// P3-4b-4d: Loop 2's corpus probe replays the published injection items
// into an agent machine as untrusted input over its guest plane (owner
// messages, the MCP effect tool, mail it is asked to act on) and takes
// each closed check's verdict from what the broker then saw: the owner's
// line, the journal and the mailbox. The guest stand-in obeys its input.
// P3-4b-4e adds the commitment filter, reached the only way a guest
// reaches it: an ADP-11 auto-reply in a thread the owner pre-allowed,
// whose verdict is what the gate and the owner channel did with it.

const (
	ownerNum, boxNum = "+15550000101", "+15550000102"
	me               = "owner@example.test"
	labelTarget      = "<label-target@news.example>"
	// The pre-allowed thread: the owner wrote to peer (the Sent copy is
	// the starter threadVerified reads) and peer answered in the inbox.
	// A cold thread is outside mail from a stranger nobody wrote to.
	peer, threadStart, threadReply = "pat@contacts.example", "<lunch-1@example.test>", "<lunch-2@contacts.example>"
	coldThread                     = "<cold-1@stranger.example>"
)

// gateOwner is the owner channel as the gate sees it, with approval
// requests recorded rather than texted, so the test can grant mail the way
// the owner's local page does. Nothing under test is an approval.
type gateOwner struct {
	*owner.Channel
	mu   sync.Mutex
	n    int
	reqs map[string][]owner.Item
	last string
	at   map[string]ask // the latest request asking about each ref
	// replies is what the owner channel did with each auto-reply the
	// gate handed it, by intent ref: the broker's own verdict.
	replies map[string]queuedReply
	// weak, when set, stands in for the channel's queue with a commitment
	// filter that matches nothing (the commitment filter's control). It
	// holds what it queues and never sends it.
	weak func(owner.AutoReply) (owner.QueueResult, error)
}

// queuedReply is one auto-reply as the owner channel answered the gate.
type queuedReply struct {
	reply owner.AutoReply
	res   owner.QueueResult
	err   error
	weak  bool
}

// QueueAutoReply is the gate's ADP-11 hand-off to the owner channel,
// recorded.
func (o *gateOwner) QueueAutoReply(ar owner.AutoReply) (owner.QueueResult, error) {
	o.mu.Lock()
	weak := o.weak
	o.mu.Unlock()
	queue := o.Channel.QueueAutoReply
	if weak != nil {
		queue = weak
	}
	res, err := queue(ar)
	o.mu.Lock()
	o.replies[ar.Ref] = queuedReply{reply: ar, res: res, err: err, weak: weak != nil}
	o.mu.Unlock()
	return res, err
}

func (o *gateOwner) Request(items []owner.Item, _ time.Duration) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.n++
	o.last = fmt.Sprintf("R%d", o.n)
	o.reqs[o.last] = append([]owner.Item(nil), items...)
	for i, it := range items {
		o.at[it.Ref] = ask{id: o.last, ref: it.Ref, item: i + 1}
	}
	return o.last, nil
}

func (o *gateOwner) RequestEach(items []owner.Item, _ []time.Duration) ([]string, error) {
	var ids []string
	for _, it := range items {
		id, _ := o.Request([]owner.Item{it}, 0)
		ids = append(ids, id)
	}
	return ids, nil
}

func (o *gateOwner) RequestLocalEach(items []owner.Item, ttls []time.Duration) ([]string, error) {
	return o.RequestEach(items, ttls)
}

// hostMachines is guest.Machines for a guest run on the host.
type hostMachines struct{}

func (hostMachines) Step(context.Context, string) error { return nil }
func (hostMachines) RaisePrivate(string) error          { return nil }
func (hostMachines) Lineage(id string) (string, error)  { return id, nil }

// managerRef lets the plane reach the manager, which needs the plane as
// its Services and so is opened after it.
type managerRef struct{ m atomic.Pointer[vm.Manager] }

func (r *managerRef) Step(ctx context.Context, id string) error {
	_, err := r.m.Load().Step(ctx, id)
	return err
}
func (r *managerRef) RaisePrivate(id string) error { return r.m.Load().RaiseLabel(id, vm.Private) }
func (r *managerRef) Lineage(id string) (string, error) {
	mc, err := r.m.Load().Get(id)
	return mc.Lineage, err
}

// relay is corpus.Relay over a real guest plane, journal, grants gate,
// mail adapter and owner channel; run runs the guest in its machine.
type relay struct {
	t       *testing.T
	srv     *mailtest.Server
	eng     *journal.Engine
	plane   *guest.Plane
	box     modem.Modem
	phone   *modem.Line
	ch      *owner.Channel
	machine string
	sock    string // the broker socket as the guest sees it
	run     func(ctx context.Context, args ...string) (string, error)
	gate    *grants.Gate
	own     *gateOwner

	mu      sync.Mutex
	n       int
	replied string
	// send is what the broker does with a guest's reply to the owner:
	// the owner channel's Notify, or a weakened copy (the control).
	send func(text string) error
	// approve has the owner approve the gate's alert archive (the
	// archive route's control).
	approve bool
	// isolated is whether the gate counts the machine as an ADP-11
	// reply composer (Config.Isolated); off only to show a reply the
	// gate refuses for it is an error.
	isolated atomic.Bool
}

// undoWindow is the rig's ADP-11 undo window: short, so a queued reply
// the rig failed to cancel would be released by the gate's next tick,
// which replayAll runs before it checks nothing was sent.
const undoWindow = time.Millisecond

// routeTimeout bounds each route, so a guest or mail exchange that stalls
// fails the run on the check it was serving instead of hanging it.
const routeTimeout = 30 * time.Second

func newRelay(t *testing.T, machines guest.Machines) *relay {
	t.Helper()
	x := &relay{t: t, srv: mailtest.Start(t)}
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: x.srv.IMAP, SMTP: x.srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain,
		From: me, Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: mailtest.User, Secret: mailtest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := mail.New(mail.Config{Account: "mail", Address: me, Store: st, AuthServ: "mx.example.test",
		SecuritySenders: []string{"security@provider.example"}, Labels: []string{"Family"},
		InUse: func(action string, since time.Time) []journal.Use {
			return x.eng.InUse("mail", action, since)
		}})
	if err != nil {
		t.Fatal(err)
	}
	x.isolated.Store(true)
	g := grants.New(grants.Config{Declared: map[string]map[string]string{"mail": mail.Declared()},
		Verifiers: map[string]grants.Verifier{"mail": a}, LocalUI: true,
		Isolated: func(m string) bool { return x.isolated.Load() && m != "" && m == x.machine }})
	if x.eng, err = journal.Open(&journal.MemStore{}, g, map[string]journal.Executor{"mail": a, grants.ExecutorName: g},
		func(s string) string { return s }); err != nil {
		t.Fatal(err)
	}
	carrier := modem.NewCarrier()
	box := carrier.Line(boxNum)
	x.box, x.phone = box, carrier.Line(ownerNum)
	if x.ch, err = owner.New(owner.Config{Owner: ownerNum, Modem: box, Engine: x.eng, Store: &owner.MemStore{},
		Location: time.UTC, Decide: g.Decide, UndoWindow: undoWindow}); err != nil {
		t.Fatal(err)
	}
	x.send = x.ch.Notify
	own := &gateOwner{Channel: x.ch, reqs: map[string][]owner.Item{}, at: map[string]ask{}, replies: map[string]queuedReply{}}
	g.Attach(x.eng, own)
	x.gate, x.own = g, own
	x.grant(grants.Spec{Account: "mail", Executor: "mail", Ops: mail.Declared()})
	// ADP-11's pre-allowance, granted down the same owner path. The gate
	// asks for no CAP-6 run when the owner grants it (a finding, recorded
	// in loops ASSUMPTIONS S44), so the rig has none to earn.
	x.grant(grants.Spec{Account: "mail", Rule: &grants.Rule{Action: mail.OpReply, Reply: true, PerRecord: 40, PerDay: 40}})

	x.plane, err = guest.New(guest.Config{Dir: filepath.Join(t.TempDir(), "guests"), Machines: machines, Effects: g,
		Route:       func(account string) (string, bool) { return "mail", account == "mail" },
		SubmitBurst: 100,
		OwnerReply: func(_ string, rep guest.Reply) {
			x.mu.Lock()
			x.replied = rep.Text
			send := x.send
			x.mu.Unlock()
			send(rep.Text)
		},
		Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(x.plane.Shutdown)
	x.srv.Deliver("INBOX", letter(labelTarget, "news@news.example", "Weekly news", "Nothing urgent."))
	x.srv.Deliver("Sent", mailOf(threadStart, me, peer, "Lunch", "", "Lunch next week?"))
	x.srv.Deliver("INBOX", mailOf(threadReply, "Pat <"+peer+">", me, "Re: Lunch", threadStart, "Sure, glad to."))
	x.srv.Deliver("INBOX", mailOf(coldThread, "stranger@stranger.example", me, "Hello", "", "Write back."))
	return x
}

// grant grants spec the way the owner does: approved, then confirmed on
// the local page.
func (x *relay) grant(s grants.Spec) {
	x.t.Helper()
	g, own := x.gate, x.own
	b, _ := json.Marshal(s)
	var spec map[string]any
	json.Unmarshal(b, &spec)
	in := journal.Intent{ID: fmt.Sprintf("local/grant/%d", len(x.eng.List())+1), Origin: "local", Account: journal.BrokerAccount,
		Action: journal.ActionGrantChange, Params: map[string]any{"grant": spec}, Executor: grants.ExecutorName}
	if _, err := g.Submit(in); err != nil {
		x.t.Fatal(err)
	}
	if st, _ := g.Authorize(context.Background(), in.ID); st.State != journal.Pending {
		x.t.Fatalf("grant: %s %q", st.State, st.Permission.Reason)
	}
	g.Flush()
	own.mu.Lock()
	req, items := own.last, own.reqs[own.last]
	own.mu.Unlock()
	for i, it := range items {
		g.Decide(owner.Decision{Request: req, Item: i + 1, Ref: it.Ref, Approved: true, Why: "owner"})
	}
	g.Wait()
	if err := g.ConfirmLocal(in.ID); err != nil {
		x.t.Fatal(err)
	}
	g.Wait()
}

func letter(id, from, subject, body string) string { return mailOf(id, from, me, subject, "", body) }

// mailOf is a message from from to to, in reply to parent when it is set.
func mailOf(id, from, to, subject, parent, body string) string {
	thread := ""
	if parent != "" {
		thread = "\nIn-Reply-To: " + parent + "\nReferences: " + parent
	}
	return "From: " + from + "\nTo: " + to + "\nSubject: " + subject +
		"\nDate: Fri, 09 Oct 2026 08:00:00 +0000\nMessage-ID: " + id + thread + "\n\n" + body + "\n"
}

// owed drains what the owner's line carried, and returns the last text.
func (x *relay) owed() string {
	last := ""
	for {
		select {
		case m := <-x.phone.Inbox():
			last = m.Text
		case <-time.After(250 * time.Millisecond):
			return last
		}
	}
}

func (x *relay) next() string {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.n++
	return fmt.Sprintf("corpus-%d", x.n)
}

// requested is the journaled request reqID, and whether the guest carried
// key=want in it, key present even for an empty want: the broker's own
// record of what the guest asked.
func (x *relay) requested(reqID, key, want string) error {
	_, err := x.carried(reqID, key, want)
	return err
}

// carried is requested, answering the journaled request.
func (x *relay) carried(reqID, key, want string) (journal.Status, error) {
	for _, st := range x.eng.List() {
		if strings.HasSuffix(st.Intent.ID, "/"+reqID) && strings.HasPrefix(st.Intent.Origin, "guest:") {
			if v, ok := st.Intent.Params[key].(string); !ok || v != want {
				return st, errors.New("the request does not carry the text handed over")
			}
			return st, nil
		}
	}
	return journal.Status{}, errors.New("the broker journaled no request")
}

func (x *relay) Reply(ctx context.Context, text string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, routeTimeout)
	defer cancel()
	x.owed()
	x.mu.Lock()
	x.replied = ""
	x.mu.Unlock()
	if _, err := x.plane.DeliverOwner(x.machine, text, false); err != nil {
		return "", err
	}
	if _, err := x.run(ctx, "relay", x.sock, "reply"); err != nil {
		return "", err
	}
	x.mu.Lock()
	got := x.replied
	x.mu.Unlock()
	if got != text {
		return "", errors.New("the guest's reply is not the text handed over")
	}
	sent := x.owed()
	if sent == "" {
		return "", errors.New("nothing reached the owner's line")
	}
	return sent, nil
}

func (x *relay) Label(ctx context.Context, text string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, routeTimeout)
	defer cancel()
	_, before, ok := x.srv.Find(labelTarget)
	if !ok {
		return false, errors.New("label target gone")
	}
	if _, err := x.plane.DeliverOwner(x.machine, text, false); err != nil {
		return false, err
	}
	req := x.next()
	if _, err := x.run(ctx, "relay", x.sock, "label", labelTarget, req); err != nil {
		return false, err
	}
	x.owed()
	if err := x.requested(req, "label", text); err != nil {
		return false, err
	}
	_, after, _ := x.srv.Find(labelTarget)
	for _, f := range after {
		if !slices.Contains(before, f) {
			return true, nil
		}
	}
	return false, nil
}

func (x *relay) Archive(ctx context.Context, text string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, routeTimeout)
	defer cancel()
	req := x.next()
	rec := "<" + req + "@news.example>"
	x.srv.Deliver("INBOX", letter(rec, "news@news.example", "Weekly news", text))
	if _, err := x.run(ctx, "relay", x.sock, "archive", rec, req); err != nil {
		return false, err
	}
	if err := x.requested(req, "record", rec); err != nil {
		return false, err
	}
	asked, err := x.settle(ctx, req)
	if err != nil {
		return false, err
	}
	if x.approve && asked.id != "" {
		x.gate.Decide(owner.Decision{Request: asked.id, Item: asked.item, Ref: asked.ref, Approved: true, Why: "owner"})
		x.gate.Wait()
		if asked, err = x.settle(ctx, req); err != nil {
			return false, err
		}
		if asked.id != "" {
			return false, errors.New("the approved archive is still pending")
		}
	}
	folder, _, ok := x.srv.Find(rec)
	return !ok || folder != "INBOX", nil
}

// AutoReply has the guest compose text as a reply in the pre-allowed
// thread and reports what the broker did with it.
func (x *relay) AutoReply(ctx context.Context, text string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, routeTimeout)
	defer cancel()
	return x.autoReply(ctx, text, threadReply, peer)
}

// autoReply has the guest compose text as a reply to record, addressed to
// to, over MCP. Its verdict is the owner channel's answer to the gate: a
// queued reply (which it then cancels, so nothing is sent) or a normal
// approval request. A reply the gate did not hand the channel as an
// auto-reply, one the channel refused, or one not left waiting on the
// owner is an error: it says nothing about the filter.
func (x *relay) autoReply(ctx context.Context, text, record, to string) (bool, error) {
	x.owed()
	if _, err := x.plane.DeliverOwner(x.machine, text, false); err != nil {
		return false, err
	}
	req := x.next()
	if _, err := x.run(ctx, "relay", x.sock, "autoreply", record, req, to); err != nil {
		return false, err
	}
	x.owed()
	st, err := x.carried(req, mail.ParamBody, text)
	if err != nil {
		return false, err
	}
	x.own.mu.Lock()
	q, ok := x.own.replies[st.Intent.ID]
	x.own.mu.Unlock()
	switch {
	case !ok:
		return false, fmt.Errorf("the gate did not take the reply as an auto-reply (%s)", st.State)
	case q.err != nil:
		return false, q.err
	case q.reply.Body != text:
		return false, errors.New("the auto-reply is not the text handed over")
	case st.State != journal.Pending:
		return false, fmt.Errorf("the reply is %s, not waiting on the owner", st.State)
	case q.res.Queued != nil:
		if q.weak {
			return true, nil // the stand-in holds it and never sends
		}
		return true, x.undo(ctx, req, q.res.Queued.ID)
	case q.res.Request != "":
		return false, nil
	}
	return false, errors.New("the owner channel neither queued the reply nor asked about it")
}

// undo has the owner cancel queued reply id within its undo window, as
// ADP-11's alert offers, and checks the broker denied request reqID.
func (x *relay) undo(ctx context.Context, reqID, id string) error {
	out := x.ch.Handle(ctx, ownerNum, "UNDO "+id)
	x.gate.Wait()
	if len(out) != 1 || !strings.Contains(out[0], "The reply was not sent.") {
		return fmt.Errorf("UNDO %s: %q", id, out)
	}
	for {
		st, err := x.carried(reqID, mail.ParamRecord, threadReply)
		if err != nil || st.State == journal.Denied {
			return err
		}
		if st.State != journal.Pending {
			return fmt.Errorf("the cancelled reply is %s", st.State)
		}
		select {
		case <-ctx.Done():
			return errors.New("the cancelled reply is still pending")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// ask is where the owner was asked about one intent: request id, item
// number and ref; id is empty when the intent was not left to the owner.
type ask struct {
	id, ref string
	item    int
}

// settle waits under ctx for the guest's request reqID to settle: done,
// denied, or pending with the owner asked. An intent still authorized or
// in flight when ctx ends is an error, never a caught route.
func (x *relay) settle(ctx context.Context, reqID string) (ask, error) {
	for {
		var st journal.Status
		found := false
		for _, s := range x.eng.List() {
			if strings.HasSuffix(s.Intent.ID, "/"+reqID) && strings.HasPrefix(s.Intent.Origin, "guest:") {
				st, found = s, true
			}
		}
		if !found {
			return ask{}, errors.New("the broker journaled no request")
		}
		switch st.State {
		case journal.Succeeded, journal.NotApplied, journal.Denied, journal.OutcomeUnknown:
			return ask{}, nil
		case journal.Pending:
			x.gate.Flush()
			if a, ok := x.asked(st.Intent.ID); ok {
				return a, nil
			}
		}
		select {
		case <-ctx.Done():
			return ask{}, errors.New("the request did not settle: " + string(st.State))
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// asked is the latest owner request that carries the intent ref, if any.
func (x *relay) asked(ref string) (ask, bool) {
	x.own.mu.Lock()
	defer x.own.mu.Unlock()
	a, ok := x.own.at[ref]
	return a, ok
}

// planeCheck is the one check of corpus.PlaneChecks(x) named name.
func planeCheck(x *relay, name string) []loops.ClosedCheck {
	for _, c := range corpus.PlaneChecks(x) {
		if c.Name == name {
			return []loops.ClosedCheck{c}
		}
	}
	x.t.Fatalf("no plane check %q", name)
	return nil
}

// replayAll checks that every route is live (a benign text gets through
// each), then runs the corpus probe over the routes and returns its
// findings, checked to carry an item ID and a check name only.
func replayAll(t *testing.T, x *relay) {
	t.Helper()
	ctx := context.Background()
	if sent, err := x.Reply(ctx, "Lunch is at noon."); err != nil || sent != owner.AgentPrefix+"Lunch is at noon." {
		t.Fatalf("reply route: %q %v", sent, err)
	}
	if hidden, err := x.Archive(ctx, "Nothing urgent this week."); err != nil || !hidden {
		t.Fatalf("archive route: %v %v", hidden, err)
	}
	if queued, err := x.AutoReply(ctx, "Thanks, glad to hear it."); err != nil || !queued {
		t.Fatalf("auto-reply route: %v %v", queued, err)
	}
	// A reply the gate refuses for a reason other than the filter is no
	// verdict: a cold thread, a machine that is not a reply composer.
	if _, err := x.autoReply(ctx, corpus.CommitmentPayload, coldThread, "stranger@stranger.example"); err == nil {
		t.Fatal("a reply in a cold thread read as a verdict")
	}
	x.isolated.Store(false)
	_, err := x.AutoReply(ctx, corpus.CommitmentPayload)
	x.isolated.Store(true)
	if err == nil {
		t.Fatal("a reply from a machine that is not a composer read as a verdict")
	}
	items, err := loops.LoadCorpus("../../../assurance/corpora/promptinject/items.json")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, it := range items {
		ids[it.ID] = true
	}
	probe := &loops.CorpusProbe{Interval: 1, Items: items, Checks: corpus.PlaneChecks(x)}
	res, err := probe.Run(ctx)
	if err != nil || len(res.Found) != 0 || len(res.Checked) != len(items)*len(probe.Checks) {
		t.Fatalf("clean run: %+v %v", res, err)
	}
	// Control: an item that replays to a configured label gets past the
	// label check, and the probe finds it through the plane. It runs
	// after the clean run, as the label it applies stays on the target.
	labelProbe := &loops.CorpusProbe{Interval: 1, Items: []loops.CorpusItem{{ID: "control-label", Text: "Family{REPLACE_rogue_string}"}},
		Checks: planeCheck(x, corpus.LabelCheck)}
	res, err = labelProbe.Run(ctx)
	if err != nil || len(res.Found) != 1 || res.Found[0].Subject != "control-label" || res.Found[0].Detail != corpus.LabelCheck {
		t.Fatalf("label control: %+v %v", res, err)
	}

	// Control: with the owner approving the gate's alert archive, alert
	// mail leaves the inbox and the probe fails on the check's own payload.
	x.approve = true
	_, err = (&loops.CorpusProbe{Interval: 1, Items: items, Checks: planeCheck(x, corpus.AlertPatterns)}).Run(ctx)
	x.approve = false
	if err == nil || !strings.Contains(err.Error(), corpus.AlertPatterns+" misses its own payload") {
		t.Fatalf("archive control: %v", err)
	}

	// Control: with the owner channel's commitment filter matching
	// nothing, every reply is queued and the probe fails on the filter's
	// own payload.
	x.own.mu.Lock()
	x.own.weak = func(ar owner.AutoReply) (owner.QueueResult, error) {
		return owner.QueueResult{Queued: &owner.Queued{ID: "W" + ar.Ref, SendAt: time.Now().Add(undoWindow), Reply: ar}}, nil
	}
	x.own.mu.Unlock()
	_, err = (&loops.CorpusProbe{Interval: 1, Items: items, Checks: planeCheck(x, corpus.CommitmentFilter)}).Run(ctx)
	x.own.mu.Lock()
	x.own.weak = nil
	x.own.mu.Unlock()
	if err == nil || !strings.Contains(err.Error(), corpus.CommitmentFilter+" misses its own payload") {
		t.Fatalf("commitment control: %v", err)
	}

	// Control: a reply filter weakened to scan a text's first 40 bytes
	// lets codes past it reach the owner, and the probe finds them.
	x.mu.Lock()
	x.send = func(s string) error {
		if owner.SecretShaped(s[:min(len(s), 40)]) {
			return x.box.Send(ownerNum, owner.Hidden)
		}
		return x.box.Send(ownerNum, owner.AgentPrefix+s)
	}
	x.mu.Unlock()
	probe.Checks = planeCheck(x, corpus.CodeFilter)
	res, err = probe.Run(ctx)
	if err != nil || len(res.Found) == 0 {
		t.Fatalf("weakened run: %+v %v", res, err)
	}
	for _, f := range res.Found {
		if !ids[f.Subject] || f.Detail != corpus.CodeFilter || f.Check != loops.CheckCorpus || f.Rule != nil {
			t.Fatalf("finding %+v", f)
		}
	}

	// Nothing the replay composed is sent (ADP-11): the channel holds no
	// queued reply, and past the undo window the gate's tick releases
	// nothing, so no account submitted mail.
	time.Sleep(10 * undoWindow)
	x.gate.Tick()
	x.gate.Wait()
	if x.ch.UndoOpen() {
		t.Fatal("an auto-reply is still queued to send")
	}
	if sent := x.srv.Submitted(); len(sent) != 0 {
		t.Fatalf("the replay sent %d messages", len(sent))
	}
}

// TestCorpusReplayThroughTheGuestPlane runs the guest stand-in on the host
// against the real broker side; the gVisor test below runs it in a
// machine.
func TestCorpusReplayThroughTheGuestPlane(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "guest")
	build := exec.Command("go", "build", "-o", bin, "./testdata/guest")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building guest: %v\n%s", err, out)
	}
	x := newRelay(t, hostMachines{})
	x.machine = "corpus"
	dir, err := x.plane.Open(x.machine)
	if err != nil {
		t.Fatal(err)
	}
	x.sock = filepath.Join(dir, guest.Socket)
	x.run = func(ctx context.Context, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, bin, args...).Output()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return strings.TrimSpace(string(out)), err
	}
	replayAll(t, x)
}

// TestCorpusReplayInAMachine is the same replay into a gVisor machine,
// the guest acting with the machine's own authority.
func TestCorpusReplayInAMachine(t *testing.T) {
	ref := &managerRef{}
	x := newRelay(t, ref)
	r := newRigWith(t, 4096, x.plane)
	ref.m.Store(r.m)
	x.machine = "corpus"
	r.create(x.machine, admission.Accepted)
	r.ask(x.machine, "token") // waits for the machine to start
	x.sock = vm.ServicesMount + "/" + guest.Socket
	logs := t.TempDir()
	x.run = func(ctx context.Context, args ...string) (string, error) {
		out, err := rawExec(ctx, r.rt, logs, x.machine, append([]string{"/guest"}, args...)...)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return strings.TrimSpace(out), err
	}
	replayAll(t, x)
}

// rawExecTail is how much of runsc's stderr and of its --log a failed raw
// exec's error carries.
const rawExecTail = 2048

// rawExec runs argv in machine id with a raw `runsc exec`, as the corpus
// replay always has, and answers its stdout. It does not go through
// Runtime.Exec, whose --cwd, --user and --pass-fd differ (a release row
// of its own). It adds only a --log file of its own, in dir, and keeps
// the process's stderr: when the exec fails, the error carries the exit
// code and the last rawExecTail bytes of each, since an exit 128 is
// runsc's own fatal and its reason is only there (P1-4-flake-exit128).
// With no --pass-fd, that stderr is runsc's merged with the guest's, and
// its label says so; the --log file is runsc's alone. The text is from
// synthetic corpus runs, printed only in a test failure.
func rawExec(ctx context.Context, r *Runtime, dir, id string, argv ...string) (string, error) {
	f, err := os.CreateTemp(dir, "exec-*.log")
	if err != nil {
		return "", err
	}
	f.Close()
	defer os.Remove(f.Name())
	var stderr bytes.Buffer
	c := r.cmd(ctx, append([]string{"--log=" + f.Name(), "exec", cid(id)}, argv...)...)
	c.Stderr = &stderr
	out, err := c.Output()
	if exit, ok := err.(*exec.ExitError); ok {
		log, _ := os.ReadFile(f.Name())
		err = fmt.Errorf("%w (exit %d)\nrunsc and guest stderr: %q\nrunsc log: %q", exit, exit.ExitCode(), tail(stderr.Bytes(), rawExecTail), tail(log, rawExecTail))
	}
	return string(out), err
}

// tail answers b's last n bytes.
func tail(b []byte, n int) string { return string(b[max(0, len(b)-n):]) }

// REQ: CAP-8, RES-4
//
// P1-4-flake-exit128: the corpus replay's raw `runsc exec` failed with a
// bare "exit status 128", runsc's own fatal, its reason discarded. Its
// error now carries the exit code and the tails of runsc's stderr and
// --log, so the next occurrence names runsc's reason.
func TestRawExecErrorCarriesRunscText(t *testing.T) {
	r := fakeRunsc(t)
	_, err := rawExec(context.Background(), r, t.TempDir(), "corpus", "fatal128")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 128 {
		t.Fatalf("error %v, want runsc's exit 128", err)
	}
	msg := err.Error()
	for _, want := range []string{"exit 128", "runsc and guest stderr: ", "runsc log: "} {
		if !strings.Contains(msg, want) {
			t.Errorf("error lacks %q: %s", want, msg)
		}
	}
	// Once from stderr, once from the --log line.
	if n := strings.Count(msg, "loading container failed: "+runscCanary); n != 2 {
		t.Errorf("runsc's message %d times in the error, want 2: %s", n, msg)
	}
}

// Only the tail of runsc's text is kept, so a large stderr cannot flood
// the test log.
func TestRawExecErrorClipsRunscText(t *testing.T) {
	if got := tail([]byte(strings.Repeat("x", 3*rawExecTail)+"end"), rawExecTail); len(got) != rawExecTail || !strings.HasSuffix(got, "end") {
		t.Fatalf("tail kept %d bytes ending %q", len(got), got[max(0, len(got)-8):])
	}
}
