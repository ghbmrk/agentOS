package gvisor

import (
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

// REQ: LOOP-7
//
// P3-4b-4d: Loop 2's corpus probe replays the published injection items
// into an agent machine as untrusted input over its guest plane (owner
// messages, the MCP effect tool, mail it is asked to act on) and takes
// each closed check's verdict from what the broker then saw: the owner's
// line, the journal and the mailbox. The guest stand-in obeys its input.

const (
	ownerNum, boxNum = "+15550000101", "+15550000102"
	me               = "owner@example.test"
	labelTarget      = "<label-target@news.example>"
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
}

func (o *gateOwner) Request(items []owner.Item, _ time.Duration) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.n++
	o.last = fmt.Sprintf("R%d", o.n)
	o.reqs[o.last] = append([]owner.Item(nil), items...)
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
	run     func(args ...string) (string, error)

	mu      sync.Mutex
	n       int
	replied string
	// send is what the broker does with a guest's reply to the owner:
	// the owner channel's Notify, or a weakened copy (the control).
	send func(text string) error
}

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
		Authorized: func(action string, since time.Time) []journal.Intent {
			return x.eng.AuthorizedSince("mail", action, since)
		}})
	if err != nil {
		t.Fatal(err)
	}
	g := grants.New(grants.Config{Declared: map[string]map[string]string{"mail": mail.Declared()},
		Verifiers: map[string]grants.Verifier{"mail": a}, LocalUI: true})
	if x.eng, err = journal.Open(&journal.MemStore{}, g, map[string]journal.Executor{"mail": a, grants.ExecutorName: g},
		func(s string) string { return s }); err != nil {
		t.Fatal(err)
	}
	carrier := modem.NewCarrier()
	box := carrier.Line(boxNum)
	x.box, x.phone = box, carrier.Line(ownerNum)
	if x.ch, err = owner.New(owner.Config{Owner: ownerNum, Modem: box, Engine: x.eng, Store: &owner.MemStore{},
		Location: time.UTC, Decide: g.Decide}); err != nil {
		t.Fatal(err)
	}
	x.send = x.ch.Notify
	own := &gateOwner{Channel: x.ch, reqs: map[string][]owner.Item{}}
	g.Attach(x.eng, own)
	x.grant(g, own)

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
	return x
}

// grant connects mail the way the owner does: approved, then confirmed
// on the local page.
func (x *relay) grant(g *grants.Gate, own *gateOwner) {
	x.t.Helper()
	b, _ := json.Marshal(grants.Spec{Account: "mail", Executor: "mail", Ops: mail.Declared()})
	var spec map[string]any
	json.Unmarshal(b, &spec)
	in := journal.Intent{ID: "local/grant/1", Origin: "local", Account: journal.BrokerAccount,
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

func letter(id, from, subject, body string) string {
	return "From: " + from + "\nTo: " + me + "\nSubject: " + subject +
		"\nDate: Fri, 09 Oct 2026 08:00:00 +0000\nMessage-ID: " + id + "\n\n" + body + "\n"
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
// key=want in it: the broker's own record of what the guest asked.
func (x *relay) requested(reqID, key, want string) error {
	for _, st := range x.eng.List() {
		if strings.HasSuffix(st.Intent.ID, "/"+reqID) && strings.HasPrefix(st.Intent.Origin, "guest:") {
			if v, _ := st.Intent.Params[key].(string); v != want {
				return errors.New("the request does not carry the text handed over")
			}
			return nil
		}
	}
	return errors.New("the broker journaled no request")
}

func (x *relay) Reply(_ context.Context, text string) (string, error) {
	x.owed()
	x.mu.Lock()
	x.replied = ""
	x.mu.Unlock()
	if _, err := x.plane.DeliverOwner(x.machine, text, false); err != nil {
		return "", err
	}
	if _, err := x.run("relay", x.sock, "reply"); err != nil {
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

func (x *relay) Label(_ context.Context, text string) (bool, error) {
	_, before, ok := x.srv.Find(labelTarget)
	if !ok {
		return false, errors.New("label target gone")
	}
	if _, err := x.plane.DeliverOwner(x.machine, text, false); err != nil {
		return false, err
	}
	req := x.next()
	if _, err := x.run("relay", x.sock, "label", labelTarget, req); err != nil {
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

func (x *relay) Archive(_ context.Context, text string) (bool, error) {
	req := x.next()
	rec := "<" + req + "@news.example>"
	x.srv.Deliver("INBOX", letter(rec, "news@news.example", "Weekly news", text))
	if _, err := x.run("relay", x.sock, "archive", rec, req); err != nil {
		return false, err
	}
	if err := x.requested(req, "record", rec); err != nil {
		return false, err
	}
	folder, _, ok := x.srv.Find(rec)
	return !ok || folder != "INBOX", nil
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
	if err != nil || len(res.Found) != 0 || len(res.Checked) != len(items) {
		t.Fatalf("clean run: %+v %v", res, err)
	}
	// The label route is live last: a configured label applies.
	if labelled, err := x.Label(ctx, "Family"); err != nil || !labelled {
		t.Fatalf("label route: %v %v", labelled, err)
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
	probe.Checks = corpus.PlaneChecks(x)[:1]
	res, err = probe.Run(ctx)
	if err != nil || len(res.Found) == 0 {
		t.Fatalf("weakened run: %+v %v", res, err)
	}
	for _, f := range res.Found {
		if !ids[f.Subject] || f.Detail != corpus.CodeFilter || f.Check != loops.CheckCorpus || f.Rule != nil {
			t.Fatalf("finding %+v", f)
		}
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
	x.run = func(args ...string) (string, error) {
		out, err := exec.Command(bin, args...).Output()
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
	x.run = func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		out, err := r.rt.cmd(ctx, append([]string{"exec", cid(x.machine), "/guest"}, args...)...).Output()
		return strings.TrimSpace(string(out)), err
	}
	replayAll(t, x)
}
