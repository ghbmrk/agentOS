package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// Evidence delivery (CH-20). With a destination set and a mail account
// connected, an agent reply from a private machine goes to the owner's
// own address, delivered by the broker as a pre-allowed share to the
// owner (grants OriginEvidence, mail.OpDeliver), and the text carries only
// a summary and a pointer. The destination is the gate's: the owner sets
// it with a code and the local page, never the agent. Otherwise replies
// are texted as before (DEP-3, UX U1 on #148); one too long for a text
// is kept on the box and the text says so (potency C1). No owner text
// names a page for kept replies until one exists (UX U2).

// mailbox is what the router needs of the connected mail account: which
// addresses are the owner's own (mail.Adapter.Owns) and the main one.
type mailbox interface {
	Owns(addr string) (account string, ok bool)
	Main() (addr, account string)
}

// evidenceGate is what the router and the setting use of the gate.
type evidenceGate interface {
	Evidence() (address, account string)
	Submit(journal.Intent) (journal.Status, error)
	Authorize(context.Context, string) (journal.Status, error)
	Dispatch(context.Context, string) (journal.Status, error)
}

type evidenceGateBox struct{ g evidenceGate }

type evidence struct {
	// gate is set once the daemon runs.
	gate atomic.Pointer[evidenceGateBox]
	// notify texts the owner an agent reply (owner.Channel.Notify, which
	// adds the prefix and runs CH-19's filter).
	notify func(string) error
	// mail is the connected mail account; nil while none is, as in this
	// build: no destination can be set and every reply goes by text.
	mail  mailbox
	kept  *keptReplies
	now   func() time.Time
	sleep func(time.Duration)
	logf  func(string, ...any)
	// page says agentosd serves the box's Wi-Fi page (-localui-uid), where
	// setting a destination is confirmed (CH-20); the gate's LocalUI.
	page bool

	q chan evidenceJob

	mu sync.Mutex
	// failing is when deliveries started failing; zero while they work.
	// refused: the last failure was the gate's refusal, not transport.
	failing time.Time
	refused bool
	// shown is the destination the digest last confirmed; digest holds
	// one-time digest lines (security C3, UX U5).
	shown  string
	digest []string
}

type evidenceJob struct {
	machine       string
	private       bool
	text, summary string
}

// Fixed wording, in the box's first-person voice (UX U7).
const (
	keptLong         = "Cut here. Ask me to send it in shorter parts."
	capNote          = "I've emailed the most replies I send in a day, so I kept this one on the box."
	failNote         = "I couldn't email the full reply, so I kept it on the box. Check that your mail account still signs in."
	refusedNote      = "I couldn't email the full reply, so I kept it on the box. Send EMAIL REPLIES ON to set emailing up again."
	evidenceEffect   = "With this on, I email your private replies and texts carry a one-line summary. Send EMAIL REPLIES OFF to stop. A request for your code follows; then confirm on my Wi-Fi page."
	evidenceNotYet   = "Emailing private replies is not in this build yet."
	evidenceOff      = "Private replies come by text again."
	evidenceNone     = "Private replies already come by text."
	evidenceStarting = "I'm still starting. Try again in a minute."
	evidenceFailed   = "I couldn't save that setting. Try again later."
	evidenceNoPage   = "Not changed: turning this on needs my Wi-Fi page, which isn't running."
	// offNotice goes to the old destination when it is cleared by text
	// (security C3 on #148, its wording).
	offNotice = "Emailing private replies was turned off by text at %s. If that wasn't you, send EMAIL REPLIES ON, then confirm on my Wi-Fi page."
)

// Sizes.
const (
	// maxText is the longest text the owner channel sends (control.MaxText;
	// agentosd does not link control).
	maxText = 3 * 153
	// smsSegment is one GSM-7 text: a redirected reply's text fits it.
	smsSegment = 160
	// minSummary is the shortest summary worth sending; with less room
	// the text carries only the pointer.
	minSummary = 20
	// fullSentence: sentences are added to a summary until it is at
	// least this long, so "Sure!" is never the whole of it (UX U4).
	fullSentence = 40
	// deliverTimeout bounds one delivery attempt.
	deliverTimeout = 30 * time.Second
)

// deliverRetries are the waits before each further attempt after a
// delivery that did not succeed (UX U2): bounded, then the reply is kept.
var deliverRetries = []time.Duration{10 * time.Second, time.Minute}

// The mail adapter's delivery operation and executor (mail.OpDeliver,
// mail.Tool): agentosd does not link the adapter (ARC-2).
const (
	opDeliver    = "mail.deliver"
	mailExecutor = "mail"
)

// newEvidence keeps undelivered replies at keptPath.
// page says the box's Wi-Fi page is served.
func newEvidence(keptPath string, page bool, logf func(string, ...any)) *evidence {
	return &evidence{kept: &keptReplies{store: change.FileStore{Path: keptPath}, now: time.Now, logf: logf},
		now: time.Now, sleep: time.Sleep, logf: logf, page: page}
}

func (e *evidence) g() evidenceGate {
	if b := e.gate.Load(); b != nil {
		return b.g
	}
	return nil
}

// enqueue hands a reply to the router's worker, in order, so a delivery
// and its retries never hold up the guest's call. Before attach it runs
// inline.
func (e *evidence) enqueue(machine string, private bool, text, summary string) {
	if e.q == nil {
		e.reply(machine, private, text, summary)
		return
	}
	e.q <- evidenceJob{machine: machine, private: private, text: text, summary: summary}
}

func (e *evidence) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-e.q:
			e.reply(j.machine, j.private, j.text, j.summary)
		}
	}
}

// reply sends one agent reply to the owner. private is the machine's
// label (REV-5): a machine that is not public counts as private.
func (e *evidence) reply(machine string, private bool, text, summary string) {
	addr, acct := "", ""
	g := e.g()
	if g != nil && e.mail != nil {
		addr, acct = g.Evidence()
	}
	if !private || addr == "" {
		if len(owner.AgentPrefix)+len(text) <= maxText {
			e.send(machine, text)
			return
		}
		e.kept.keep(text)
		e.send(machine, clip(text, maxText-len(owner.AgentPrefix)-1-len(keptLong))+" "+keptLong)
		return
	}
	tail := "Full reply sent to " + maskAddress(addr) + "."
	err := e.deliver(g, addr, acct, text, grants.DeliverFromAgent, true)
	switch {
	case err == nil:
		e.setFailing(false, false)
	case errors.Is(err, errCapped):
		e.kept.keep(text)
		tail = capNote
	case errors.Is(err, errRefused):
		// Signing in cannot fix a refusal (a dropped alias, a paused
		// grant): setting it up again can (L3 MUST-2 on #148).
		e.logf("reply from %s not emailed: %v", machine, err)
		e.kept.keep(text)
		e.setFailing(true, true)
		tail = refusedNote
	default:
		e.logf("reply from %s not emailed: %v", machine, err)
		e.kept.keep(text)
		e.setFailing(true, false)
		tail = failNote
	}
	e.send(machine, join(summarize(text, summary, smsSegment-len(owner.AgentPrefix)-1-len(tail)), tail))
}

func (e *evidence) send(machine, text string) {
	if err := e.notify(text); err != nil {
		e.logf("reply from %s not sent: %v", machine, err)
	}
}

func (e *evidence) setFailing(on, refused bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refused = refused
	switch {
	case !on:
		e.failing = time.Time{}
	case e.failing.IsZero():
		e.failing = e.now()
	}
}

var (
	errCapped  = errors.New("the day's deliveries are used up")
	errRefused = errors.New("the gate refused the delivery")
)

// deliver submits a delivery and runs it now. With retry, an attempt
// that did not succeed and was not refused is tried again after each of
// deliverRetries. Anything but success is an error.
func (e *evidence) deliver(g evidenceGate, addr, acct, body, from string, retry bool) error {
	var err error
	for i := 0; ; i++ {
		if err = e.deliverOnce(g, addr, acct, body, from); err == nil || errors.Is(err, errCapped) || errors.Is(err, errRefused) ||
			!retry || i == len(deliverRetries) {
			return err
		}
		e.sleep(deliverRetries[i])
	}
}

func (e *evidence) deliverOnce(g evidenceGate, addr, acct, body, from string) error {
	id := "evidence/" + randHex(8)
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	defer cancel()
	st, err := g.Submit(journal.Intent{ID: id, Origin: grants.OriginEvidence, Account: acct, Action: opDeliver,
		Params: map[string]any{grants.ParamBody: body, grants.ParamFrom: from}, Recipients: []string{addr}, Executor: mailExecutor})
	if err == nil && st.State == journal.Pending {
		st, err = g.Authorize(ctx, id)
	}
	if err == nil && st.State == journal.Authorized {
		st, err = g.Dispatch(ctx, id)
	}
	switch {
	case err != nil:
		return err
	case st.State == journal.Denied && st.Permission.Reason == grants.DeliveryCapReason:
		return errCapped
	case st.State == journal.Denied:
		return errRefused
	case st.State != journal.Succeeded:
		return errors.New("delivery " + string(st.State))
	}
	return nil
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func join(summary, tail string) string {
	if summary == "" {
		return tail
	}
	return summary + " " + tail
}

// summarize is the text's one-line summary of at most max bytes: the
// agent's own (guest.Reply.Summary) if it gave one, else the reply's
// opening sentences, enough that a filler opening ("Sure!") is never the
// whole of it (UX U4). It is "" when there is too little room or it looks
// like a code or key (CH-19, security C6): the text then carries only the
// pointer.
func summarize(text, own string, max int) string {
	s := strings.Join(strings.Fields(own), " ")
	if s == "" {
		s = opening(text)
	}
	if max < minSummary {
		return ""
	}
	s = clip(s, max)
	if owner.SecretShaped(s) {
		return ""
	}
	return s
}

// opening is text's first sentences, at least fullSentence bytes when
// the text has that many, on one line.
func opening(text string) string {
	t := strings.Join(strings.Fields(text), " ")
	for i := 0; i+1 < len(t); i++ {
		if strings.ContainsRune(".!?", rune(t[i])) && t[i+1] == ' ' && i+1 >= fullSentence {
			return t[:i+1]
		}
	}
	return t
}

// clip cuts s to max bytes on a rune boundary, marking the cut.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len("...")
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if cut <= 0 {
		return ""
	}
	return strings.TrimSpace(s[:cut]) + "..."
}

// maskAddress shows the first letter of the local part and the domain.
func maskAddress(addr string) string {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok || local == "" {
		return "your email"
	}
	r, _ := utf8.DecodeRuneInString(local)
	return string(r) + "***@" + domain
}

// note is STATUS's line, only while deliveries are failing (UX U5).
func (e *evidence) note() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failing.IsZero() {
		return ""
	}
	since := e.failing.Local().Format("15:04")
	if e.refused {
		return "Emailing replies: refused since " + since + ". Send EMAIL REPLIES ON to set it up again."
	}
	return "Emailing replies: failing since " + since + ". Check that your mail account still signs in."
}

// digestLines are the digest's lines: a new destination confirmed once,
// a clearing by text once, and the failing line while it lasts (UX U5,
// security C3). The digest's sender is not wired yet.
func (e *evidence) digestLines() []string {
	addr := ""
	if g := e.g(); g != nil {
		addr, _ = g.Evidence()
	}
	e.mu.Lock()
	out := e.digest
	e.digest = nil
	if addr != e.shown && addr != "" {
		out = append(out, "Private replies now come by email to "+maskAddress(addr)+".")
	}
	e.shown = addr
	e.mu.Unlock()
	if l := e.note(); l != "" {
		out = append(out, l)
	}
	return out
}

// settings takes EVIDENCE ON (the account's main address), EVIDENCE TO
// <address> and EVIDENCE OFF, or the same with EMAIL REPLIES, (control.Handler.Settings), only in an
// unlocked session; a locked one gets the unlock prompt. Turning it on is
// asked by the gate with a code and the local page (CH-10); turning it off
// needs neither, and the old destination is told (security C3).
func (e *evidence) settings(ctx context.Context, msg string, unlocked bool) (string, bool) {
	f := strings.Fields(msg)
	alias := len(f) > 2 && strings.EqualFold(f[0], "EMAIL") && strings.EqualFold(f[1], "REPLIES")
	if alias {
		f = f[1:] // EMAIL REPLIES is EVIDENCE's other name (UX N2)
	} else if len(f) < 2 || !strings.EqualFold(f[0], "EVIDENCE") {
		return "", false
	}
	on, addr := false, ""
	switch {
	case len(f) == 2 && strings.EqualFold(f[1], "OFF"):
	case len(f) == 2 && strings.EqualFold(f[1], "ON"):
		on = true
	case len(f) == 3 && strings.EqualFold(f[1], "TO") && strings.Contains(f[2], "@"):
		on, addr = true, strings.ToLower(strings.TrimRight(f[2], "."))
	default:
		return "", false
	}
	if !unlocked {
		return "", false
	}
	if e.mail == nil {
		return evidenceNotYet, true
	}
	g := e.g()
	if g == nil {
		return evidenceStarting, true
	}
	if !on {
		return e.off(ctx, g), true
	}
	if !e.page {
		// Known here, not matched in the gate's reason: the journal
		// redacts reasons, so a matcher on them never fired (P2-2w d).
		return evidenceNoPage, true
	}
	main, mainAcct := e.mail.Main()
	acct := mainAcct
	if addr == "" {
		addr = main
	} else {
		var ok bool
		if acct, ok = e.mail.Owns(addr); !ok && alias {
			// "Email replies to bob@corp.example" is a task for the
			// agent, not this setting (L3 SHOULD 4 on #148).
			return "", false
		} else if !ok {
			return "Not changed: I can email replies only to your mail account's own address, " + maskAddress(main) + ". Send EMAIL REPLIES ON to use it.", true
		}
	}
	id := "owner/evidence/" + randHex(6)
	st, err := g.Submit(grants.EvidenceIntent(id, grants.OriginOwner, addr, acct))
	if err == nil && st.State == journal.Pending {
		st, err = g.Authorize(ctx, id)
	}
	switch {
	case err != nil:
		e.logf("evidence setting: %v", err)
		return evidenceFailed, true
	case st.State == journal.Denied:
		// Gate reasons are not texted verbatim (L3 SHOULD 3 on #148).
		e.logf("evidence setting refused: %s", st.Permission.Reason)
		return evidenceFailed, true
	}
	return evidenceEffect, true
}

// off clears the destination, telling it first, since afterwards nothing
// can be delivered there.
func (e *evidence) off(ctx context.Context, g evidenceGate) string {
	addr, acct := g.Evidence()
	if addr == "" {
		return evidenceNone
	}
	at := e.now().Local().Format("15:04 on Jan 2")
	if err := e.deliver(g, addr, acct, strings.Replace(offNotice, "%s", at, 1), grants.DeliverFromBox, false); err != nil {
		e.logf("evidence off notice not emailed: %v", err)
	}
	id := "owner/evidence/" + randHex(6)
	st, err := g.Submit(grants.EvidenceIntent(id, grants.OriginOwner, "", ""))
	if err == nil && st.State == journal.Pending {
		st, err = g.Authorize(ctx, id)
	}
	if err == nil && st.State == journal.Authorized {
		st, err = g.Dispatch(ctx, id)
	}
	if err != nil || st.State != journal.Succeeded {
		e.logf("evidence off: %v (%s)", err, st.State)
		return evidenceFailed
	}
	e.mu.Lock()
	e.digest = append(e.digest, "Emailing private replies was turned off by text at "+at+".")
	e.shown = ""
	e.mu.Unlock()
	return evidenceOff
}

// wire adds the setting ahead of the loops' (cfg.Settings), STATUS's line,
// and the gate's destination check. Call attach once the daemon runs.
func (e *evidence) wire(cfg *daemon.Config) {
	prev := cfg.Settings
	cfg.Settings = func(ctx context.Context, msg string, unlocked bool) (string, bool) {
		if r, ok := e.settings(ctx, msg, unlocked); ok {
			return r, true
		}
		if prev != nil {
			return prev(ctx, msg, unlocked)
		}
		return "", false
	}
	cfg.Notes = append(cfg.Notes, e.note)
	if e.mail != nil {
		cfg.Grants.Destination = e.mail.Owns
	}
}

// attach starts routing through the running daemon's gate and owner
// channel.
func (e *evidence) attach(ctx context.Context, d *daemon.Daemon) {
	e.notify = func(text string) error {
		ch := d.Owner()
		if ch == nil {
			return errors.New("no owner channel")
		}
		return ch.Notify(text)
	}
	e.gate.Store(&evidenceGateBox{d.Gate()})
	e.shown, _ = d.Gate().Evidence()
	e.q = make(chan evidenceJob, 16)
	go e.run(ctx)
}

// Kept replies: a reply that could not be emailed, or was too long for a
// text, waits here for the box's local page (BOARD CH-20p): at most
// maxKept, none past keepReplies, in a 0600 file in the box's state
// directory. A deletion's reach (CAP-3) forgets them all (forgetFan).
const (
	maxKept     = 20
	keepReplies = 7 * 24 * time.Hour
)

type keptReply struct {
	Text string    `json:"text"`
	At   time.Time `json:"at"`
}

type keptReplies struct {
	store change.Store
	now   func() time.Time
	logf  func(string, ...any)

	mu sync.Mutex
}

func (k *keptReplies) keep(text string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	l := append(k.loadLocked(), keptReply{Text: text, At: k.now()})
	if len(l) > maxKept {
		l = l[len(l)-maxKept:]
	}
	k.saveLocked(l)
}

func (k *keptReplies) saveLocked(l []keptReply) {
	b, _ := json.Marshal(l)
	if err := k.store.Save(b); err != nil && k.logf != nil {
		k.logf("kept replies not saved: %v", err)
	}
}

// forget drops every kept reply.
func (k *keptReplies) forget() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.store.Save([]byte("[]"))
}

// list returns the kept replies, oldest first.
func (k *keptReplies) list() []keptReply {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.loadLocked()
}

func (k *keptReplies) loadLocked() []keptReply {
	raw, err := k.store.Load()
	var l, out []keptReply
	if err != nil || json.Unmarshal(raw, &l) != nil {
		return nil
	}
	for _, r := range l {
		if k.now().Sub(r.At) < keepReplies {
			out = append(out, r)
		}
	}
	return out
}

// forgetFan is what a deletion reaches beyond the journal (recalltool
// Cases): the learning plane's cases, if it runs, and every kept reply,
// since a kept reply may quote the deleted record (security C6 on #148).
type forgetFan struct {
	cases recallCases
	kept  *keptReplies
}

type recallCases interface {
	ForgetTasks(ids ...string) (int, error)
}

func (f forgetFan) ForgetTasks(ids ...string) (int, error) {
	kerr := f.kept.forget()
	if f.cases == nil {
		return 0, kerr
	}
	n, err := f.cases.ForgetTasks(ids...)
	return n, errors.Join(err, kerr)
}
