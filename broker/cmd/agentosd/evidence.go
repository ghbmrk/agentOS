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
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
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

// mailOn reports whether a mail account is connected.
func (e *evidence) mailOn() bool {
	if e.mail == nil {
		return false
	}
	addr, _ := e.mail.Main()
	return addr != ""
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
	// mail is the mail account (lateMail): with none connected (nil, or
	// no main address) no destination can be set and every reply goes by
	// text.
	mail  mailbox
	kept  *keptReplies
	now   func() time.Time
	sleep func(time.Duration)
	logf  func(string, ...any)
	// page says agentosd serves the box's Wi-Fi page (-localui-uid), where
	// setting a destination is confirmed (CH-20); the gate's LocalUI.
	page bool

	// wake tells the worker the guest plane's outbox has new replies;
	// src is that outbox, once the plane is open (DEL-1b).
	wake chan struct{}
	src  atomic.Pointer[replySourceBox]

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

// replySource is the guest plane's reply outbox (guest.Plane).
type replySource interface {
	PendingReplies() []guest.PendingReply
	ReplyDone(machine, id string) error
}

type replySourceBox struct{ s replySource }

// Fixed wording, in the box's first-person voice (UX U7).
const (
	keptLong         = "Cut here. Ask me to send it in shorter parts."
	capNote          = "I've emailed the most replies I send in a day, so I kept this one here."
	failNote         = "I couldn't email the full reply, so I kept it here. Check that your mail account still signs in."
	refusedNote      = "I couldn't email the full reply, so I kept it here. Send EMAIL REPLIES ON to set emailing up again."
	evidenceEffect   = "With this on, I email your private replies and texts carry a one-line summary. Send EMAIL REPLIES OFF to stop. A request for your code follows; then confirm on my Wi-Fi page."
	evidenceNotYet   = "Emailing private replies is not in this build yet."
	evidenceOff      = "Private replies come by text again."
	evidenceNone     = "Private replies already come by text."
	evidenceStarting = "I'm still starting. Try again in a minute."
	evidenceFailed   = "I couldn't save that setting. Try again later."
	// evidenceFenced answers while a restart fence holds the broker
	// account (OP-4): trying again works only once STATUS no longer lists
	// the earlier change (UX U3 on #1382). loops' fencedReply, word for word.
	evidenceFenced = "I'm holding settings until I can confirm a change from before the restart. Send this again once STATUS no longer lists it."
	// evidenceHeld answers a change held behind the same change whose
	// outcome is not known yet (journal.HeldError, OP-2): no restart, and
	// STATUS does not list it. loops' heldReply, word for word.
	evidenceHeld   = "I'm holding this setting: the same change is already under way and not confirmed yet. Try again later."
	evidenceNoPage = "Not changed: turning this on needs my Wi-Fi page, which I'm not serving. Private replies still come by text."
	// evidenceNoPageSet is the same refusal while replies already go to
	// an address (%s, masked).
	evidenceNoPageSet = "Not changed: this needs my Wi-Fi page, which I'm not serving. Private replies still go to %s."
	// offNotice goes to the old destination when it is cleared by text
	// (security C3 on #148, its wording).
	offNotice = "Emailing private replies was turned off by text at %s. If that wasn't you, send EMAIL REPLIES ON, then confirm on my Wi-Fi page."
)

// Sizes.
const (
	// smsSegment is one GSM-7 text: a redirected reply's text fits it.
	smsSegment = 160
	// smsSegmentUCS2 is one UCS-2 text, in UTF-16 units.
	smsSegmentUCS2 = 70
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

// newEvidence keeps undelivered replies at keptPath.
// page says the box's Wi-Fi page is served.
func newEvidence(keptPath string, page bool, logf func(string, ...any)) *evidence {
	return &evidence{kept: &keptReplies{store: change.FileStore{Path: keptPath}, now: time.Now, logf: logf},
		now: time.Now, sleep: time.Sleep, logf: logf, page: page, wake: make(chan struct{}, 1)}
}

func (e *evidence) g() evidenceGate {
	if b := e.gate.Load(); b != nil {
		return b.g
	}
	return nil
}

// serve takes replies from the guest plane's outbox, where each waits on
// disk from the guest's 204 until it has gone out (DEL-1b): replies a
// crash left there go first.
func (e *evidence) serve(src replySource) {
	if c, ok := src.(replyChecker); ok {
		c.CheckReplies(refuseGuestReply)
	}
	e.kept.attach(src)
	e.src.Store(&replySourceBox{src})
	e.poke()
}

// replyChecker is an outbox that can refuse a reply before storing it
// (guest.Plane.CheckReplies).
type replyChecker interface {
	CheckReplies(check func(text string) string)
}

// guestReactionRefused is what a guest hears when its reply is an agent
// reaction: fixed broker words, never the error's own text.
const guestReactionRefused = "agent reactions are refused; reply in text"

// refuseGuestReply refuses, at the guest's POST, a reply Converse would
// refuse after the 204, when only the log would hear it (CH-11, #2196).
func refuseGuestReply(text string) string {
	if owner.RefuseAgentText(control.StripControls(text)) != nil {
		return guestReactionRefused
	}
	return ""
}

// poke tells the worker the outbox has a new reply (guest.Config.Replies).
// It never blocks the guest's call.
func (e *evidence) poke() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// run routes the outbox's replies one at a time, in the order the guests
// sent them. A reply leaves the outbox once reply returns, whatever its
// outcome (it was texted, emailed or kept); a crash between the two may
// send it again (provisional until DEL-2 records outcomes).
func (e *evidence) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.wake:
		}
		b := e.src.Load()
		if b == nil {
			continue
		}
		// The outbox is read again before each reply, so none a deletion
		// dropped meanwhile goes out (DEL-1-f1c).
		var last guest.PendingReply
		for ctx.Err() == nil {
			gen, l := e.kept.pending(b.s)
			if len(l) == 0 {
				break
			}
			p := l[0]
			if p.Machine == last.Machine && p.ID == last.ID {
				e.logf("evidence: reply %s stays in the outbox", p.ID)
				break
			}
			last = p
			e.reply(p.Machine, p.Private, p.Text, p.Summary)
			e.kept.settle(gen)
			if err := b.s.ReplyDone(p.Machine, p.ID); err != nil {
				e.logf("evidence: reply %s left in the outbox store: %v", p.ID, err)
			}
		}
	}
}

// reply sends one agent reply to the owner. private is the machine's
// label (REV-5): a machine that is not public counts as private.
func (e *evidence) reply(machine string, private bool, text, summary string) {
	addr, acct := "", ""
	g := e.g()
	if g != nil && e.mailOn() {
		addr, acct = g.Evidence()
	}
	if !private || addr == "" {
		e.sendSplit(machine, text)
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
	e.send(machine, join(summarize(text, summary, tail), tail))
}

// sendSplit texts a reply as up to maxReplyTexts consecutive texts
// (CH-12, D-127); one longer than that is kept whole and the third text
// ends with keptLong. The reply is stripped of control and bidi
// characters first (control.StripControls), then CH-19's check runs on
// the whole of it as written and stripped (owner.AgentSecret): a
// secret-shaped reply goes as one text, as written, which the
// owner channel replaces with its local-UI pointer, so no code is split
// past the check. A text that does not go stops the rest, so none arrives
// out of order, and the reply is kept. What is kept for the local UI is
// the stripped reply too.
func (e *evidence) sendSplit(machine, text string) {
	raw := text
	text = control.StripControls(text)
	if owner.AgentSecret(raw) {
		if n, gsm7 := control.Units(text); n > textRoom(gsm7) {
			e.kept.keep(text)
		}
		e.send(machine, raw)
		return
	}
	parts, cut := splitReply(text)
	if cut {
		e.kept.keep(text)
	}
	for i, p := range parts {
		if err := e.notify(p); err != nil {
			e.logf("reply from %s not sent (text %d of %d): %v", machine, i+1, len(parts), err)
			if len(parts) > 1 && !cut {
				e.kept.keep(text)
			}
			return
		}
	}
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
	st, err := g.Submit(journal.Intent{ID: id, Origin: grants.OriginEvidence, Account: acct, Action: mail.OpDeliver,
		Params: map[string]any{grants.ParamBody: body, grants.ParamFrom: from}, Recipients: []string{addr}, Executor: mail.Tool})
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

// summarize is the text's one-line summary: the agent's own
// (guest.Reply.Summary) if it gave one, else the reply's opening
// sentences, enough that a filler opening ("Sure!") is never the whole of
// it (UX U4), both stripped (control.StripControls). Its room is what one
// text leaves after AgentPrefix, a space and tail, in the encoding the
// whole text needs: one GSM-7 text when the summary and tail both fit
// GSM-7, else one UCS-2 text. It is cut in its own encoding, never inside
// a character or a joined emoji (CH-12). It is "" when there is too
// little room or its source, as written or stripped, looks like a code or
// key (owner.AgentSecret, CH-19, security C6): the text then carries only
// the pointer.
func summarize(text, own, tail string) string {
	src := own
	s := strings.Join(strings.Fields(control.StripControls(own)), " ")
	if s == "" {
		src, s = text, opening(control.StripControls(text))
	}
	n, gsm7 := control.Units(owner.AgentPrefix + " " + tail)
	max := smsSegment - n
	if _, g := control.Units(s); !g || !gsm7 {
		// A GSM-7 part counted in septets is never fewer UTF-16 units.
		max = smsSegmentUCS2 - n
	}
	if max < minSummary {
		return ""
	}
	s = clip(s, max)
	if owner.SecretShaped(s) || owner.AgentSecret(src) {
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

// maxReplyTexts is how many texts one agent reply may take (CH-12).
const maxReplyTexts = 3

// textRoom is what one text leaves for agent text after AgentPrefix, in
// units of its encoding (control.Units): 3 x 153 septets for GSM-7, 3 x 67
// UTF-16 units for UCS-2 (CH-12).
func textRoom(gsm7 bool) int { return control.Room(gsm7) - len(owner.AgentPrefix) }

// splitReply cuts text into at most maxReplyTexts parts, each within one
// text in the encoding the rest of the reply needs from where it starts
// (control.Units, textRoom), so a reply with an emoji gets UCS-2 room. cut
// says the reply did not fit: the last part then ends with keptLong. Each
// cut is at the strongest boundary in the second half of the part (a
// paragraph, then a line, then a sentence end, then a word), so a part is
// never a stub; failing all of these, the last word boundary, else a rune
// boundary outside any joined emoji (control.Prefix).
func splitReply(text string) (parts []string, cut bool) {
	rest := strings.TrimSpace(text)
	for len(parts) < maxReplyTexts-1 && !fits(rest) {
		i := cutAt(rest, control.Prefix(rest, roomOf(rest)))
		parts = append(parts, strings.TrimSpace(rest[:i]))
		rest = strings.TrimSpace(rest[i:])
	}
	if fits(rest) {
		return append(parts, rest), false
	}
	i := cutAt(rest, control.Prefix(rest, roomOf(rest)-1-len(keptLong)))
	return append(parts, strings.TrimSpace(rest[:i])+" "+keptLong), true
}

// fits says s fits one text after AgentPrefix.
func fits(s string) bool {
	n, gsm7 := control.Units(s)
	return n <= textRoom(gsm7)
}

// roomOf is textRoom in the encoding s needs.
func roomOf(s string) int {
	_, gsm7 := control.Units(s)
	return textRoom(gsm7)
}

// cutAt is where to end a part of s (longer than max) at most max bytes
// long, max already within one text and at a Joinable point: s[:i] is
// the part.
func cutAt(s string, max int) int {
	paragraph := func(p int) bool { return strings.HasPrefix(s[p:], "\n\n") }
	line := func(p int) bool { return s[p] == '\n' }
	word := func(p int) bool { return s[p] == ' ' || s[p] == '\n' || s[p] == '\t' }
	sentence := func(p int) bool {
		t := strings.TrimRight(s[:p], `"')`)
		return word(p) && t != "" && strings.ContainsRune(".!?", rune(t[len(t)-1]))
	}
	for _, at := range []func(int) bool{paragraph, line, sentence, word} {
		for p := max; p > max/2; p-- {
			if at(p) {
				return p
			}
		}
	}
	for p := max / 2; p > 0; p-- {
		if word(p) {
			return p
		}
	}
	return max
}

// clip cuts s to max units in the encoding it needs (control.Units),
// where control.Prefix allows, marking the cut.
func clip(s string, max int) string {
	if n, _ := control.Units(s); n <= max {
		return s
	}
	cut := control.Prefix(s, max-len("..."))
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
	if !e.mailOn() {
		return evidenceNotYet, true
	}
	g := e.g()
	if g == nil {
		return evidenceStarting, true
	}
	if !on {
		return e.off(ctx, g), true
	}
	main, acct := e.mail.Main()
	owned := true
	if addr == "" {
		addr = main
	} else if acct, owned = e.mail.Owns(addr); !owned && alias {
		// "Email replies to bob@corp.example" is a task for the agent,
		// not this setting (L3 SHOULD 4 on #148).
		return "", false
	}
	if !e.page {
		// Known here, not matched in the gate's reason: the journal
		// redacts reasons, so a matcher on them never fired (P2-2w d).
		// After the agent's case (UX B1 on #322), before the address
		// step, which would then fail here (L3 F2 on #322). Set earlier,
		// replies still go by email: Attach replays it without the page
		// (L3 F1 on #322).
		if cur, _ := g.Evidence(); cur != "" {
			return strings.Replace(evidenceNoPageSet, "%s", maskAddress(cur), 1), true
		}
		return evidenceNoPage, true
	}
	if !owned {
		return "Not changed: I can email replies only to your mail account's own address, " + maskAddress(main) + ". Send EMAIL REPLIES ON to use it.", true
	}
	id := "owner/evidence/" + randHex(6)
	st, err := g.Submit(grants.EvidenceIntent(id, grants.OriginOwner, addr, acct))
	if err == nil && st.State == journal.Pending {
		st, err = g.Authorize(ctx, id)
	}
	switch {
	case err != nil:
		e.logf("evidence setting: %v", err)
		return settingFailed(err), true
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
		return settingFailed(err)
	}
	e.mu.Lock()
	e.digest = append(e.digest, "Emailing private replies was turned off by text at "+at+".")
	e.shown = ""
	e.mu.Unlock()
	return evidenceOff
}

// settingFailed words a destination change that did not run. A fence or a
// same-effect hold says what to wait for; a HeldError also matches
// ErrUnreconciled, so it is checked first.
func settingFailed(err error) string {
	var held *journal.HeldError
	switch {
	case errors.As(err, &held):
		return evidenceHeld
	case errors.Is(err, journal.ErrUnreconciled):
		return evidenceFenced
	}
	return evidenceFailed
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
	e.wireOwner(d.Owner)
	e.gate.Store(&evidenceGateBox{d.Gate()})
	e.shown, _ = d.Gate().Evidence()
	go e.run(ctx)
	e.poke()
}

// wireOwner routes outbox replies to the owner channel as conversation.
// attach calls it; it is the only place e.notify is set outside tests.
// A deletion's reach also clears the channel's recent texts (#2360).
func (e *evidence) wireOwner(channel func() *owner.Channel) {
	e.notify = converse(channel)
	if e.kept != nil {
		e.kept.attachOwner(channel)
	}
}

// converse sends an agent reply to the owner as conversation (CH-15):
// every reply in the outbox answers one owner message (guest
// POST /owner/reply), so it is never held or paced.
func converse(channel func() *owner.Channel) func(string) error {
	return func(text string) error {
		ch := channel()
		if ch == nil {
			return errors.New("no owner channel")
		}
		return ch.Converse(text)
	}
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

	// fmu orders a deletion (forget) against the worker's reads of the
	// outbox: src is the outbox a deletion also drops (DEL-1-f1), and gen
	// counts deletions, so a reply routed across one is not kept.
	fmu sync.Mutex
	src replySource
	gen uint64
	// owner is the owner channel, whose recent texts a reaction quotes
	// back: a deletion clears them too (CAP-3, #2360).
	owner func() *owner.Channel
}

// attachOwner makes the owner channel's recent texts part of what forget
// drops.
func (k *keptReplies) attachOwner(channel func() *owner.Channel) {
	k.fmu.Lock()
	defer k.fmu.Unlock()
	k.owner = channel
}

// forgetOwnerLocked clears the owner channel's recent texts and voids its
// held or pending reaction events. k.fmu is held.
func (k *keptReplies) forgetOwnerLocked() {
	if k.owner == nil {
		return
	}
	if ch := k.owner(); ch != nil {
		ch.ForgetRecent()
	}
}

// attach makes src, the guest plane's outbox, part of what forget drops.
func (k *keptReplies) attach(src replySource) {
	k.fmu.Lock()
	defer k.fmu.Unlock()
	k.src = src
}

// pending reads the outbox for the worker, with the deletion count it
// read it under.
func (k *keptReplies) pending(src replySource) (uint64, []guest.PendingReply) {
	k.fmu.Lock()
	defer k.fmu.Unlock()
	return k.gen, src.PendingReplies()
}

// settle runs after a reply read under gen was routed. A reply in flight
// when a deletion ran cannot be recalled, but any copy it kept after the
// deletion dropped the kept replies is dropped now (DEL-1-f1c), and so is
// its text in the owner channel's recent texts (#2360).
func (k *keptReplies) settle(gen uint64) {
	k.fmu.Lock()
	defer k.fmu.Unlock()
	if k.gen == gen {
		return
	}
	k.forgetOwnerLocked()
	if err := k.drop(); err != nil && k.logf != nil {
		k.logf("kept replies not dropped after a deletion: %v", err)
	}
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

// forget drops every kept reply and every reply waiting in the guest
// plane's outbox, once it is attached: no waiting reply names the task it
// is about, so a deletion drops them all, as it does the kept ones
// (DEL-1-f1b). For the same reason it clears the owner channel's recent
// texts, which a reaction's quote would bring back (#2360).
func (k *keptReplies) forget() error {
	k.fmu.Lock()
	defer k.fmu.Unlock()
	k.gen++
	k.forgetOwnerLocked()
	err := k.drop()
	if k.src == nil {
		return err
	}
	o, ok := k.src.(interface{ ForgetReplies() error })
	if !ok {
		return errors.Join(err, errors.New("the reply outbox cannot drop replies"))
	}
	return errors.Join(err, o.ForgetReplies())
}

func (k *keptReplies) drop() error {
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
// Cases): the learning plane's cases, if it runs, every kept reply and
// reply waiting in the guest outbox, and the owner channel's recent texts,
// since any may quote the deleted record (security C6 on #148, DEL-1-f1,
// #2360).
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
