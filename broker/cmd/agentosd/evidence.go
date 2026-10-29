package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/owner"
)

// Agent replies (CH-20). An agent reply is texted to the owner; one too
// long for maxReplyTexts texts, or one whose text did not go, is kept on
// the box for its local page (potency C1). CH-20's owner destination is
// not wired: the mail clerk runs in its own process (clerk/run) and has no
// share route yet, so EVIDENCE and EMAIL REPLIES say it is not in this
// build, and private replies go as public ones do (DEP-3).

type evidence struct {
	// notify texts the owner an agent reply (owner.Channel.Converse, which
	// adds the prefix and runs CH-19's filter).
	notify func(string) error
	// inform texts the owner one of the broker's own notices
	// (owner.Channel.Inform).
	inform func(string) error
	kept   *keptReplies
	logf   func(string, ...any)
	// page says the owner page is served, so the owner channel may point
	// to what it keeps there (owner.Channel.SetKeeper, CH-12).
	page bool

	// wake tells the worker the guest plane's outbox has new replies;
	// src is that outbox, once the plane is open (DEL-1b).
	wake chan struct{}
	src  atomic.Pointer[replySourceBox]
}

// replySource is the guest plane's reply outbox (guest.Plane).
type replySource interface {
	PendingReplies() []guest.PendingReply
	ReplyDone(machine, id string) error
}

type replySourceBox struct{ s replySource }

// Fixed wording, in the box's first-person voice (UX U7). The
// could-not-be-kept texts name no page (CH-19, CH-12); keptLongNotKept is
// no longer than keptLong, so it fits where keptLong would.
const (
	keptLong        = "Cut here. Ask me to send it in shorter parts."
	keptLongNotKept = "Cut here, and I could not keep the rest."
	unsentNotKept   = "A reply did not go, and I could not keep it."
	evidenceNotYet  = "Emailing private replies is not in this build yet."
)

// newEvidence keeps undelivered and withheld replies at keptPath for
// keepFor (CH-19).
func newEvidence(keptPath string, keepFor time.Duration, logf func(string, ...any)) *evidence {
	return &evidence{kept: &keptReplies{store: change.FileStore{Path: keptPath}, now: time.Now, logf: logf, keepFor: keepFor},
		logf: logf, wake: make(chan struct{}, 1)}
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
// outcome (it was texted or kept); a crash between the two may
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
			e.sendSplit(p.Machine, p.Text)
			e.kept.settle(gen)
			if err := b.s.ReplyDone(p.Machine, p.ID); err != nil {
				e.logf("evidence: reply %s left in the outbox store: %v", p.ID, err)
			}
		}
	}
}

// sendSplit texts a reply as up to maxReplyTexts consecutive texts
// (CH-12, D-127); one longer than that is kept whole and the third text
// ends with keptLong, or with keptLongNotKept if it could not be kept.
// The reply is stripped of control and bidi characters first
// (control.StripControls), then CH-19's check runs on the whole of it as
// written, stripped and with its controls removed (owner.AgentSecret): a
// secret-shaped reply goes as one text, as written, which the owner
// channel keeps whole and replaces with its pointer, so no code is split
// past the check. A text that does not go stops the rest, so none arrives
// out of order, and the reply is kept; if it cannot be, the owner is told.
// What is kept for the local UI is the stripped reply too.
func (e *evidence) sendSplit(machine, text string) {
	raw := text
	text = control.StripControls(text)
	if owner.AgentSecret(raw) {
		e.send(machine, raw)
		return
	}
	parts, cut := splitReply(text)
	if cut && e.kept.keep(localapi.HeldLong, text) != nil {
		parts, _ = splitReplyEnd(text, keptLongNotKept)
	}
	for i, p := range parts {
		if err := e.notify(p); err != nil {
			e.logf("reply from %s not sent (text %d of %d): %v", machine, i+1, len(parts), err)
			if len(parts) > 1 && !cut && e.kept.keep(localapi.HeldUnsent, text) != nil {
				e.tellNotKept()
			}
			return
		}
	}
}

// tellNotKept tells the owner an unsent reply could not be kept, in the
// broker's own words.
func (e *evidence) tellNotKept() {
	if e.inform == nil {
		return
	}
	if err := e.inform(unsentNotKept); err != nil {
		e.logf("reply not kept; owner not told: %v", err)
	}
}

func (e *evidence) send(machine, text string) {
	if err := e.notify(text); err != nil {
		e.logf("reply from %s not sent: %v", machine, err)
	}
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
	return splitReplyEnd(text, keptLong)
}

// splitReplyEnd is splitReply with end in place of keptLong.
func splitReplyEnd(text, end string) (parts []string, cut bool) {
	rest := strings.TrimSpace(text)
	for len(parts) < maxReplyTexts-1 && !fits(rest) {
		i := cutAt(rest, control.Prefix(rest, roomOf(rest)))
		parts = append(parts, strings.TrimSpace(rest[:i]))
		rest = strings.TrimSpace(rest[i:])
	}
	if fits(rest) {
		return append(parts, rest), false
	}
	i := cutAt(rest, control.Prefix(rest, roomOf(rest)-1-len(end)))
	return append(parts, strings.TrimSpace(rest[:i])+" "+end), true
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

// settings answers EVIDENCE ON, EVIDENCE TO <address> and EVIDENCE OFF,
// or the same with EMAIL REPLIES (control.Handler.Settings), in an
// unlocked session, with evidenceNotYet: no destination can be set (CH-20
// is not wired), and the owner hears so rather than the agent getting the
// command as task chat. A locked session gets the unlock prompt.
func settings(msg string, unlocked bool) (string, bool) {
	f := strings.Fields(msg)
	if len(f) > 2 && strings.EqualFold(f[0], "EMAIL") && strings.EqualFold(f[1], "REPLIES") {
		f = f[1:] // EMAIL REPLIES is EVIDENCE's other name (UX N2)
	} else if len(f) < 2 || !strings.EqualFold(f[0], "EVIDENCE") {
		return "", false
	}
	switch {
	case len(f) == 2 && (strings.EqualFold(f[1], "OFF") || strings.EqualFold(f[1], "ON")):
	case len(f) == 3 && strings.EqualFold(f[1], "TO") && strings.Contains(f[2], "@"):
	default:
		return "", false
	}
	if !unlocked {
		return "", false
	}
	return evidenceNotYet, true
}

// wire adds the setting ahead of the loops' (cfg.Settings). Call attach
// once the daemon runs.
func (e *evidence) wire(cfg *daemon.Config) {
	prev := cfg.Settings
	cfg.Settings = func(ctx context.Context, msg string, unlocked bool) (string, bool) {
		if r, ok := settings(msg, unlocked); ok {
			return r, true
		}
		if prev != nil {
			return prev(ctx, msg, unlocked)
		}
		return "", false
	}
}

// attach starts routing through the running daemon's owner channel, and,
// with the owner page served, keeps what the channel withholds for it.
func (e *evidence) attach(ctx context.Context, d *daemon.Daemon) {
	e.wireOwner(d.Owner)
	if ch := d.Owner(); ch != nil && e.page {
		ch.SetKeeper(e.kept)
	}
	go e.kept.sweepEvery(ctx, time.Hour)
	go e.run(ctx)
	e.poke()
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// wireOwner routes outbox replies to the owner channel as conversation.
// attach calls it; it is the only place e.notify is set outside tests.
// A deletion's reach also clears the channel's recent texts (#2360).
func (e *evidence) wireOwner(channel func() *owner.Channel) {
	e.notify = converse(channel)
	e.inform = func(text string) error {
		ch := channel()
		if ch == nil {
			return errors.New("no owner channel")
		}
		return ch.Inform(text)
	}
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

// Kept replies (CH-19, CH-20p): a reply that could not be sent or was
// too long for maxReplyTexts texts, and every text the owner channel
// withheld (owner.Keeper), wait here for the box's local page, in a 0600
// file in the box's state directory, saved atomically (change.FileStore).
// Each expires only by time, keepFor after it was kept; its text is then
// dropped and a stub stays for stubFor more, so the page can say it has
// expired. Nothing is evicted by count: a new item that would take the
// file past maxKeptBytes is refused, and its sender says it could not be
// kept. A deletion's reach (CAP-3) forgets them all, stubs too (forget).
const (
	defaultKeepFor = 30 * 24 * time.Hour
	stubFor        = 30 * 24 * time.Hour
	maxKeptBytes   = 1 << 20
)

var errKeptFull = errors.New("kept replies are full")

type keptReply struct {
	ID   string    `json:"id,omitempty"`
	Kind string    `json:"kind,omitempty"`
	Text string    `json:"text,omitempty"`
	At   time.Time `json:"at"`
	// Expired marks a stub: its text is gone.
	Expired bool `json:"expired,omitempty"`
}

type keptReplies struct {
	store change.Store
	now   func() time.Time
	logf  func(string, ...any)
	// keepFor is how long an item is kept (-kept-days); zero is
	// defaultKeepFor.
	keepFor time.Duration

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
// held or pending reaction events. It returns how many held agent texts
// the channel dropped (CAP3-F1). k.fmu is held.
func (k *keptReplies) forgetOwnerLocked() int {
	if k.owner == nil {
		return 0
	}
	if ch := k.owner(); ch != nil {
		return ch.ForgetRecent()
	}
	return 0
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
// its text in the owner channel's recent texts (#2360). The owner is
// told how many held agent texts that dropped (CAP3-F1), in the broker's
// own words and as urgent as the rollback texts, after fmu is released.
func (k *keptReplies) settle(gen uint64) {
	k.fmu.Lock()
	if k.gen == gen {
		k.fmu.Unlock()
		return
	}
	held := k.forgetOwnerLocked()
	var ch *owner.Channel
	if k.owner != nil {
		ch = k.owner()
	}
	if err := k.drop(); err != nil && k.logf != nil {
		k.logf("kept replies not dropped after a deletion: %v", err)
	}
	k.fmu.Unlock()
	if err := tellHeldDropped(ch, held); err != nil && k.logf != nil {
		k.logf("held agent texts dropped; owner not told: %v", err)
	}
}

// tellHeldDropped is the one sender of the count of held agent texts a
// deletion dropped, told alone (CAP3-F1): broker text, never agent text,
// so no later forget drops it, and as urgent as the rollback texts. None
// tells nothing.
func tellHeldDropped(ch *owner.Channel, n int) error {
	if n <= 0 {
		return nil
	}
	if ch == nil {
		return errors.New("no owner channel")
	}
	if n == 1 {
		return ch.Post(owner.ClassApproval, "A deletion dropped 1 held agent text.")
	}
	return ch.Post(owner.ClassApproval, fmt.Sprintf("A deletion dropped %d held agent texts.", n))
}

// Keep keeps a text the owner channel withheld (owner.Keeper).
func (k *keptReplies) Keep(kind, text string) error {
	return k.keep(kind, text)
}

// keep adds text of kind, or refuses it, logging why without the text.
func (k *keptReplies) keep(kind, text string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	l, err := k.loadLocked()
	if err == nil {
		l = append(l, keptReply{ID: randHex(8), Kind: kind, Text: text, At: k.now()})
		err = k.saveLocked(l)
	}
	if err != nil && k.logf != nil {
		k.logf("a %s reply was not kept: %v", kind, err)
	}
	return err
}

// saveLocked saves l, or refuses it past maxKeptBytes.
func (k *keptReplies) saveLocked(l []keptReply) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if len(b) > maxKeptBytes {
		return errKeptFull
	}
	return k.store.Save(b)
}

// sweep saves the kept items as they now read, so an expired item's text
// leaves the disk and an old stub goes.
func (k *keptReplies) sweep() {
	k.mu.Lock()
	defer k.mu.Unlock()
	raw, err := k.store.Load()
	if err != nil || len(raw) == 0 {
		return
	}
	l, err := k.loadLocked()
	if err == nil {
		var b []byte
		if b, err = json.Marshal(l); err == nil && string(b) != string(raw) {
			err = k.store.Save(b)
		}
	}
	if err != nil && k.logf != nil {
		k.logf("kept replies not swept: %v", err)
	}
}

// sweepEvery sweeps every d until ctx is done.
func (k *keptReplies) sweepEvery(ctx context.Context, d time.Duration) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		k.sweep()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// forget drops every kept reply and every reply waiting in the guest
// plane's outbox, once it is attached: no waiting reply names the task it
// is about, so a deletion drops them all, as it does the kept ones
// (DEL-1-f1b). For the same reason it clears the owner channel's recent
// texts, which a reaction's quote would bring back (#2360). It returns
// how many held agent texts the owner channel dropped (CAP3-F1). Nothing
// calls it in this version: FORGET and recall's deletions are deleted
// (#2781); it stays as the hook the kernel's erase (#2823) is to reach
// the kept replies by.
func (k *keptReplies) forget() (int, error) {
	k.fmu.Lock()
	defer k.fmu.Unlock()
	k.gen++
	held := k.forgetOwnerLocked()
	err := k.drop()
	if k.src == nil {
		return held, err
	}
	o, ok := k.src.(interface{ ForgetReplies() error })
	if !ok {
		return held, errors.Join(err, errors.New("the reply outbox cannot drop replies"))
	}
	return held, errors.Join(err, o.ForgetReplies())
}

func (k *keptReplies) drop() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.store.Save([]byte("[]"))
}

// list returns the kept items as they now read, oldest first: expired
// ones as stubs. Reading changes nothing.
func (k *keptReplies) list() []keptReply {
	k.mu.Lock()
	defer k.mu.Unlock()
	l, _ := k.loadLocked()
	return l
}

// held is the owner page's view (localapi.OpHeld): the items still kept,
// newest first, then the stubs, newest first.
func (k *keptReplies) held() localapi.HeldList {
	var live, stubs []localapi.HeldItem
	for _, r := range slices.Backward(k.list()) {
		it := localapi.HeldItem{ID: r.ID, Kind: r.Kind, At: r.At, Text: r.Text, Expired: r.Expired}
		if r.Expired {
			stubs = append(stubs, it)
		} else {
			live = append(live, it)
		}
	}
	return localapi.HeldList{Items: append(live, stubs...)}
}

// loadLocked reads the kept items as of now: one past keepFor is a stub,
// and a stub past stubFor more is gone. A store it cannot read is an
// error, so keep never writes over it.
func (k *keptReplies) loadLocked() ([]keptReply, error) {
	raw, err := k.store.Load()
	if err != nil {
		return nil, err
	}
	var l, out []keptReply
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &l); err != nil {
			return nil, err
		}
	}
	keepFor := k.keepFor
	if keepFor <= 0 {
		keepFor = defaultKeepFor
	}
	now := k.now()
	for _, r := range l {
		age := now.Sub(r.At)
		switch {
		case age >= keepFor+stubFor:
			continue
		case age >= keepFor:
			r.Text, r.Expired = "", true
		}
		out = append(out, r)
	}
	return out, nil
}
