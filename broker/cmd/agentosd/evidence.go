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

// Evidence delivery (CH-20). With a destination set, an agent reply from
// a private machine goes there, delivered by the broker as a pre-allowed
// share to the owner (grants OriginEvidence, mail.OpDeliver), and the text
// carries only a summary and a pointer, so a SIM swapper gets summaries,
// not content. The destination is the gate's: the owner sets it with a
// code and the local page, never the agent. Without one, replies are
// texted as before (DEP-3).

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
	// owns reports whether addr is a connected mail account's own
	// address, and which account (mail.Adapter.Owns); nil while no mail
	// account is connected. It is grants.Config.Destination too.
	owns func(addr string) (account string, ok bool)
	kept *keptReplies
	logf func(string, ...any)
}

// The mail adapter's delivery operation and executor (mail.OpDeliver,
// mail.Tool): agentosd does not link the adapter (ARC-2).
const (
	opDeliver    = "mail.deliver"
	mailExecutor = "mail"
)

// deliverTimeout bounds one delivery.
const deliverTimeout = 30 * time.Second

// minSummary is the shortest summary worth sending; with less room (a
// very long domain) the text says only that the agent replied.
const minSummary = 20

// smsSegment is one GSM-7 text: a redirected reply's text fits in it.
const smsSegment = 160

// Fixed wording. The pointer names the destination masked, as STATUS does.
const (
	keptPointer      = "The full reply could not be emailed; it is kept for the box's Wi-Fi page."
	noSummary        = "Your agent replied."
	evidenceAsked    = "Changing where private replies go needs a code and confirmation on the box's Wi-Fi page. A request follows."
	evidenceNotOwn   = "Not changed: replies can go only to the connected mail account's own address."
	evidenceNoMail   = "Not changed: emailing replies needs a connected mail account, which this box does not have yet."
	evidenceStarting = "The box is still starting. Try again in a minute."
	evidenceFailed   = "The box could not save that setting. Try again later."
)

// newEvidence keeps undelivered replies at keptPath.
func newEvidence(keptPath string, logf func(string, ...any)) *evidence {
	return &evidence{kept: &keptReplies{store: change.FileStore{Path: keptPath}, now: time.Now, logf: logf}, logf: logf}
}

func (e *evidence) g() evidenceGate {
	if b := e.gate.Load(); b != nil {
		return b.g
	}
	return nil
}

// reply sends one agent reply to the owner. private is the machine's
// label (REV-5): a machine that is not public counts as private.
func (e *evidence) reply(machine string, private bool, text string) {
	g := e.g()
	addr, acct := "", ""
	if g != nil {
		addr, acct = g.Evidence()
	}
	if !private || addr == "" {
		e.send(machine, text)
		return
	}
	pointer := "Full reply sent to " + maskAddress(addr) + "."
	if err := e.deliver(g, addr, acct, text); err != nil {
		e.logf("reply from %s not emailed: %v", machine, err)
		e.kept.keep(text)
		pointer = keptPointer
	}
	e.send(machine, summarize(text, smsSegment-len(owner.AgentPrefix)-1-len(pointer))+" "+pointer)
}

func (e *evidence) send(machine, text string) {
	if err := e.notify(text); err != nil {
		e.logf("reply from %s not sent: %v", machine, err)
	}
}

// deliver submits the delivery and runs it now. Anything but success is
// an error: the reply is then kept, never texted.
func (e *evidence) deliver(g evidenceGate, addr, acct, text string) error {
	var b [8]byte
	rand.Read(b[:])
	id := "evidence/" + hex.EncodeToString(b[:])
	ctx, cancel := context.WithTimeout(context.Background(), deliverTimeout)
	defer cancel()
	st, err := g.Submit(journal.Intent{ID: id, Origin: grants.OriginEvidence, Account: acct, Action: opDeliver,
		Params: map[string]any{grants.ParamBody: text}, Recipients: []string{addr}, Executor: mailExecutor})
	if err == nil && st.State == journal.Pending {
		st, err = g.Authorize(ctx, id)
	}
	if err == nil && st.State == journal.Authorized {
		st, err = g.Dispatch(ctx, id)
	}
	if err != nil {
		return err
	}
	if st.State != journal.Succeeded {
		return errors.New("delivery " + string(st.State) + ": " + st.Permission.Reason)
	}
	return nil
}

// summarize is the reply's first line, or its first sentence, cut to max
// bytes. A summary that looks like a code or key is left out (CH-19), so
// the text never turns into the held-back notice.
func summarize(text string, max int) string {
	s := strings.TrimSpace(text)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	for i := 0; i+1 < len(s); i++ {
		if strings.ContainsRune(".!?", rune(s[i])) && s[i+1] == ' ' {
			s = s[:i+1]
			break
		}
	}
	if max < minSummary {
		return noSummary
	}
	if len(s) > max {
		cut := max - len("...")
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = strings.TrimSpace(s[:cut]) + "..."
	}
	if s == "" || owner.SecretShaped(s) {
		return noSummary
	}
	return s
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

// note is STATUS's line while a destination is set.
func (e *evidence) note() string {
	g := e.g()
	if g == nil {
		return ""
	}
	if addr, _ := g.Evidence(); addr != "" {
		return "Private replies: emailed to " + maskAddress(addr) + "."
	}
	return ""
}

// settings takes EMAIL REPLIES TO <address> and EMAIL REPLIES OFF
// (control.Handler.Settings). Either changes where private content goes,
// so a locked session never takes them (they get the unlock prompt) and
// the gate asks the owner for a code and the local page (CH-10).
func (e *evidence) settings(ctx context.Context, msg string, unlocked bool) (string, bool) {
	f := strings.Fields(msg)
	if len(f) < 3 || !strings.EqualFold(f[0], "EMAIL") || !strings.EqualFold(f[1], "REPLIES") {
		return "", false
	}
	addr := ""
	switch {
	case len(f) == 3 && strings.EqualFold(f[2], "OFF"):
	case len(f) == 4 && strings.EqualFold(f[2], "TO") && strings.Contains(f[3], "@"):
		addr = strings.ToLower(strings.TrimRight(f[3], "."))
	default:
		return "", false
	}
	if !unlocked {
		return "", false
	}
	g := e.g()
	if g == nil {
		return evidenceStarting, true
	}
	acct := ""
	if addr != "" {
		if e.owns == nil {
			return evidenceNoMail, true
		}
		var ok bool
		if acct, ok = e.owns(addr); !ok {
			return evidenceNotOwn, true
		}
	}
	var b [6]byte
	rand.Read(b[:])
	id := "owner/evidence/" + hex.EncodeToString(b[:])
	st, err := g.Submit(grants.EvidenceIntent(id, grants.OriginOwner, addr, acct))
	if err == nil && st.State == journal.Pending {
		st, err = g.Authorize(ctx, id)
	}
	switch {
	case err != nil:
		e.logf("evidence setting: %v", err)
		return evidenceFailed, true
	case st.State == journal.Denied:
		return "Not changed: " + strings.TrimSuffix(st.Permission.Reason, ".") + ".", true
	}
	return evidenceAsked, true
}

// Kept replies: a private reply that could not be delivered waits here
// for the box's Wi-Fi page, at most maxKept and none past keepReplies, in
// a file only the broker reads.
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
	b, _ := json.Marshal(l)
	if err := k.store.Save(b); err != nil && k.logf != nil {
		k.logf("reply not kept: %v", err)
	}
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
	cfg.Grants.Destination = e.owns
}

// attach starts routing through the running daemon's gate and owner
// channel.
func (e *evidence) attach(d *daemon.Daemon) {
	e.notify = func(text string) error {
		ch := d.Owner()
		if ch == nil {
			return errors.New("no owner channel")
		}
		return ch.Notify(text)
	}
	e.gate.Store(&evidenceGateBox{d.Gate()})
}
