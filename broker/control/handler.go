package control

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// CodeTTL is how long a texted RESUME code stays valid (CH-10 default).
const CodeTTL = 15 * time.Minute

// Texted-code limits (CH-18). maxWrong wrong replies void one code;
// maxWrongDay wrong codes in a day lock texted RESUME codes. maxCodeTexts
// caps the RESUME texts the broker sends per hour, so a spoofer cannot
// make the box text the owner without limit.
const (
	maxWrong     = 3
	maxWrongDay  = 5
	maxCodeTexts = 3
)

// DeliverTimeout bounds how long task chat waits on the agent.
const DeliverTimeout = 5 * time.Second

// Engine is the part of the journal engine that control words drive.
type Engine interface {
	Stop(ctx context.Context) (journal.StopReport, error)
	Resume() error
	Stopped() bool
	List() []journal.Status
}

// Auth answers CH-3's proofs. The owner channel (P1-5) supplies the real
// implementation: the owner's number and the code-generator session unlock.
type Auth interface {
	IsOwner(from string) bool
	SessionUnlocked(now time.Time) bool
}

// Agent receives task chat. An error means the agent is unavailable.
type Agent interface {
	Deliver(ctx context.Context, text string, public bool) error
}

// Handler turns one owner message into the broker's replies. It is safe for
// concurrent use.
type Handler struct {
	Engine Engine
	Auth   Auth
	Agent  Agent // nil: no agent running
	// Machines, if set, returns STATUS's line about agent machines.
	Machines func() string
	Now      func() time.Time
	// NewCode returns a fresh texted code; nil means 6 random digits.
	NewCode func() string
	// Settings, if set, answers an owner text that is a whole-message
	// setting outside the control words above (the loops' LOOPS OFF,
	// SPARE BUDGET n, HELP LOOPS; loops.Scheduler.Text). It is tried
	// after the control words, so it cannot shadow STOP. unlocked says
	// whether the session is unlocked: locked, the hook takes only
	// settings whose worst case is a pause (CH-11's pause words need no
	// unlock) and returns ok false for the rest, which get the unlock
	// prompt. ok false in an unlocked session passes the message on to
	// the agent.
	Settings func(ctx context.Context, msg string, unlocked bool) (reply string, ok bool)
	// HelpExtra, if set, is appended to HELP's reply (loops.HelpLine).
	HelpExtra string

	mu     sync.Mutex
	resume *pendingCode
	// wrongAt and textsAt are the times of wrong RESUME codes and of RESUME
	// texts sent. Neither resets when a new code is issued.
	wrongAt []time.Time
	textsAt []time.Time
	// hintAt is when the STOP hint was last sent.
	hintAt time.Time
}

type pendingCode struct {
	code    string
	expires time.Time
	wrong   int
}

// Handle processes one message from number from and returns the texts to
// send back. Messages from any other number than the owner's get no reply.
func (h *Handler) Handle(ctx context.Context, from, msg string) []string {
	if !h.Auth.IsOwner(from) {
		return nil
	}
	cmd := Parse(msg)
	var r string
	switch cmd.Word {
	case WordStop:
		r = h.stop(ctx)
	case WordResume:
		r = h.resumeCmd(cmd.Args)
	case WordStatus:
		if !h.Auth.SessionUnlocked(h.now()) {
			r = unlockText
		} else {
			r = h.status()
		}
	case WordHelp:
		r = helpText
		if h.HelpExtra != "" {
			r += " " + h.HelpExtra
		}
	case WordYes, WordNo:
		r = "No open requests."
	case WordUndo, WordMore:
		r = fmt.Sprintf("No request %s.", cmd.Args[0])
	case WordUnclear:
		r = "Not understood, and not sent to your agent. Reply HELP for commands."
	default:
		var out []string
		if StopNearMiss(cmd.Text) && h.takeHint() {
			out = append(out, stopHint)
		}
		unlocked := h.Auth.SessionUnlocked(h.now())
		if reply, ok := h.setting(ctx, cmd, unlocked); ok {
			out = append(out, reply)
		} else if !unlocked {
			out = append(out, unlockText)
		} else if !h.deliver(ctx, cmd) {
			out = append(out, "Your agent is not running. STOP, RESUME, STATUS and HELP still work.")
		}
		for i := range out {
			out[i] = Fit(out[i])
		}
		return out
	}
	if r == "" {
		return nil
	}
	return []string{Fit(r)}
}

const stopHint = "To pause everything, reply STOP."

// HintQuiet is the least time between two STOP hints. The hint answers a
// message that only proves the owner's number, so spoofed near-misses must
// not be able to make the box text the owner repeatedly (CH-15).
const HintQuiet = time.Hour

func (h *Handler) takeHint() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if !h.hintAt.IsZero() && now.Sub(h.hintAt) < HintQuiet {
		return false
	}
	h.hintAt = now
	return true
}

// setting tries the Settings hook on a whole message that is not marked
// PUBLIC (a PUBLIC task is always task chat).
func (h *Handler) setting(ctx context.Context, cmd Command, unlocked bool) (string, bool) {
	if h.Settings == nil || cmd.Public {
		return "", false
	}
	return h.Settings(ctx, cmd.Text, unlocked)
}

func (h *Handler) deliver(ctx context.Context, cmd Command) bool {
	if h.Agent == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, DeliverTimeout)
	defer cancel()
	return h.Agent.Deliver(ctx, cmd.Text, cmd.Public) == nil
}

const helpText = "Commands: STOP pauses all actions. RESUME restarts them (needs a texted code). " +
	"STATUS. YES or NO answers a request, e.g. YES 1 3 <code>. UNDO <id>. MORE <id>. " +
	"Start a task with PUBLIC to mark it public. Anything else goes to your agent."

const unlockText = "This needs an unlocked session. Send a code from your code generator. STOP works without one."

func (h *Handler) stop(ctx context.Context) string {
	h.mu.Lock()
	h.resume = nil // a code issued before STOP must not lift it
	h.mu.Unlock()
	rep, err := h.Engine.Stop(ctx)
	if err != nil && !h.Engine.Stopped() {
		return "STOP failed to record. Nothing new starts now; reply STOP again."
	}
	return fmt.Sprintf("Stopped. %d held, %d may have happened, %d cancel requests sent. Nothing was undone. Reply RESUME to restart.",
		len(rep.Held), len(rep.Unresolved), accepted(rep.Cancels))
}

func accepted(cs []journal.CancelAttempt) int {
	n := 0
	for _, c := range cs {
		if c.Supported {
			n++
		}
	}
	return n
}

func (h *Handler) resumeCmd(args []string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	h.wrongAt = since(h.wrongAt, now.Add(-24*time.Hour))
	h.textsAt = since(h.textsAt, now.Add(-time.Hour))
	if !h.Engine.Stopped() {
		h.resume = nil
		return "Not stopped. Nothing to resume."
	}
	if len(h.wrongAt) >= maxWrongDay {
		h.resume = nil
		return h.codeText(now, "RESUME is locked after 5 wrong codes in 24 hours. STOP still works.")
	}
	if len(args) == 0 {
		if h.resume == nil || now.After(h.resume.expires) {
			h.resume = &pendingCode{code: h.newCode(), expires: now.Add(CodeTTL)}
		}
		return h.codeText(now, fmt.Sprintf("To restart all actions, reply RESUME %s within %d min.",
			h.resume.code, int(h.resume.expires.Sub(now).Round(time.Minute)/time.Minute)))
	}
	p := h.resume
	if p == nil || now.After(p.expires) {
		h.resume = nil
		return "No valid code. Reply RESUME for a new one."
	}
	if subtle.ConstantTimeCompare([]byte(args[0]), []byte(p.code)) != 1 {
		p.wrong++
		h.wrongAt = append(h.wrongAt, now)
		if len(h.wrongAt) >= maxWrongDay {
			h.resume = nil
			return "Wrong code 5 times in 24 hours. RESUME by texted code is locked. STOP still works."
		}
		if p.wrong >= maxWrong {
			h.resume = nil
			return "Wrong code 3 times; it is void. Reply RESUME for a new one."
		}
		return "Wrong code. Reply RESUME <code>."
	}
	h.resume = nil
	if err := h.Engine.Resume(); err != nil {
		return "RESUME failed to record. Still stopped."
	}
	return "Resumed. Held actions may now run."
}

// codeText sends text unless the hourly cap on RESUME texts is spent, in
// which case the broker stays silent.
func (h *Handler) codeText(now time.Time, text string) string {
	if len(h.textsAt) >= maxCodeTexts {
		return ""
	}
	h.textsAt = append(h.textsAt, now)
	return text
}

func since(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return ts[i:]
}

func (h *Handler) status() string {
	var b strings.Builder
	if h.Engine.Stopped() {
		b.WriteString("Stopped.")
	} else {
		b.WriteString("Running.")
	}
	var unresolved, held, open []string
	for _, s := range h.Engine.List() {
		label := safeToken(s.Intent.Action, 20) + "/" + safeToken(s.Intent.Account, 16)
		switch s.State {
		case journal.InFlight, journal.OutcomeUnknown:
			unresolved = append(unresolved, label)
		case journal.Authorized, journal.NotApplied:
			held = append(held, label)
		case journal.Pending:
			open = append(open, label)
		}
	}
	fmt.Fprintf(&b, " %d may have happened%s", len(unresolved), sample(unresolved))
	fmt.Fprintf(&b, ", %d waiting to run, %d awaiting a decision.", len(held), len(open))
	if h.Machines != nil {
		b.WriteString(" " + plainLine(h.Machines(), 80))
	}
	return b.String()
}

// sample lists up to three labels, so STATUS stays within three segments.
func sample(labels []string) string {
	if len(labels) == 0 {
		return ""
	}
	n := len(labels)
	if n > 3 {
		labels = labels[:3]
	}
	s := " (" + strings.Join(labels, ", ")
	if n > 3 {
		s += fmt.Sprintf(", +%d more", n-3)
	}
	return s + ")"
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h *Handler) newCode() string {
	if h.NewCode != nil {
		return h.NewCode()
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic("control: no system randomness: " + err.Error())
	}
	return fmt.Sprintf("%06d", n.Int64())
}
