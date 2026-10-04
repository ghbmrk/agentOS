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

// maxWrong wrong replies void a texted code (CH-18).
const maxWrong = 3

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

	mu     sync.Mutex
	resume *pendingCode
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
	case WordYes, WordNo:
		r = "No open requests."
	case WordUndo, WordMore:
		r = fmt.Sprintf("No request %s.", cmd.Args[0])
	default:
		if !h.Auth.SessionUnlocked(h.now()) {
			r = unlockText
		} else if h.Agent == nil || h.Agent.Deliver(ctx, cmd.Text, cmd.Public) != nil {
			r = "Your agent is not running. STOP, RESUME, STATUS and HELP still work."
		} else {
			return nil
		}
	}
	return []string{Fit(r)}
}

const helpText = "Commands: STOP pauses all actions. RESUME restarts them (needs a texted code). " +
	"STATUS. YES or NO answers a request, e.g. YES 1 3 <code>. UNDO <id>. MORE <id>. " +
	"Start a task with PUBLIC to mark it public. Anything else goes to your agent."

const unlockText = "This needs an unlocked session. Send a code from your code generator."

func (h *Handler) stop(ctx context.Context) string {
	h.mu.Lock()
	h.resume = nil // a code issued before STOP must not lift it
	h.mu.Unlock()
	rep, err := h.Engine.Stop(ctx)
	if err != nil && !h.Engine.Stopped() {
		return "STOP failed to record. Nothing new will start until the broker restarts."
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
	if !h.Engine.Stopped() {
		h.resume = nil
		return "Not stopped. Nothing to resume."
	}
	now := h.now()
	if len(args) == 0 {
		h.resume = &pendingCode{code: h.newCode(), expires: now.Add(CodeTTL)}
		return fmt.Sprintf("To restart all actions, reply RESUME %s within %d min.",
			h.resume.code, int(CodeTTL/time.Minute))
	}
	p := h.resume
	if p == nil || now.After(p.expires) {
		h.resume = nil
		return "No valid code. Reply RESUME for a new one."
	}
	if subtle.ConstantTimeCompare([]byte(args[0]), []byte(p.code)) != 1 {
		p.wrong++
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
		b.WriteString(" " + h.Machines())
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
