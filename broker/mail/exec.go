package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

var _ journal.Executor = (*Adapter)(nil)

// Change is the journaled evidence of one organize, trash or spam effect:
// the message, its state before, and what the agent set (ADP-2: the
// broker journals the prior state with each one). Undo reads it back.
type Change struct {
	Op      string   `json:"op"`
	Record  string   `json:"record"`
	Sender  string   `json:"sender,omitempty"`
	From    string   `json:"from"`         // folder before
	To      string   `json:"to,omitempty"` // folder after, if moved
	Before  []string `json:"before,omitempty"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
	// Alert marks an effect on a message the alert guard caught that ran
	// all the same (a label or star), for the digest's guard hits.
	Alert bool `json:"alert,omitempty"`
}

// Outgoing is the journaled evidence of a sent or saved message.
type Outgoing struct {
	Op        string `json:"op"`
	MessageID string `json:"message_id"`
	Folder    string `json:"folder,omitempty"`
}

// Execute performs one effect (journal.Executor). It runs only after the
// gate allowed it, and re-reads the source rather than trusting what the
// gate saw: a reply goes to the thread's participants as they are now, and
// an organize target is checked again.
func (a *Adapter) Execute(ctx context.Context, in journal.Intent, attempt int) journal.Outcome {
	o, p, err := a.intent(in)
	if err != nil {
		return notApplied(err)
	}
	switch o.Name {
	case OpDraft:
		return a.draft(ctx, in, attempt, p)
	case OpSend, OpReply:
		return a.send(ctx, in, attempt, o, p)
	}
	pl, err := a.planOrganize(ctx, o, p)
	if err != nil {
		return notApplied(err)
	}
	ch := Change{Op: o.Name, Record: pl.msg.MessageID, Sender: pl.msg.From, From: pl.msg.Folder,
		Before: sorted(pl.msg.Flags), Alert: pl.alert && !pl.hides}
	for _, f := range pl.add {
		if !has(pl.msg.Flags, f) {
			ch.Added = append(ch.Added, f)
		}
	}
	for _, f := range pl.remove {
		if has(pl.msg.Flags, f) {
			ch.Removed = append(ch.Removed, f)
		}
	}
	if len(ch.Added)+len(ch.Removed) > 0 {
		if err := a.cfg.Store.SetFlags(ctx, pl.msg.Folder, pl.msg.UID, ch.Added, ch.Removed); err != nil {
			return unknown(err)
		}
	}
	if pl.to != "" {
		if strings.HasPrefix(pl.to, Namespace) {
			if err := a.cfg.Store.Ensure(ctx, pl.to); err != nil {
				return unknown(err)
			}
		}
		if err := a.cfg.Store.Move(ctx, pl.msg.Folder, pl.msg.UID, pl.to); err != nil {
			return unknown(err)
		}
		ch.To = pl.to
	}
	return succeeded(ch)
}

// Reconcile asks the mailbox what happened to an attempt.
func (a *Adapter) Reconcile(ctx context.Context, in journal.Intent, attempt int) journal.Outcome {
	o, p, err := a.intent(in)
	if err != nil {
		return notApplied(err)
	}
	byRole, _, err := a.folders(ctx)
	if err != nil {
		return unknown(err)
	}
	switch o.Name {
	case OpDraft, OpSend, OpReply:
		id := a.messageID(in.ID, attempt)
		folder := byRole[Sent]
		if o.Name == OpDraft {
			folder = byRole[Drafts]
		}
		if folder != "" {
			ms, err := a.cfg.Store.Find(ctx, folder, id)
			if err != nil {
				return unknown(err)
			}
			if len(ms) > 0 {
				return succeeded(Outgoing{Op: o.Name, MessageID: id, Folder: folder})
			}
		}
		if o.Name == OpDraft {
			// Saving a draft is one APPEND: absent means not saved.
			return notApplied(errors.New("mail: draft not in the drafts folder"))
		}
		return unknown(errors.New("mail: sent message not found in the sent folder"))
	}
	pl, err := a.planOrganize(ctx, o, p)
	if err != nil {
		return unknown(err)
	}
	done := pl.to == "" || pl.to == pl.msg.Folder
	for _, f := range pl.add {
		done = done && has(pl.msg.Flags, f)
	}
	for _, f := range pl.remove {
		done = done && !has(pl.msg.Flags, f)
	}
	if done {
		return succeeded(Change{Op: o.Name, Record: pl.msg.MessageID, Sender: pl.msg.From, From: pl.msg.Folder})
	}
	return notApplied(errors.New("mail: the message is not in the state the effect sets"))
}

func (a *Adapter) draft(ctx context.Context, in journal.Intent, attempt int, p map[string]string) journal.Outcome {
	byRole, _, err := a.folders(ctx)
	if err != nil {
		return unknown(err)
	}
	if byRole[Drafts] == "" {
		return notApplied(errors.New("mail: the account has no drafts folder"))
	}
	h := header{}
	to, err := canonAll(in.Recipients)
	if err != nil {
		return notApplied(err)
	}
	subject := p[ParamSubject]
	if p[ParamRecord] != "" {
		m, err := a.locate(ctx, p[ParamRecord], "")
		if err != nil {
			return notApplied(err)
		}
		h.thread(m)
		if subject == "" {
			subject = reSubject(m.Subject)
		}
	}
	id := a.messageID(in.ID, attempt)
	raw := a.build(h, to, nil, subject, p[ParamBody], id)
	if err := a.cfg.Store.Append(ctx, byRole[Drafts], []string{Draft, Seen}, a.cfg.Now(), raw); err != nil {
		return unknown(err)
	}
	return succeeded(Outgoing{Op: OpDraft, MessageID: id, Folder: byRole[Drafts]})
}

func (a *Adapter) send(ctx context.Context, in journal.Intent, attempt int, o Op, p map[string]string) journal.Outcome {
	h := header{}
	var to, cc []string
	subject := p[ParamSubject]
	if o.Name == OpReply {
		m, err := a.locate(ctx, p[ParamRecord], "")
		if err != nil {
			return notApplied(err)
		}
		// The approval was for the thread's participants as the source
		// named them; they must still be exactly the intent's.
		rc := a.participants(m)
		got, err := canonAll(in.Recipients)
		if err != nil || !sameSet(got, rc) {
			return notApplied(errors.New("mail: the reply's recipients are not the thread's participants"))
		}
		for _, x := range append([]string{m.From}, m.To...) {
			if !a.self[x] && !has(to, x) {
				to = append(to, x)
			}
		}
		for _, x := range rc {
			if !has(to, x) {
				cc = append(cc, x)
			}
		}
		h.thread(m)
		subject = reSubject(m.Subject)
	} else {
		var err error
		if to, err = canonAll(in.Recipients); err != nil || len(to) == 0 {
			return notApplied(errors.New("mail: a message needs valid recipients"))
		}
		for _, x := range to {
			if a.self[x] {
				// The owner channel is the owner's; mail to the owner's
				// own address would be a way around it.
				return notApplied(errors.New("mail: the owner's own address is not a recipient"))
			}
		}
	}
	id := a.messageID(in.ID, attempt)
	raw := a.build(h, to, cc, subject, p[ParamBody], id)
	if err := a.cfg.Store.Submit(ctx, append(append([]string{}, to...), cc...), raw); err != nil {
		return unknown(err)
	}
	ev := Outgoing{Op: o.Name, MessageID: id}
	if a.cfg.AppendSent {
		if byRole, _, err := a.folders(ctx); err == nil && byRole[Sent] != "" {
			if a.cfg.Store.Append(ctx, byRole[Sent], []string{Seen}, a.cfg.Now(), raw) == nil {
				ev.Folder = byRole[Sent]
			}
		}
	}
	return succeeded(ev)
}

// messageID is the outgoing Message-ID of an attempt: stable, so
// Reconcile can find it, and it carries no intent text.
func (a *Adapter) messageID(intent string, attempt int) string {
	sum := sha256.Sum256([]byte(a.cfg.Account + "\x00" + journal.AttemptKey(intent, attempt)))
	return "<agentos." + hex.EncodeToString(sum[:16]) + "@" + domainOf(a.cfg.Address) + ">"
}

type header struct{ inReplyTo, references string }

func (h *header) thread(m Message) {
	h.inReplyTo = m.MessageID
	refs := append(append([]string{}, m.References...), m.MessageID)
	if len(refs) > 20 {
		refs = append(refs[:1], refs[len(refs)-19:]...)
	}
	h.references = strings.Join(refs, " ")
}

// build renders a plain-text message. Every header value is the broker's
// or has had line breaks removed, so the agent's subject cannot add a
// header.
func (a *Adapter) build(h header, to, cc []string, subject, body, id string) []byte {
	var b bytes.Buffer
	line := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	line("From", a.cfg.Address)
	if len(to) > 0 {
		line("To", strings.Join(to, ", "))
	}
	if len(cc) > 0 {
		line("Cc", strings.Join(cc, ", "))
	}
	line("Subject", mime.QEncoding.Encode("utf-8", oneLine(subject)))
	line("Date", a.cfg.Now().Format(time.RFC1123Z))
	line("Message-ID", id)
	if h.inReplyTo != "" {
		line("In-Reply-To", h.inReplyTo)
		line("References", h.references)
	}
	line("MIME-Version", "1.0")
	line("Content-Type", "text/plain; charset=utf-8")
	line("Content-Transfer-Encoding", "quoted-printable")
	b.WriteString("\r\n")
	w := quotedprintable.NewWriter(&b)
	w.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n")))
	w.Close()
	return b.Bytes()
}

func oneLine(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == '\r' || r == '\n' }), " ")
}

func reSubject(s string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), "re:") {
		return s
	}
	return "Re: " + s
}

func canonAll(l []string) ([]string, error) {
	var out []string
	for _, x := range l {
		c, ok := canon(x)
		if !ok || strings.ToLower(strings.TrimSpace(x)) != c {
			return nil, fmt.Errorf("mail: recipient is not a bare address")
		}
		if !has(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := sorted(a), sorted(b)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func sorted(l []string) []string {
	out := append([]string(nil), l...)
	sort.Strings(out)
	return out
}

func succeeded(v any) journal.Outcome {
	b, _ := json.Marshal(v)
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: string(b)}
}

// Errors are the adapter's own wording, never the server's, so nothing a
// server echoes reaches the journal.
func notApplied(err error) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied, Evidence: reason(err)}
}

func unknown(err error) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown, Evidence: reason(err)}
}

func reason(err error) string {
	for _, e := range []error{ErrNotFound, ErrTarget, ErrAccount, ErrOp} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	if s := err.Error(); strings.HasPrefix(s, "mail: ") {
		return s
	}
	return "mail: the mailbox refused or did not answer"
}
