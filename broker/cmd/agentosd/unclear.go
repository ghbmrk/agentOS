package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/journal"
)

// unclearNoteMax is the longest unclear note: STATUS cuts each note at
// 100 characters.
const unclearNoteMax = 100

// unclearLine names one waiting effect in the owner's words (CH-12: no
// internal parts), with when it was first tried.
func unclearLine(p journal.ParkedIntent, loc *time.Location) string {
	w := daemon.EffectWord(p.Intent.Executor)
	w = strings.ToUpper(w[:1]) + w[1:]
	if !p.Dispatched.IsZero() {
		w += " first tried " + p.Dispatched.In(loc).Format("15:04 Jan 2")
	}
	if p.NotDone {
		return w + " did not go; not resent. Text RETRY to send it."
	}
	return w + " may not have gone; not retried. Text RETRY to try again; it may go twice."
}

// unclearNote is STATUS's line for what RETRY offers (OP-2, DRA-3): the
// effects whose outcome stayed unknown and that the broker parked rather
// than retried, and those a check proved were not done but whose resend
// was refused. One is named, with when it was first tried if that fits;
// more are counted. A refused owner retry leaves the effect waiting, so it
// stays listed. waiting is nil until daemon.Run returns, and the note is
// "" until then and while nothing waits. The owner reads it on asking:
// nothing is texted (DRB-1).
type unclearNote struct {
	waiting atomic.Pointer[func() []journal.ParkedIntent]
	loc     *time.Location
}

func (n *unclearNote) set(waiting func() []journal.ParkedIntent) { n.waiting.Store(&waiting) }

func (n *unclearNote) line() string {
	f := n.waiting.Load()
	if f == nil {
		return ""
	}
	ps := (*f)()
	switch len(ps) {
	case 0:
		return ""
	case 1:
		if l := unclearLine(ps[0], n.loc); len(l) <= unclearNoteMax {
			return l
		}
		p := ps[0]
		p.Dispatched = time.Time{}
		return unclearLine(p, n.loc)
	}
	for _, p := range ps {
		if !p.NotDone {
			return fmt.Sprintf("%d actions may not have gone; not retried. Text RETRY to go through them; some may go twice.", len(ps))
		}
	}
	return fmt.Sprintf("%d actions did not go; not resent. Text RETRY to send them.", len(ps))
}

// wireStatusNotes adds STATUS's lines for what waits on the owner, read
// when asked rather than texted (DRB-1): effects left unclear and parked
// rather than retried, or proved not done (OP-2, DRA-3), then each mail
// day still undoable (ADP-2), at most undoLookback. Both read the daemon
// once it runs: the caller sets unclear after daemon.Run and passes mail
// to wireMail.
func wireStatusNotes(cfg *daemon.Config) (*unclearNote, *mailNote) {
	unclear := &unclearNote{loc: time.Local}
	mail := &mailNote{}
	cfg.Notes = append(cfg.Notes, unclear.line)
	for k := 0; k < undoLookback; k++ {
		cfg.Notes = append(cfg.Notes, mail.slot(k))
	}
	return unclear, mail
}
