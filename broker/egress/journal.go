package egress

import (
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Recorder is the journal's audit entry point (journal.Engine).
type Recorder interface {
	RecordEgress(journal.EgressNote) error
}

// JournalAuditor is the Auditor the broker uses: denials become journal
// records (ADP-10, E6). Allowed requests are counted by the OP-8 meter,
// not journaled one by one. A failed journal write is reported to Logf;
// the request was already denied.
//
// Denials are coalesced so a looping guest cannot fill the journal: per
// machine and reason class (the reason up to any quoted, guest-chosen
// part, so varying a key name does not open a new entry), the first denial in a window (default one minute)
// is journaled at once, the rest are counted, and the count rides on the
// next note for that machine and reason (EgressNote.Suppressed).
type JournalAuditor struct {
	Journal Recorder
	Logf    func(format string, args ...any)
	Window  time.Duration    // default 1 minute
	Now     func() time.Time // default time.Now

	mu   sync.Mutex
	seen map[[2]string]*denials
}

type denials struct {
	since      time.Time
	suppressed int
}

// reasonClass is a denial reason without its quoted parts: the fixed
// text the proxy chose, never anything the request named.
func reasonClass(reason string) string {
	if i := strings.IndexByte(reason, '"'); i >= 0 {
		return reason[:i]
	}
	return reason
}

// maxKeys bounds the coalescing table; past it, expired entries are pruned.
const maxKeys = 4096

// Egress implements Auditor.
func (j *JournalAuditor) Egress(ev Event) {
	if ev.Allowed {
		return
	}
	n := journal.EgressNote{Machine: ev.Machine, Adapter: ev.Adapter, Operation: ev.Operation, Method: ev.Method, Status: ev.Status, Reason: ev.Reason}
	if !j.admit(&n) {
		return
	}
	if err := j.Journal.RecordEgress(n); err != nil && j.Logf != nil {
		j.Logf("journal egress denial for %s: %v", ev.Machine, err)
	}
}

// admit reports whether n is journaled now, and sets its Suppressed count.
func (j *JournalAuditor) admit(n *journal.EgressNote) bool {
	win, now := j.Window, time.Now()
	if win <= 0 {
		win = time.Minute
	}
	if j.Now != nil {
		now = j.Now()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.seen == nil {
		j.seen = map[[2]string]*denials{}
	}
	k := [2]string{n.Machine, reasonClass(n.Reason)}
	d := j.seen[k]
	if d != nil && now.Sub(d.since) < win {
		d.suppressed++
		return false
	}
	if d != nil {
		n.Suppressed = d.suppressed
	}
	if len(j.seen) >= maxKeys {
		for k2, d2 := range j.seen {
			if now.Sub(d2.since) >= win {
				delete(j.seen, k2)
			}
		}
	}
	if len(j.seen) >= maxKeys && d == nil {
		// Every key is live: journal this one without tracking it.
		return true
	}
	j.seen[k] = &denials{since: now}
	return true
}
