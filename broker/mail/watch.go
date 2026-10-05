package mail

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/events"
	"github.com/ghbmrk/agentos/broker/recall"
)

// Publisher is the event bus as the watcher uses it (events.Bus).
type Publisher interface {
	Publish(e events.Event) (string, bool, error)
}

// WatchConfig configures a Watcher.
type WatchConfig struct {
	// Publisher receives an event per new message (CAP-4); the bus's
	// recall trigger (events.IndexInto) indexes it (CAP-3).
	Publisher Publisher
	// Keyer must be the bus's and recall's (Index.Keyer), so the watcher
	// names deleted messages by the identity recall holds them under.
	Keyer recall.Keyer
	// State keeps each folder's UID validity and the identity of each UID
	// seen: hashes only, no content.
	State recall.Store
	// Deleted is called with the recall identities of messages gone from
	// every watched folder (deleted at the source, or moved to trash or
	// junk). It is called only after a poll that listed every folder,
	// and only for messages whose last folders were read again under the
	// same UID validity.
	// Until the owner decides whether a mail deleted at the source also
	// takes back agent work, the wiring passes a recall-only deletion
	// (ASSUMPTIONS M7).
	Deleted func(ids []string) error
	// Backfill bounds how many of a folder's newest messages its first
	// poll publishes (default 10000); older ones are recorded unpublished.
	Backfill int
	// Batch bounds the messages fetched per request (default 100).
	Batch int
}

// DefaultBackfill is the first poll's per-folder bound, inside recall's
// measured ceiling of about 100k items (recall R8).
const DefaultBackfill = 10000

// Watcher publishes a mail account's new messages to the event bus and
// reports deletions at the source.
type Watcher struct {
	a   *Adapter
	cfg WatchConfig
	mu  sync.Mutex
	st  watchState
}

type watchState struct {
	Folders map[string]*folderState `json:"folders"`
}

type folderState struct {
	Validity uint32            `json:"validity"`
	UIDs     map[uint32]string `json:"uids"` // UID -> recall identity, "" if never published
	// Missing counts consecutive polls whose listing lacked this folder.
	Missing int `json:"missing,omitempty"`
}

// missingPolls is how many consecutive listings must lack a known folder
// before its messages count as deleted with it.
const missingPolls = 3

// PollReport is what one poll did: events the bus took as new, and
// messages reported deleted.
type PollReport struct {
	Published, Deleted int
	Complete           bool // every folder listed
}

// ErrWatchConfig is returned for an incomplete WatchConfig.
var ErrWatchConfig = errors.New("mail: WatchConfig needs Publisher, a Keyer, State and Deleted")

// Watch returns the account's watcher, loading its state.
func (a *Adapter) Watch(cfg WatchConfig) (*Watcher, error) {
	if cfg.Publisher == nil || !cfg.Keyer.Valid() || cfg.State == nil || cfg.Deleted == nil {
		return nil, ErrWatchConfig
	}
	if cfg.Backfill <= 0 {
		cfg.Backfill = DefaultBackfill
	}
	if cfg.Batch <= 0 {
		cfg.Batch = 100
	}
	w := &Watcher{a: a, cfg: cfg, st: watchState{Folders: map[string]*folderState{}}}
	b, err := cfg.State.ReadAll()
	if err != nil {
		return nil, err
	}
	if s := strings.TrimSpace(string(b)); s != "" {
		// The state is rewritten whole; the last line is the current one.
		lines := strings.Split(s, "\n")
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &w.st); err != nil {
			return nil, fmt.Errorf("mail: watch state: %v", err)
		}
		if w.st.Folders == nil {
			w.st.Folders = map[string]*folderState{}
		}
	}
	return w, nil
}

// watched are the folders the watcher reads: an all-mail view if the
// account has one (Gmail's, where an archived message is in no other
// folder), else every folder but trash, junk and drafts.
func watched(fs []Folder) []string {
	for _, f := range fs {
		if f.Role == All {
			return []string{f.Name}
		}
	}
	var out []string
	for _, f := range fs {
		switch f.Role {
		case Trash, Junk, Drafts, All:
			continue
		}
		if trashNames.MatchString(f.Name) {
			continue
		}
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}

// Poll reads every watched folder once: new messages are published, and
// messages gone from all of them are reported deleted. A folder that
// cannot be listed keeps its last known contents, deletions wait for a
// poll that lists everything, and a message counts as deleted only if
// every folder it was last seen in was read again under the same UID
// validity, so an outage, a short listing, a change in the watched set or
// a renumbering never reads as deletion.
func (w *Watcher) Poll(ctx context.Context) (PollReport, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var rep PollReport
	fs, err := w.a.cfg.Store.Folders(ctx)
	if err != nil {
		return rep, err
	}
	// Where each published message was last seen. A message counts as
	// deleted only if every folder it was last seen in was listed and read
	// again under the same UID validity: a folder that left the listing or
	// the watched set (an all-mail view that lost its role), or was
	// renumbered, never makes its messages read as deleted.
	lastIn := map[string][]string{}
	for name, f := range w.st.Folders {
		for _, id := range f.UIDs {
			if id != "" {
				lastIn[id] = append(lastIn[id], name)
			}
		}
	}
	stable := map[string]bool{}
	present := map[string]bool{}
	complete := true
	var errs []error
	next := map[string]*folderState{}
	names := watched(fs)
	// A listing without the inbox (or the all-mail view) is not a
	// mailbox's real listing: nothing is concluded from it.
	hasInbox := false
	for _, f := range fs {
		if f.Role == Inbox || f.Role == All || strings.EqualFold(f.Name, "INBOX") {
			hasInbox = true
		}
	}
	if !hasInbox {
		return rep, errors.New("mail: the folder listing has no inbox")
	}
	// A known folder missing from the listing keeps its contents present
	// until missingPolls listings in a row lack it, so a short or broken
	// listing never reads as mass deletion.
	listed := map[string]bool{}
	for _, n := range names {
		listed[n] = true
	}
	for name, old := range w.st.Folders {
		if listed[name] {
			continue
		}
		if old.Missing+1 < missingPolls {
			kept := *old
			kept.Missing++
			next[name] = &kept
			complete = false
		}
	}
	for _, name := range names {
		old := w.st.Folders[name]
		validity, uids, err := w.a.cfg.Store.UIDs(ctx, name)
		if err != nil {
			complete = false
			errs = append(errs, err)
			if old != nil {
				next[name] = old
			}
			continue
		}
		fst := &folderState{Validity: validity, UIDs: map[uint32]string{}}
		first := old == nil
		if old != nil && old.Validity != validity {
			// UIDs were renumbered: read the folder again, bounded like a
			// first read.
			old, first = nil, true
		}
		readAll := true
		var fresh []uint32
		for _, u := range uids {
			if old != nil {
				if id, ok := old.UIDs[u]; ok {
					fst.UIDs[u] = id
					present[id] = true
					continue
				}
			}
			fresh = append(fresh, u)
		}
		sort.Slice(fresh, func(i, j int) bool { return fresh[i] < fresh[j] })
		if first && len(fresh) > w.cfg.Backfill {
			for _, u := range fresh[:len(fresh)-w.cfg.Backfill] {
				fst.UIDs[u] = ""
			}
			fresh = fresh[len(fresh)-w.cfg.Backfill:]
		}
		n, err := w.publish(ctx, name, fresh, fst, present)
		rep.Published += n
		if err != nil {
			complete = false
			readAll = false
			errs = append(errs, err)
		}
		stable[name] = readAll && !first
		next[name] = fst
	}
	w.st.Folders = next
	if err := w.save(); err != nil {
		return rep, err
	}
	rep.Complete = complete
	if complete {
		var gone []string
	ids:
		for id, in := range lastIn {
			if present[id] {
				continue
			}
			for _, f := range in {
				if !stable[f] {
					continue ids
				}
			}
			gone = append(gone, id)
		}
		sort.Strings(gone)
		if len(gone) > 0 {
			if err := w.cfg.Deleted(gone); err != nil {
				errs = append(errs, err)
			} else {
				rep.Deleted = len(gone)
			}
		}
	}
	return rep, errors.Join(errs...)
}

// publish fetches and publishes fresh messages, recording each one it
// published. One that fails stays unrecorded and is tried next poll.
func (w *Watcher) publish(ctx context.Context, folder string, fresh []uint32, fst *folderState, present map[string]bool) (int, error) {
	n := 0
	for len(fresh) > 0 {
		k := min(len(fresh), w.cfg.Batch)
		batch := fresh[:k]
		fresh = fresh[k:]
		ms, err := w.a.cfg.Store.Fetch(ctx, folder, batch)
		if err != nil {
			return n, err
		}
		for _, m := range ms {
			ref := refOf(folder, m)
			id := w.cfg.Keyer.SourceID(string(events.Mail), w.a.cfg.Account, ref)
			_, isNew, err := w.cfg.Publisher.Publish(events.Event{
				Kind: events.Mail, Account: w.a.cfg.Account, Ref: ref, Version: ref, At: m.Date,
				Label: recall.Private, Summary: summary(m), Body: m.Text,
			})
			if err != nil {
				return n, err
			}
			fst.UIDs[m.UID] = id
			present[id] = true
			if isNew {
				n++
			}
		}
	}
	return n, nil
}

// refOf names a message for the bus and recall. A Message-ID is the
// sender's to choose, so it is not the identity alone: the ref is the
// Message-ID with a digest of the sender, date and the first bytes of the
// text. A move keeps it; a different message reusing the ID (to replace
// or shadow one in recall) is a separate item. A message without a
// Message-ID is named by a digest of its location and headers; a move
// makes it a new item.
func refOf(folder string, m Message) string {
	if m.MessageID != "" {
		text := m.Text
		if len(text) > refText {
			text = text[:refText]
		}
		return m.MessageID + " #" + digest(m.From, m.Date.UTC().Format(time.RFC3339), text)
	}
	return "nomid: #" + digest(folder, strconv.FormatUint(uint64(m.UID), 10), m.From, m.Subject, m.Date.String())
}

// refText is how much of a message's text its ref digests.
const refText = 256

// digest is 72 bits of a SHA-256 over parts, as 18 letters a to p. The
// letters keep the ref readable in recall, whose scrubber removes long
// random-looking tokens (CRED-1) but keeps letter runs under 20.
func digest(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	b := make([]byte, 18)
	for i := range b {
		n := h[i/2]
		if i%2 == 0 {
			n >>= 4
		}
		b[i] = 'a' + n&0x0f
	}
	return string(b)
}

// summary is the event's header lines. Everything in it came from the
// sender and is untrusted content (recall renders it so).
func summary(m Message) string {
	s := "From: " + m.From
	if len(m.To) > 0 {
		s += "\nTo: " + strings.Join(m.To, ", ")
	}
	if len(m.Cc) > 0 {
		s += "\nCc: " + strings.Join(m.Cc, ", ")
	}
	s += "\nSubject: " + oneLine(m.Subject)
	if m.Attachments {
		s += "\n(has attachments)"
	}
	return s
}

func (w *Watcher) save() error {
	b, err := json.Marshal(w.st)
	if err != nil {
		return err
	}
	return w.cfg.State.Rewrite(append(b, '\n'))
}

// Coverage is how much of the watched mail is in recall: messages
// published, and messages seen in all, as of the last poll. The owner
// reads it as "Mail indexed: newest 10,000 of 48,200" when the first
// backfill was bounded.
func (w *Watcher) Coverage() (indexed, total int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, f := range w.st.Folders {
		for _, id := range f.UIDs {
			total++
			if id != "" {
				indexed++
			}
		}
	}
	return indexed, total
}
