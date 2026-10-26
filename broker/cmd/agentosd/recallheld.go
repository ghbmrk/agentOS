package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/daemon"
)

// Recall lineages held at upgrade (VM-lineage-contained, LOG-4, CAP-3).
// Before #2781 recall contained an agent lineage that had read a record
// the owner deleted, and rolled it back once the owner said yes. agentosd
// no longer opens recall, so at each start it reads the directory recall
// left at rest (FD-3), read-only and without the deleted code, finds the
// lineages still holding a deleted record, rolls each back to before its
// first such read, records that durably, and tells the owner. Until then,
// and for good when the files cannot be read, the lineage is contained:
// no fork, no merge, no pre-allowance.
const (
	// recallSettledFile, in the -machines directory (stateDir), records
	// each lineage rolled back, so a restart never rolls it back again.
	recallSettledFile = "recall-settled.json"
)

// recallAtRest is the old -recall default (FD-3); tests read their own.
var recallAtRest = "/var/lib/agentos/recall"

// recallRecord is one line of provenance.jsonl or backs.jsonl
// (recalltool's provRecord at c2c29e8).
type recallRecord struct {
	Lineage  string    `json:"l"`
	IDs      []string  `json:"ids"`
	At       time.Time `json:"at"`
	Forget   bool      `json:"forget"`
	Reset    time.Time `json:"reset"`
	TakeBack bool      `json:"tb"`
	Anchor   string    `json:"a"`
	Seq      int       `json:"seq"`
	Note     string    `json:"n"`
}

// recallSpan is a recorded reset or a back: the lineage's machines went
// back to before since at began.
type recallSpan struct{ since, began time.Time }

// recallLineage is one lineage's replayed provenance.
type recallLineage struct {
	reads  map[string]time.Time
	resets map[int64]recallSpan
	backs  map[int64]recallSpan
}

// undone reports a time inside a reset or back known so far (recalltool's
// undone): what was read then is no longer in the lineage's machines.
func (l *recallLineage) undone(t time.Time) bool {
	for _, m := range []map[int64]recallSpan{l.resets, l.backs} {
		for _, s := range m {
			if !t.Before(s.since) && t.Before(s.began) {
				return true
			}
		}
	}
	return false
}

// recallReplay replays provenance in recalltool's apply order.
type recallReplay map[string]*recallLineage

func (p recallReplay) of(lineage string) *recallLineage {
	l := p[lineage]
	if l == nil {
		l = &recallLineage{reads: map[string]time.Time{}, resets: map[int64]recallSpan{}, backs: map[int64]recallSpan{}}
		p[lineage] = l
	}
	return l
}

// apply mirrors recalltool's apply: the first case that matches decides.
func (p recallReplay) apply(r recallRecord) {
	switch {
	case r.Lineage == "", r.Note != "", r.Anchor != "" || r.Seq > 0:
		return
	case r.TakeBack:
		if r.Forget && !r.Reset.IsZero() {
			p.of(r.Lineage).backs[r.At.UnixNano()] = recallSpan{r.At, r.Reset}
		}
	case !r.Reset.IsZero():
		l, since := p.of(r.Lineage), r.At.UnixNano()
		if r.Forget {
			for _, id := range r.IDs {
				delete(l.reads, id)
			}
			delete(l.resets, since)
			return
		}
		delete(l.backs, since)
		l.resets[since] = recallSpan{r.At, r.Reset}
	case r.Forget:
		l := p.of(r.Lineage)
		if len(r.IDs) == 0 {
			l.reads = map[string]time.Time{}
		}
		for _, id := range r.IDs {
			delete(l.reads, id)
		}
	default:
		l := p.of(r.Lineage)
		for _, id := range r.IDs {
			if t, ok := l.reads[id]; !ok || l.undone(t) {
				l.reads[id] = r.At
			}
		}
	}
}

// recallLines splits a JSON-lines file as recall's stores did: a torn
// final line (no newline) is dropped, and empty lines are skipped. An
// absent file has none.
func recallLines(path string) ([][]byte, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	var lines [][]byte
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		if i > 0 {
			lines = append(lines, data[:i])
		}
		data = data[i+1:]
	}
	return lines, true, nil
}

// heldLineage is a lineage holding a deleted record: the deleted items it
// read, and the earliest time it read one.
type heldLineage struct {
	IDs   []string
	Since time.Time
}

// readRecallHeld reads dir at rest. An absent dir holds nothing. Any
// unreadable file or line other than a torn final one is an error: the
// caller then contains every lineage.
func readRecallHeld(dir string) (map[string]heldLineage, error) {
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	tombs := map[string]time.Time{}
	meta, metaFound, err := recallLines(filepath.Join(dir, "recall", "meta.jsonl"))
	if err != nil {
		return nil, err
	}
	for i, line := range meta {
		var r struct {
			Op string    `json:"op"`
			ID string    `json:"id"`
			At time.Time `json:"at"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("recall/meta.jsonl line %d: %w", i+1, err)
		}
		if r.Op == "tomb" && r.ID != "" {
			tombs[r.ID] = r.At
		}
	}
	live, err := reingested(filepath.Join(dir, "recall"), tombs)
	if err != nil {
		return nil, err
	}
	p := recallReplay{}
	// Backs first, as OpenProvenanceWithBacks: a back must be known when
	// the record's re-reads and resets are replayed.
	for _, name := range []string{"backs.jsonl", "provenance.jsonl"} {
		lines, _, err := recallLines(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		for i, line := range lines {
			var r recallRecord
			if err := json.Unmarshal(line, &r); err != nil {
				return nil, fmt.Errorf("%s line %d: %w", name, i+1, err)
			}
			if name == "backs.jsonl" && (r.Lineage == "" || !r.TakeBack || !r.Forget || r.Reset.IsZero()) {
				continue
			}
			p.apply(r)
		}
	}
	held := map[string]heldLineage{}
	for name, l := range p {
		var h heldLineage
		for id, t := range l.reads {
			if _, gone := tombs[id]; !gone || live[id] || l.undone(t) {
				continue
			}
			h.IDs = append(h.IDs, id)
			if len(h.IDs) == 1 || t.Before(h.Since) {
				h.Since = t
			}
		}
		if len(h.IDs) > 0 {
			sort.Strings(h.IDs)
			held[name] = h
		}
	}
	// Reads with no meta log to say what was deleted: recall always wrote
	// one, so its absence is not "nothing deleted".
	if !metaFound {
		for _, l := range p {
			if len(l.reads) > 0 {
				return nil, errors.New("recall/meta.jsonl is missing")
			}
		}
	}
	return held, nil
}

// reingested finds the deleted IDs ingested again after their tombstone,
// as recall's Index.Deleted saw them (c2c29e8): an item line in a segment
// whose receipt is after the tomb is live, so its ID is not deleted. Lines
// recall skipped (no id, or undecodable) are skipped here too; an
// unreadable segment is an error.
func reingested(dir string, tombs map[string]time.Time) (map[string]bool, error) {
	if len(tombs) == 0 {
		return nil, nil
	}
	names, err := filepath.Glob(filepath.Join(dir, "seg-*.jsonl"))
	if err != nil {
		return nil, err
	}
	live := map[string]bool{}
	for _, p := range names {
		n := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "seg-"), ".jsonl")
		if _, err := strconv.ParseUint(n, 10, 32); err != nil {
			continue
		}
		lines, _, err := recallLines(p)
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			var it struct {
				ID       string    `json:"id"`
				Received time.Time `json:"received"`
			}
			if json.Unmarshal(line, &it) != nil {
				continue
			}
			if t, gone := tombs[it.ID]; gone && it.Received.After(t) {
				live[it.ID] = true
			}
		}
	}
	return live, nil
}

// recallSettled is one lineage's entry in recallSettledFile: rolled back
// to Since over IDs, and whether the owner was told.
type recallSettled struct {
	IDs   []string  `json:"ids"`
	Since time.Time `json:"since"`
	Told  bool      `json:"told"`
}

// recallHeld is agentosd's view of the lineages held at upgrade:
// Contained for vm.Config and grants.Config, a STATUS note, and the
// start-up rollback.
type recallHeld struct {
	path string // recallSettledFile
	logf func(string, ...any)

	mu        sync.Mutex
	unknown   bool
	held      map[string]heldLineage
	kept      map[string]bool
	keptKnown bool // the journal was read
	settled   map[string]recallSettled
}

// openRecallHeld reads the recall directory at rest and the settled
// record. Either one unreadable contains every lineage.
func openRecallHeld(dir, settledPath string, logf func(string, ...any)) *recallHeld {
	h := &recallHeld{path: settledPath, logf: logf, kept: map[string]bool{}, settled: map[string]recallSettled{}}
	held, err := readRecallHeld(dir)
	if err != nil {
		logf("recall directory at rest unreadable, every agent contained: %v", err)
		h.unknown = true
	}
	h.held = held
	// Unknown files still read the record, so its untold notices go out.
	if len(held) == 0 && !h.unknown {
		return h
	}
	data, err := os.ReadFile(settledPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		logf("%s unreadable, every agent contained: %v", settledPath, err)
		h.unknown = true
	default:
		if err := json.Unmarshal(data, &h.settled); err != nil {
			// Unmarshal keeps what it decoded before a type error: none of
			// it is told or saved, so the record stays as it is.
			logf("%s unreadable, every agent contained: %v", settledPath, err)
			h.unknown = true
			h.settled = map[string]recallSettled{}
		}
	}
	return h
}

// isSettled reports a rollback recorded over every deleted item lineage
// holds now. Caller holds mu.
func (h *recallHeld) isSettled(lineage string) bool {
	s, ok := h.settled[lineage]
	if !ok {
		return false
	}
	done := map[string]bool{}
	for _, id := range s.IDs {
		done[id] = true
	}
	for _, id := range h.held[lineage].IDs {
		if !done[id] {
			return false
		}
	}
	return true
}

// containedLocked: held, not settled, and not kept by the owner's NO
// (counted as held until the journal is read). Caller holds mu.
func (h *recallHeld) containedLocked(lineage string) bool {
	if h.unknown {
		return true
	}
	if _, ok := h.held[lineage]; !ok || h.isSettled(lineage) {
		return false
	}
	return !h.keptKnown || !h.kept[lineage]
}

// Contained is vm.Config.Contained and grants.Config.Contained.
func (h *recallHeld) Contained(lineage string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.containedLocked(lineage)
}

// wire sets the grants hook and the STATUS line; the daemon copies both.
func (h *recallHeld) wire(cfg *daemon.Config) {
	cfg.Grants.Contained = h.Contained
	cfg.Notes = append(cfg.Notes, h.Note)
}

// Note is STATUS's line: the agents still holding a record the owner
// deleted, and which of them cannot fork or merge.
func (h *recallHeld) Note() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.unknown {
		return "The old memory directory could not be read: agents cannot fork or merge"
	}
	var contained, kept []string
	for l := range h.held {
		switch {
		case h.containedLocked(l):
			contained = append(contained, agentName(l))
		case h.keptKnown && h.kept[l] && !h.isSettled(l):
			kept = append(kept, agentName(l))
		}
	}
	var parts []string
	if len(contained) > 0 {
		parts = append(parts, holdLine(contained)+"; no fork or merge until it goes back, which I try again when I restart")
	}
	if len(kept) > 0 {
		parts = append(parts, holdLine(kept))
	}
	return strings.Join(parts, "; ")
}

func holdLine(names []string) string {
	sort.Strings(names)
	verb := " still holds"
	if len(names) > 1 {
		verb = " still hold"
	}
	return strings.Join(names, ", ") + verb + " a record you deleted"
}

// agentName is how STATUS names a lineage (recalltool's agentName).
func agentName(lineage string) string {
	if i := strings.LastIndex(lineage, "."); i > 0 {
		return lineage[:i]
	}
	return lineage
}

// lineageForgetter is the vm.Manager part settle uses.
type lineageForgetter interface {
	ForgetSince(ctx context.Context, lineage string, since time.Time) error
}

// recallNo is the owner's NO to a rollback question as the journal holds
// it (recallNos in main.go): the lineage, and the comma-joined items asked.
type recallNo struct{ lineage, items string }

// keep reads the owner's NOs: a lineage is kept when a NO names it and
// covers every deleted item it holds (recalltool's current). Matched on
// lineage and items, not intent ID, since this reader's since may differ.
func (h *recallHeld) keep(nos []recallNo) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, no := range nos {
		l, items := no.lineage, no.items
		hl, ok := h.held[l]
		if !ok {
			continue
		}
		covered := map[string]bool{}
		for _, id := range strings.Split(items, ",") {
			covered[id] = true
		}
		all := true
		for _, id := range hl.IDs {
			all = all && covered[id]
		}
		if all {
			h.kept[l] = true
		}
	}
	h.keptKnown = true
}

// settle runs once at start-up, after the machines open and before any is
// served: it reads the owner's NOs, then rolls back each held lineage that
// is neither kept nor settled, recording each success before the next, and
// tells the owner of each rollback not yet told. A failed rollback leaves
// its lineage contained until the next start. Unknown files, or a journal
// that cannot be read (nos errs), roll back nothing; rollbacks settled at
// an earlier start are still told.
func (h *recallHeld) settle(ctx context.Context, m lineageForgetter, nos func() ([]recallNo, error), tell func(string) error) {
	if got, err := nos(); err != nil {
		h.logf("journal unreadable, agents holding a record the owner deleted stay contained: %v", err)
	} else {
		h.keep(got)
		h.rollBack(ctx, m)
	}
	h.notify(tell)
}

// rollBack rolls back each contained held lineage, recording each.
func (h *recallHeld) rollBack(ctx context.Context, m lineageForgetter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.unknown {
		return
	}
	var todo []string
	for l := range h.held {
		if h.containedLocked(l) {
			todo = append(todo, l)
		}
	}
	sort.Strings(todo)
	for _, l := range todo {
		hl := h.held[l]
		if err := m.ForgetSince(ctx, l, hl.Since); err != nil {
			h.logf("agent %s holds a record the owner deleted and could not go back: %v", agentName(l), err)
			continue
		}
		h.settled[l] = recallSettled{IDs: hl.IDs, Since: hl.Since}
		if err := h.save(); err != nil {
			// Not recorded: the lineage stays contained and the next
			// start rolls it back again, so no further one is risked now.
			delete(h.settled, l)
			h.logf("agent %s went back but %s was not written: %v", agentName(l), h.path, err)
			return
		}
	}
}

// notify tells the owner of each settled rollback not yet told. Sends run
// outside mu, so a slow owner channel never stalls Contained.
func (h *recallHeld) notify(tell func(string) error) {
	h.mu.Lock()
	var untold []string
	since := map[string]time.Time{}
	for l, s := range h.settled {
		if !s.Told {
			untold = append(untold, l)
			since[l] = s.Since
		}
	}
	h.mu.Unlock()
	sort.Strings(untold)
	for _, l := range untold {
		if err := tell(recallBackNotice(l, since[l])); err != nil {
			h.logf("rollback notice for agent %s not sent: %v", agentName(l), err)
			continue
		}
		h.mu.Lock()
		s := h.settled[l]
		s.Told = true
		h.settled[l] = s
		if err := h.save(); err != nil {
			h.logf("%s not written: %v", h.path, err)
		}
		h.mu.Unlock()
	}
}

// recallBackNotice is the owner's notice of one rollback.
func recallBackNotice(lineage string, since time.Time) string {
	to := "its start"
	if !since.IsZero() {
		to = since.Local().Format("Jan 2 15:04")
	}
	return fmt.Sprintf("Agent %s had read a record you deleted, so it went back to %s; its work since then is gone.", agentName(lineage), to)
}

// save writes the settled record durably. Caller holds mu.
func (h *recallHeld) save() error {
	b, err := json.Marshal(h.settled)
	if err != nil {
		return err
	}
	return writeSynced(h.path, b)
}
