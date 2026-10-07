package change

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"unicode/utf8"
)

var ErrDigestSnapshot = errors.New("change: invalid digest snapshot")
var ErrDigestInvalidated = errors.New("change: digest snapshot invalidated by forget")

// DigestSnapshot is broker-private source output. Its receipt is scoped to
// acknowledgment of this pipeline's emitted data, never approval/effect authority.
// Queue integration must retain the full snapshot for idempotent recovery.
type DigestSnapshot struct {
	Schema     int          `json:"schema"`
	Generation uint64       `json:"generation"`
	Hash       string       `json:"hash"`
	Lines      []string     `json:"lines"`
	References []string     `json:"references,omitempty"`
	Marks      []DigestMark `json:"marks"`
}

// DigestMark binds an exact source event; a later changed event is not consumed.
type DigestMark struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	Tag  string `json:"tag"`
}
type digestEntry struct {
	line       string
	mark       DigestMark
	references []string
}

func digestCopy[T any](v T) T {
	b, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(b, &out)
	return out
}
func digestTag(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func listedTag(a *Adoption) string {
	v := *a
	v.Listed = false
	v.RevertSeen = false
	v.ConcernSeen = false
	v.Concern = ""
	v.ConcernScore = Score{}
	return digestTag(v)
}
func concernTag(a *Adoption) string {
	return digestTag(struct {
		Why   string
		Score Score
	}{a.Concern, a.ConcernScore})
}
func (p *Pipeline) digestReceipt(s DigestSnapshot) string {
	s.Hash = ""
	b, _ := json.Marshal(s)
	h := hmac.New(sha256.New, p.st.SplitKey)
	_, _ = h.Write([]byte("agentos/change/digest/v1\x00"))
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
func (p *Pipeline) validDigest(s DigestSnapshot) bool {
	if s.Schema != 1 || s.Generation == 0 || len(s.Lines) == 0 || len(s.Lines) > 64 || len(s.Marks) != len(s.Lines) || len(s.References) > 64 {
		return false
	}
	total := 0
	for _, line := range s.Lines {
		if line == "" || len(line) > 4096 || !utf8.ValidString(line) {
			return false
		}
		total += len(line)
	}
	if total > 64<<10 {
		return false
	}
	for _, m := range s.Marks {
		switch m.Kind {
		case "listed", "revert", "concern", "notice", "outage", "repeat":
		default:
			return false
		}
		if len(m.Tag) != 64 {
			return false
		}
	}
	expected := p.digestReceipt(s)
	return len(s.Hash) == 64 && hmac.Equal([]byte(expected), []byte(s.Hash))
}
func (p *Pipeline) checkDigestStateLocked() error {
	if p.st.DigestAcked > p.st.DigestSeq || p.st.DigestFloor > p.st.DigestSeq {
		return ErrDigestSnapshot
	}
	if s := p.st.DigestPending; s != nil {
		if !p.validDigest(*s) || s.Generation != p.st.DigestSeq || s.Generation <= p.st.DigestAcked || s.Generation <= p.st.DigestFloor {
			return ErrDigestSnapshot
		}
	}
	return nil
}

func (p *Pipeline) digestFail(err error) error {
	p.broken = fmt.Errorf("change: digest storage outcome uncertain; restart required: %w", err)
	return p.broken
}

// PeekDigest opts this pipeline into snapshot delivery, which excludes the
// destructive legacy Digest reader. It persists immutable pending output without
// marking any event seen. Later events wait for the next generation.
func (p *Pipeline) PeekDigest() (*DigestSnapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken != nil {
		return nil, p.broken
	}
	if err := p.checkDigestStateLocked(); err != nil {
		return nil, err
	}
	if s := p.st.DigestPending; s != nil {
		if !p.validDigest(*s) || s.Generation != p.st.DigestSeq || s.Generation <= p.st.DigestFloor {
			return nil, ErrDigestSnapshot
		}
		// Re-save on reopen/re-peek: reading post-rename bytes alone is not durability.
		if err := p.saveLocked(); err != nil {
			return nil, p.digestFail(err)
		}
		copy := digestCopy(*s)
		return &copy, nil
	}
	entries := p.digestEntriesLocked()
	if len(entries) == 0 {
		return nil, nil
	}
	if p.st.DigestSeq == math.MaxUint64 {
		return nil, ErrDigestSnapshot
	}
	s := DigestSnapshot{Schema: 1, Generation: p.st.DigestSeq + 1}
	refs := map[string]bool{}
	total := 0
	for _, e := range entries {
		if len(e.line) > 4096 || !utf8.ValidString(e.line) {
			return nil, ErrDigestSnapshot
		}
		if len(s.Lines) == 64 || total+len(e.line) > 64<<10 {
			break
		}
		total += len(e.line)
		s.Lines = append(s.Lines, e.line)
		s.Marks = append(s.Marks, e.mark)
		for _, ref := range e.references {
			refs[ref] = true
		}
	}
	for ref := range refs {
		s.References = append(s.References, ref)
	}
	slices.Sort(s.References)
	if len(s.References) > 64 {
		return nil, ErrDigestSnapshot
	}
	s.Hash = p.digestReceipt(s)
	previous := p.st.DigestSeq
	p.st.DigestSeq = s.Generation
	p.st.DigestPending = &s
	if err := p.saveLocked(); err != nil {
		p.st.DigestSeq = previous
		p.st.DigestPending = nil
		return nil, p.digestFail(err)
	}
	copy := digestCopy(s)
	return &copy, nil
}

// AckDigest must follow durable queue admission. It consumes only captured
// event versions; newer events stay pending. Issued receipts allow older exact
// acknowledgments to remain idempotent without an unbounded acknowledgment log.
// This is a broker-only API. A receipt is not permission to send or adopt.
func (p *Pipeline) AckDigest(s DigestSnapshot) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken != nil {
		return p.broken
	}
	if err := p.checkDigestStateLocked(); err != nil {
		return err
	}
	if !p.validDigest(s) || s.Generation > p.st.DigestSeq {
		return ErrDigestSnapshot
	}
	if s.Generation <= p.st.DigestFloor {
		return ErrDigestInvalidated
	}
	if s.Generation <= p.st.DigestAcked {
		if err := p.saveLocked(); err != nil {
			return p.digestFail(err)
		}
		return nil
	}
	if p.st.DigestPending == nil || p.st.DigestPending.Generation != s.Generation || p.st.DigestPending.Hash != s.Hash {
		return ErrDigestSnapshot
	}
	old := digestCopy(p.st)
	for _, m := range s.Marks {
		p.applyDigestMarkLocked(m)
	}
	p.st.DigestAcked = s.Generation
	p.st.DigestPending = nil
	if err := p.saveLocked(); err != nil {
		p.st = old
		return p.digestFail(err)
	}
	return nil
}

// ValidateDigest checks issuance and forget invalidation. It does not prove that
// commands/references are still live; render/dispatch qualification is separate.
func (p *Pipeline) ValidateDigest(s DigestSnapshot) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.broken != nil {
		return p.broken
	}
	if err := p.checkDigestStateLocked(); err != nil {
		return err
	}
	if !p.validDigest(s) || s.Generation > p.st.DigestSeq {
		return ErrDigestSnapshot
	}
	if s.Generation <= p.st.DigestFloor {
		return ErrDigestInvalidated
	}
	return nil
}
func (p *Pipeline) invalidateDigestGoalLocked(goal string) {
	if p.st.DigestPending != nil && slices.Contains(p.st.DigestPending.References, goal) {
		p.st.DigestFloor = p.st.DigestSeq
		p.st.DigestPending = nil
	}
}
func (p *Pipeline) applyDigestMarkLocked(m DigestMark) {
	switch m.Kind {
	case "listed":
		if a := p.adoptionLocked(m.ID); a != nil && listedTag(a) == m.Tag {
			a.Listed = true
		}
	case "revert":
		if a := p.adoptionLocked(m.ID); a != nil && digestTag(a.Reverted) == m.Tag {
			a.RevertSeen = true
		}
	case "concern":
		if a := p.adoptionLocked(m.ID); a != nil && concernTag(a) == m.Tag {
			a.ConcernSeen = true
		}
	case "notice":
		for i := range p.st.Notices {
			n := &p.st.Notices[i]
			if n.Key == m.ID && digestTag(n.Line) == m.Tag {
				n.Seen = true
			}
		}
	case "outage":
		if digestTag(p.st.Outages) == m.Tag {
			p.st.OutageSeen = true
		}
	}
}

// digestEntriesLocked is the single fixed-wording renderer for legacy and
// snapshot delivery. Rendering is read-only; only matching marks consume events.
func (p *Pipeline) digestEntriesLocked() []digestEntry {
	var out []digestEntry
	add := func(line, kind, id, tag string, refs []string) {
		out = append(out, digestEntry{line: line, mark: DigestMark{Kind: kind, ID: id, Tag: tag}, references: slices.Clone(refs)})
	}
	for _, a := range p.st.Adoptions {
		if !a.Listed {
			line := p.what(a) + "." + testedText(a.Score)
			switch a.Basis {
			case BasisOwner:
				line += " You approved it."
			case BasisSecurity:
				line += " Security update, under your standing policy."
			}
			switch {
			case a.Reverted != "":
			case p.undoableLocked(a):
				line += fmt.Sprintf(" UNDO %s / MORE %s", a.Short, a.Short)
			default:
				line += fmt.Sprintf(" MORE %s", a.Short)
			}
			add(line, "listed", a.ID, listedTag(a), a.Goals)
		}
		if a.Reverted != "" && !a.RevertSeen {
			why := map[string]string{WhyOwner: " as you asked.", WhyRegression: ": it did worse on newer tasks.", WhySecurity: ": it failed a security check.", WhyFallback: ": the update did not start cleanly, so the box kept the previous one.", WhyForgotten: ": it was learned from a task you asked the box to forget."}[a.Reverted]
			add("Undid "+a.Short+why, "revert", a.ID, digestTag(a.Reverted), a.Goals)
		}
	}
	// One-shot events precede repeated declined-release reminders so repeated
	// lines cannot starve new notices in a bounded snapshot.
	for _, a := range p.st.Adoptions {
		if a.Concern != "" && !a.ConcernSeen && a.Reverted == "" {
			score := a.ConcernScore
			line := p.what(&Adoption{Classes: a.Classes, Origin: a.Origin}) + " now"
			if a.Concern == WhySecurity {
				line += " fails a newer security check"
			} else {
				line += fmt.Sprintf(" does worse on %d of %d newer tasks", max(score.Regressions, score.BaselinePassed-score.Passed), score.HeldOut)
			}
			if p.undoableLocked(a) {
				line += ". Reply UNDO " + a.Short + " to go back to the previous version, or nothing to keep it."
			} else {
				line += ". It is the only version on the box, so it stays until a newer update is installed."
			}
			add(line, "concern", a.ID, concernTag(a), a.Goals)
		}
	}
	for _, n := range p.st.Notices {
		if !n.Seen {
			add(n.Line, "notice", n.Key, digestTag(n.Line), nil)
		}
	}
	if p.st.Outages >= OutageAlert && !p.st.OutageSeen {
		add(fmt.Sprintf("The box could not re-test its learned changes the last %d times it tried; they stay as they are until it can.", p.st.Outages), "outage", strconv.Itoa(p.st.Outages), digestTag(p.st.Outages), nil)
	}
	seen := map[string]bool{}
	for _, d := range p.st.Declined {
		if !seen[d.Version] {
			seen[d.Version] = true
			line := "You declined security update " + safe(d.Version) + "; the box is still on the previous version until a newer update is installed."
			add(line, "repeat", d.Version, digestTag(line), nil)
		}
	}
	return out
}
