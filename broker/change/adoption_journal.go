package change

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"

	"github.com/ghbmrk/agentos/broker/journal"
)

// The adoption lifecycle on the journal (OP-11, SM-AD-1..4).
//
// Every lifecycle transition is a change intent: adopt (which stages an
// image), confirm, withdraw and revert. An adoption's body (its edits,
// score, owner-facing ID and digest marks) is kept in Content under
// "adoption/<id>", without the lifecycle fields, and a waiting proposal
// under "proposal/<id>". Attach rebuilds p.st.Adoptions and p.props from
// the journal's change intents in dispatch order, reading the bodies they
// name; the saved state no longer holds adoptions.
//
// Two undo paths are no intent by design and stay in the body: a forget
// (C23, WhyForgotten) and the owner's own settings replacing the adopted
// state (Superseded, WhySettings). Replay applies them last.

// lifecycle is an adoption's lifecycle as a state saved before the
// journal held it recorded it; replay starts such an adoption from it.
type lifecycle struct {
	Staged       bool   `json:"staged,omitempty"`
	Confirmed    bool   `json:"confirmed,omitempty"`
	Reverted     string `json:"reverted,omitempty"`
	WithdrawnFor string `json:"withdrawn_for,omitempty"`
}

// adoptionBody is what Content holds for an adoption.
type adoptionBody struct {
	Adoption
	Legacy *lifecycle `json:"legacy,omitempty"`
}

// savedProposal is what Content holds for a waiting proposal.
type savedProposal struct {
	Cand     Candidate `json:"cand"`
	Base     string    `json:"base"`
	Next     Tree      `json:"next"`
	Edits    []Edit    `json:"edits"`
	Report   Report    `json:"report"`
	Example  *Case     `json:"example,omitempty"`
	Classes  []Class   `json:"classes"`
	Security bool      `json:"security,omitempty"`
}

func adoptionKey(id string) string { return "adoption/" + id }
func proposalKey(id string) string { return "proposal/" + id }

// tailRevert: an undo that is no intent, so the body keeps it.
func tailRevert(why string) bool { return why == WhyForgotten || why == WhySettings }

// encodeBodyLocked is a's body as Content holds it: the lifecycle fields
// are the journal's, except an undo that is no intent.
func (p *Pipeline) encodeBodyLocked(a *Adoption) ([]byte, error) {
	b := adoptionBody{Adoption: *a, Legacy: p.legacy[a.ID]}
	b.Staged, b.Confirmed, b.WithdrawnFor = false, false, ""
	if !tailRevert(b.Reverted) {
		b.Reverted = ""
	}
	return json.Marshal(b)
}

// saveBodiesLocked puts every adoption body that changed since it was
// last put. It runs before the state is saved, so a failed put fails the
// save and the caller goes back to what was saved.
func (p *Pipeline) saveBodiesLocked() error {
	for _, a := range p.st.Adoptions {
		b, err := p.encodeBodyLocked(a)
		if err != nil {
			return err
		}
		if bytes.Equal(b, p.lastBody[a.ID]) {
			continue
		}
		if err := p.content.Put(adoptionKey(a.ID), b); err != nil {
			return err
		}
		p.lastBody[a.ID] = b
	}
	return nil
}

func cloneAdoptions(ads []*Adoption) []*Adoption {
	if ads == nil {
		return nil
	}
	out := make([]*Adoption, len(ads))
	for i, a := range ads {
		c := *a
		c.Classes = slices.Clone(a.Classes)
		c.Edits = slices.Clone(a.Edits)
		c.Goals = slices.Clone(a.Goals)
		out[i] = &c
	}
	return out
}

// migrateLocked moves the adoptions of a state saved before the journal
// held their lifecycle into Content, each with its saved lifecycle, and
// saves the state without them. Their adopt intents are in the journal,
// so replay finds them; later transitions apply on top.
func (p *Pipeline) migrateLocked() error {
	for _, a := range p.st.Adoptions {
		p.legacy[a.ID] = &lifecycle{Staged: a.Staged, Confirmed: a.Confirmed, Reverted: a.Reverted, WithdrawnFor: a.WithdrawnFor}
	}
	return p.saveLocked()
}

func (p *Pipeline) putProposalLocked(id string, pr *proposal) error {
	b, err := json.Marshal(savedProposal{Cand: pr.cand, Base: pr.base, Next: pr.next, Edits: pr.edits,
		Report: pr.report, Example: pr.report.example, Classes: pr.classes, Security: pr.security})
	if err != nil {
		return err
	}
	return p.content.Put(proposalKey(id), b)
}

// dropLocked forgets proposal id, in memory and in Content. A failed
// delete is logged: the proposal is gone from memory, and replay drops a
// proposal whose intent is no longer waiting.
func (p *Pipeline) dropLocked(id string) {
	delete(p.props, id)
	if err := p.content.Delete(proposalKey(id)); err != nil && p.cfg.Logf != nil {
		p.cfg.Logf("change: proposal not deleted (%s)", errClass(err))
	}
}

// recordsReader is the journal's record log; *journal.Engine has it.
type recordsReader interface {
	RecordsAfter(seq uint64) ([]journal.Record, error)
}

var seqPart = regexp.MustCompile(`^[cn][0-9]+$`)

// replayLocked rebuilds the adoptions and the waiting proposals from the
// journal (OP-11). A transition counts once its intent succeeded, or when
// its outcome is unknown and the saved state shows its effect (Reconcile
// will answer the same). Each applies only from a legal state: a confirm
// to a staged active adoption, a withdraw or a revert to an active one,
// so no crash between two steps replays to an illegal state (SM-AD-4).
func (p *Pipeline) replayLocked(j Journal) {
	rr, ok := j.(recordsReader)
	if !ok {
		return // no record log: what New loaded stands
	}
	recs, err := rr.RecordsAfter(0)
	if err != nil {
		p.brokenLocked("journal not readable", err)
		return
	}
	type change struct {
		in    journal.Intent
		parts []string
		seq   uint64 // its last dispatch
	}
	byID := map[string]*change{}
	var order []string
	maxSeq := p.st.Seq
	for _, r := range recs {
		switch r.Type {
		case journal.RecSubmitted:
			if r.Intent == nil || r.Intent.Executor != Executor || byID[r.Intent.ID] != nil {
				continue
			}
			parts := parseID(r.Intent.ID)
			if parts == nil {
				continue
			}
			for _, s := range parts[1:] {
				if seqPart.MatchString(s) {
					if n, err := strconv.Atoi(s[1:]); err == nil && n > maxSeq {
						maxSeq = n
					}
				}
			}
			byID[r.Intent.ID] = &change{in: *r.Intent, parts: parts}
			order = append(order, r.Intent.ID)
		case journal.RecDispatched:
			if c := byID[r.ID]; c != nil {
				c.seq = r.Seq
			}
		}
	}
	p.st.Seq = maxSeq

	var done []*change
	props := map[string]*proposal{}
	for _, id := range order {
		c := byID[id]
		st, err := j.Get(id)
		if err != nil {
			continue
		}
		switch {
		case st.State == journal.Succeeded, st.State == journal.OutcomeUnknown && p.st.Applied[id]:
			if c.seq > 0 {
				done = append(done, c)
			}
		case (st.State == journal.Pending || st.State == journal.Authorized) && c.in.Action == ActionAdopt && id == adoptID(c.parts[1]):
			if pr := p.loadProposalLocked(c.parts[1]); pr != nil {
				props[c.parts[1]] = pr
			}
		}
	}
	sort.SliceStable(done, func(a, b int) bool { return done[a].seq < done[b].seq })

	var ads []*Adoption
	byAd := map[string]*Adoption{}
	tail := map[string]string{}
	for _, c := range done {
		id := c.parts[1]
		switch {
		case c.in.Action == ActionAdopt:
			if byAd[id] != nil || c.in.ID != adoptID(id) {
				continue
			}
			a, legacy, err := p.loadBodyLocked(id)
			if err != nil {
				p.brokenLocked("adoption body missing", err)
				return
			}
			if tailRevert(a.Reverted) {
				tail[id] = a.Reverted
			}
			a.Reverted, a.Staged, a.Confirmed, a.WithdrawnFor = "", false, false, ""
			if legacy != nil {
				p.legacy[id] = legacy
				a.Staged, a.Confirmed, a.Reverted, a.WithdrawnFor = legacy.Staged, legacy.Confirmed, legacy.Reverted, legacy.WithdrawnFor
			} else {
				for _, cl := range a.Classes {
					a.Staged = a.Staged || cl == ClassGuestImage || cl == ClassHostImage
				}
			}
			byAd[id] = a
			ads = append(ads, a)
		case len(c.parts) < 3 || byAd[id] == nil || byAd[id].Reverted != "":
			// Not an adoption transition, or not from a legal state.
		case c.parts[2] == "confirm":
			if a := byAd[id]; a.Staged {
				a.Staged, a.Confirmed = false, true
			}
		case c.parts[2] == "withdraw" && len(c.parts) == 5:
			why := c.parts[4]
			if why == whyNone {
				why = ""
			}
			byAd[id].WithdrawnFor = why
		case c.parts[2] == "revert" && len(c.parts) == 5:
			a, why := byAd[id], c.parts[4]
			if why == WhyDropped && a.WithdrawnFor != "" {
				why = a.WithdrawnFor
			}
			a.Reverted = why
		}
	}
	for _, a := range ads {
		if why := tail[a.ID]; why != "" && a.Reverted == "" {
			a.Reverted = why
		}
	}
	p.st.Adoptions = ads
	p.savedAds = cloneAdoptions(ads)
	p.lastBody = map[string][]byte{}
	for _, a := range ads {
		if b, err := p.encodeBodyLocked(a); err == nil {
			p.lastBody[a.ID] = b
		}
	}
	for id, pr := range props {
		if p.props[id] == nil {
			p.props[id] = pr
		}
	}
	p.reforgetLocked()
}

// reforgetLocked forgets again each goal forgotten before Attach: the
// start-up forget replay runs before the adoptions are rebuilt, so it
// could not reach them (C23).
func (p *Pipeline) reforgetLocked() {
	goals := make([]string, 0, len(p.gone))
	for g := range p.gone {
		goals = append(goals, g)
	}
	sort.Strings(goals)
	for _, g := range goals {
		tree, ads, touched, changed := p.forgetAdoptionsLocked(g)
		if !changed {
			continue
		}
		if err := p.activateLocked(p.st.Active, tree, touched); err != nil {
			p.brokenLocked("forget not replayed", err)
			return
		}
		p.st.Adoptions, p.st.Active = ads, tree
		p.dropOldBasesLocked(tree.Hash())
		if err := p.saveLocked(); err != nil {
			p.brokenLocked("forget not saved", err)
			return
		}
	}
}

func (p *Pipeline) loadBodyLocked(id string) (*Adoption, *lifecycle, error) {
	raw, err := p.content.Get(adoptionKey(id))
	if err != nil {
		return nil, nil, err
	}
	if raw == nil {
		return nil, nil, errors.New("not found")
	}
	var b adoptionBody
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, nil, err
	}
	if b.ID != id {
		return nil, nil, fmt.Errorf("body names another adoption")
	}
	a := b.Adoption
	return &a, b.Legacy, nil
}

// loadProposalLocked reads a waiting proposal; nil when it is absent or
// unreadable, which leaves its intent with nothing to adopt (Check
// refuses it).
func (p *Pipeline) loadProposalLocked(id string) *proposal {
	raw, err := p.content.Get(proposalKey(id))
	if err != nil || raw == nil {
		return nil
	}
	var sp savedProposal
	if err := json.Unmarshal(raw, &sp); err != nil {
		return nil
	}
	rep := sp.Report
	rep.example = sp.Example
	return &proposal{cand: sp.Cand, base: sp.Base, next: sp.Next, edits: sp.Edits, report: rep,
		classes: sp.Classes, security: sp.Security}
}

// brokenLocked stops the pipeline: replay could not rebuild its state.
func (p *Pipeline) brokenLocked(what string, err error) {
	if p.cfg.Logf != nil {
		p.cfg.Logf("change: %s (%s); restart needed", what, errClass(err))
	}
	p.broken = errStateBroken
}

// whyNone is the withdraw mark's "no revert" in an intent ID.
const whyNone = "none"
