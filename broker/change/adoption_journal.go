package change

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
// The two undos that happen under the pipeline's own lock, a forget (C23,
// WhyForgotten) and the owner's own settings replacing the adopted state
// (Superseded, WhySettings), are revert intents too. They take effect in
// the same save that owes their intent (oweLocked), and flushOwed
// journals it once the lock is free: the journal calls Check and Execute
// under that lock. Replay reads no lifecycle from a body
// (CHG-forget-revert-journal, SM-AD-2).

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

// owedRevert: an undo the pipeline applies under its own lock and then
// journals (oweLocked). An earlier build kept it in the body.
func owedRevert(why string) bool { return why == WhyForgotten || why == WhySettings }

// encodeBodyLocked is a's body as Content holds it: the lifecycle fields
// are the journal's.
func (p *Pipeline) encodeBodyLocked(a *Adoption) ([]byte, error) {
	b := adoptionBody{Adoption: *a, Legacy: p.legacy[a.ID]}
	b.Staged, b.Confirmed, b.Reverted, b.WithdrawnFor = false, false, "", ""
	return json.Marshal(b)
}

// oweRevertsLocked owes a revert intent for each adoption that next
// undoes by a forget or the owner's settings and prev left active. The
// caller saves the effect and the debt together; flushOwed journals it.
func (p *Pipeline) oweRevertsLocked(prev, next []*Adoption) []string {
	active := map[string]bool{}
	for _, a := range prev {
		active[a.ID] = a.Reverted == ""
	}
	var owed []string
	for _, a := range next {
		if active[a.ID] && owedRevert(a.Reverted) {
			owed = append(owed, p.oweLocked(a.ID, a.Reverted))
		}
	}
	return owed
}

// oweLocked records that adoption id was reverted for why and that the
// journal does not hold it yet: Applied answers the intent's Execute and
// Reconcile, Unjournaled keeps it for replay and flushOwed.
func (p *Pipeline) oweLocked(id, why string) string {
	p.st.Seq++
	in := fmt.Sprintf("chg:%s:revert:n%d:%s", id, p.st.Seq, why)
	p.st.Applied[in] = true
	p.st.Unjournaled = append(p.st.Unjournaled, in)
	return in
}

// unoweLocked takes back what oweLocked added, for an effect whose save
// failed and was undone in memory.
func (p *Pipeline) unoweLocked(owed []string) {
	for _, in := range owed {
		delete(p.st.Applied, in)
		p.st.Unjournaled = slices.DeleteFunc(p.st.Unjournaled, func(s string) bool { return s == in })
	}
}

// owedIntent is the journal record of an owed revert. It is built from
// the ID alone, so a retry after a crash has the same fingerprint.
func owedIntent(id string, parts []string) journal.Intent {
	return journal.Intent{ID: id, Origin: OriginOwner, Account: journal.BrokerAccount,
		Action: ActionRevert, Executor: Executor,
		Params: map[string]any{"adoption": parts[1], "why": parts[4]}}
}

// flushOwed journals each owed revert. Execute answers it from Applied.
// One that fails stays owed and is logged by class; the next forget,
// settings revert or Attach retries it.
func (p *Pipeline) flushOwed(ctx context.Context) {
	p.flushMu.Lock()
	defer p.flushMu.Unlock()
	p.mu.Lock()
	j, owed := p.j, slices.Clone(p.st.Unjournaled)
	p.mu.Unlock()
	if j == nil {
		return
	}
	for _, id := range owed {
		parts := parseID(id)
		if len(parts) != 5 {
			continue
		}
		if err := p.run(ctx, owedIntent(id, parts)); err != nil {
			if p.cfg.Logf != nil {
				p.cfg.Logf("change: a %s revert is not journaled yet (%s)", parts[4], errClass(err))
			}
			continue
		}
		p.mu.Lock()
		p.st.Unjournaled = slices.DeleteFunc(p.st.Unjournaled, func(s string) bool { return s == id })
		if err := p.saveLocked(); err != nil && p.cfg.Logf != nil {
			// Still owed on disk: the next flush finds it journaled.
			p.cfg.Logf("change: a journaled revert is not saved as such (%s)", errClass(err))
		}
		p.mu.Unlock()
	}
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

// sealedProposal is a proposal blob as Content holds it: the body and a
// MAC over the proposal's ID and the body under a key Content never holds,
// so a rewritten or misfiled blob is not used (CHG-2, AJS-2).
type sealedProposal struct {
	Body json.RawMessage `json:"body"`
	MAC  string          `json:"mac"`
}

// proposalMAC binds body to proposal id under a key derived from the
// pipeline's secret key.
func (p *Pipeline) proposalMAC(id string, body []byte) []byte {
	k := hmac.New(sha256.New, p.key)
	k.Write([]byte("change/proposal-mac"))
	m := hmac.New(sha256.New, k.Sum(nil))
	m.Write([]byte(id))
	m.Write([]byte{0})
	m.Write(body)
	return m.Sum(nil)
}

func (p *Pipeline) putProposalLocked(id string, pr *proposal) error {
	body, err := json.Marshal(savedProposal{Cand: pr.cand, Base: pr.base, Next: pr.next, Edits: pr.edits,
		Report: pr.report, Example: pr.report.example, Classes: pr.classes, Security: pr.security})
	if err != nil {
		return err
	}
	b, err := json.Marshal(sealedProposal{Body: body, MAC: hex.EncodeToString(p.proposalMAC(id, body))})
	if err != nil {
		return err
	}
	return p.content.Put(proposalKey(id), b)
}

// dropLocked forgets proposal id, in memory and in Content. A failed
// delete is logged and kept in stray, which the next forget retries;
// replay deletes again the proposal of every intent no longer waiting
// (C23, AJS-1).
func (p *Pipeline) dropLocked(id string) {
	delete(p.props, id)
	p.deleteProposalLocked(id)
}

func (p *Pipeline) deleteProposalLocked(id string) {
	if err := p.content.Delete(proposalKey(id)); err != nil {
		if p.stray == nil {
			p.stray = map[string]bool{}
		}
		p.stray[id] = true
		if p.cfg.Logf != nil {
			p.cfg.Logf("change: proposal not deleted (%s)", errClass(err))
		}
		return
	}
	delete(p.stray, id)
}

// retryStrayLocked deletes again each proposal whose delete failed.
func (p *Pipeline) retryStrayLocked() {
	ids := make([]string, 0, len(p.stray))
	for id := range p.stray {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p.deleteProposalLocked(id)
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
				continue
			}
			// Waiting, but its blob is absent, unsealed or forged: nothing
			// can adopt it, so its bytes go now rather than outliving a
			// forget of the goal they came from (AJS-1, AJS-2).
			if p.cfg.Logf != nil {
				p.cfg.Logf("change: a waiting proposal did not load or failed its seal; dropped, propose again")
			}
			p.deleteProposalLocked(c.parts[1])
			continue
		}
		if c.in.Action == ActionAdopt && id == adoptID(c.parts[1]) {
			// No longer waiting: its candidate bytes go, even when the
			// settle's delete failed or never ran (AJS-1).
			p.deleteProposalLocked(c.parts[1])
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
			if owedRevert(a.Reverted) {
				tail[id] = a.Reverted // an earlier build's body revert
			}
			a.Reverted, a.Staged, a.Confirmed, a.WithdrawnFor = "", false, false, ""
			if legacy != nil {
				if owedRevert(legacy.Reverted) {
					// A pre-journal state's forget or settings revert:
					// the journal holds it, or it is owed below (#1995).
					tail[id] = legacy.Reverted
					legacy.Reverted = ""
				}
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
	// Owed reverts: applied and saved with their effect, not yet in the
	// journal (oweLocked). One the journal now holds was applied above.
	var owed []string
	for _, in := range p.st.Unjournaled {
		parts := parseID(in)
		if len(parts) != 5 || parts[2] != "revert" || !owedRevert(parts[4]) || byAd[parts[1]] == nil {
			continue
		}
		if st, err := j.Get(in); err == nil && st.State == journal.Succeeded {
			continue
		}
		owed = append(owed, in)
		if a := byAd[parts[1]]; a.Reverted == "" {
			a.Reverted = parts[4]
		}
	}
	resave := len(owed) != len(p.st.Unjournaled)
	p.st.Unjournaled = owed
	// A body an earlier build saved with a forget or settings revert in
	// it, top-level or in its legacy lifecycle, on an adoption the journal
	// leaves active: owe it once. Every such body is put again without it.
	var migrated []string
	owes := false
	for _, a := range ads {
		why := tail[a.ID]
		if why == "" {
			continue
		}
		if a.Reverted == "" {
			a.Reverted = why
			p.oweLocked(a.ID, why)
			owes = true
		}
		migrated = append(migrated, a.ID)
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
	// The debt is saved before a migrated body loses its revert, so a
	// crash or failed save between the two keeps the revert somewhere.
	if resave || owes {
		if err := p.saveLocked(); err != nil {
			p.brokenLocked("owed reverts not saved", err)
			return
		}
	}
	if len(migrated) > 0 {
		for _, id := range migrated {
			delete(p.lastBody, id) // put again, without the revert
		}
		if err := p.saveLocked(); err != nil {
			p.brokenLocked("migrated bodies not saved", err)
			return
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
		p.oweRevertsLocked(p.st.Adoptions, ads)
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

// loadProposalLocked reads a waiting proposal; nil when it is absent,
// unreadable, or its MAC does not bind it to id, which leaves its intent
// with nothing to adopt (Check refuses it; AJS-2).
func (p *Pipeline) loadProposalLocked(id string) *proposal {
	raw, err := p.content.Get(proposalKey(id))
	if err != nil || raw == nil {
		return nil
	}
	var sealed sealedProposal
	if err := json.Unmarshal(raw, &sealed); err != nil {
		return nil
	}
	mac, err := hex.DecodeString(sealed.MAC)
	if err != nil || !hmac.Equal(mac, p.proposalMAC(id, sealed.Body)) {
		return nil
	}
	var sp savedProposal
	if err := json.Unmarshal(sealed.Body, &sp); err != nil {
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
