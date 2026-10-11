package loopbuild

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
)

// FixSignal is a fix brief's signal: the job answers Loop 2's fix-candidate
// request for one finding (LOOP-9, P3-4b-5), not a Loop 1 hypothesis.
const FixSignal = "loop2"

// FixNS are the namespaces a fix job may write, one per job: the finding's.
// They are the namespaces a Loop 2 seed may lie in that the builder can
// write a format for; routing stays out, as for Loop 1 (C-3c-4), and
// authority and governance are never a candidate's (LOOP-10, CHG-2).
var FixNS = map[string]change.Class{
	"procedures": change.ClassProcedure,
	"skills":     change.ClassSkill,
	"context":    change.ClassContext,
	"config":     change.ClassConfig,
}

// ErrNoNamespace: the finding's regression is not a valid tree rule whose
// clauses all read one namespace in FixNS, so no job could be confined to
// it and none is run.
// It wraps loops.ErrNotFixable, so Loop 2 does not count it as a failed
// build.
var ErrNoNamespace = fmt.Errorf("loopbuild: the finding names no one namespace a fix may write: %w", loops.ErrNotFixable)

// NoModel is Unready's answer when the builder has no model route, in
// owner words: STATUS says "I cannot build one yet, because" before it.
const NoModel = "building repairs needs AI access I do not have"

var (
	_ loops.Fixer   = (*Builder)(nil)
	_ loops.Unready = (*Builder)(nil)
)

// Unready says why the builder cannot answer a fix request now, "" when it
// can: without a model route every job would end with no candidate.
func (b *Builder) Unready() string {
	if b.cfg.Model == nil {
		return NoModel
	}
	return ""
}

// Fix answers Loop 2's fix-candidate request for f (loops.Fixer). Loop 2
// hands it the finding with its minimized regression as Rule. The job's
// brief carries the finding's subject, detail and that regression, and
// nothing else from the suite; the machine is Loop 1's builder machine,
// treated as compromised (C-3c-4), and writes only in the namespace the
// regression reads, clipped. The candidate comes back unstamped: Loop 2
// stamps its source, origin and finding and clears the rest before
// Propose, and the change pipeline decides (§11, CHG-2).
func (b *Builder) Fix(ctx context.Context, f loops.Finding) (change.Candidate, error) {
	ns, class, err := fixNamespace(f.Rule)
	if err != nil {
		return change.Candidate{}, err
	}
	select {
	case b.slot <- struct{}{}:
		defer func() { <-b.slot }()
	case <-ctx.Done():
		return change.Candidate{}, ctx.Err()
	}
	brief, err := json.Marshal(Brief{Signal: FixSignal, Class: string(class), Key: f.ID, Writes: ns,
		Steps: []BriefStep{}, Cases: []BriefCase{{ID: "regression", Input: raw(f.Rule), Expect: raw([]byte(change.TreeRuleOK))}},
		Limits:  BriefLimits{Files: MaxFiles, FileBytes: MaxFileBytes, Bytes: MaxCandidateBytes},
		Subject: f.Subject, Detail: f.Detail})
	if err != nil {
		return change.Candidate{}, err
	}
	id := FixPrefix + newID()
	start := time.Now()
	files, err := b.run(ctx, id, ns, brief)
	b.logJob(id, FixSignal, start, err)
	if err != nil {
		return change.Candidate{}, err
	}
	return change.Candidate{Files: files}, nil
}

// fixNamespace is the one namespace rule's clauses read, if it is in FixNS.
func fixNamespace(rule []byte) (string, change.Class, error) {
	r, ok, err := change.ParseTreeRule(rule)
	if !ok || err != nil || r.Valid() != nil {
		return "", "", ErrNoNamespace
	}
	nss := r.Namespaces()
	if len(nss) != 1 {
		return "", "", ErrNoNamespace
	}
	class, ok := FixNS[nss[0]]
	if !ok {
		return "", "", ErrNoNamespace
	}
	return nss[0], class, nil
}
