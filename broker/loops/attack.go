package loops

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Loop 2's active testing from inside the sandbox (LOOP-7). A Probe attacks
// the box's own code with no more authority than a guest has: the socket
// fuzzer speaks only through one experiment machine's own socket, and the
// canary hunt reruns the A5 test with fresh synthetic canaries. Nothing here
// dials a network address or touches anything outside the box (A1, S10).
// What a probe finds is handled like any Loop 2 finding (LOOP-9): contain,
// preserve evidence, add the minimized reproducer to the security suite,
// propose a fix, tell the owner.

// CheckActive marks a finding from an active probe.
const CheckActive Check = "active"

// Probe is one active self-test.
type Probe interface {
	// Name is a fixed word naming the probe ("guest-socket", "canary-hunt").
	Name() string
	// Run attacks for at most rounds attempts and returns what it found,
	// each with a minimized reproducer. It must return soon after ctx is
	// cancelled. An error means the probe could not run as a test, which
	// is never reported as passing.
	Run(ctx context.Context, rounds int) ([]Hit, error)
	// Replay runs one reproducer and returns the oracle that fires, or ""
	// when none does. The guard uses it to tell whether an open finding
	// persists.
	Replay(ctx context.Context, h Hit) (oracle string, err error)
}

// Hit is one thing a probe found.
type Hit struct {
	// Subject narrows the probe: a canary target's name, or "" for the
	// probe as a whole.
	Subject string `json:"subject,omitempty"`
	// Oracle is the fixed word for what broke ("canary", "no-reply",
	// "hang", "bad-reply", "down", "leak").
	Oracle string `json:"oracle"`
	// Input is the minimized reproducer: bytes the probe generated, never
	// anything it read back from its target (so never a canary value).
	Input []byte `json:"input,omitempty"`
	// Contain is what to pause while the finding is open.
	Contain *Target `json:"-"`
}

// activeFinding turns a hit into a Loop 2 finding. Its ID names the probe,
// subject and oracle, not the input: the same weakness found again through
// another input is the same finding.
func activeFinding(probe string, h Hit) Finding {
	subject := probe
	if h.Subject != "" {
		subject += "/" + h.Subject
	}
	return Finding{
		ID:       findingID(CheckActive, subject, h.Oracle),
		Check:    CheckActive,
		Subject:  subject,
		Detail:   h.Oracle,
		Severity: High,
		Contain:  h.Contain,
		Rule: fixtureInput(FixtureRule{Check: CheckActive, Subject: probe,
			Target: h.Subject, Oracle: h.Oracle, Input: h.Input}),
	}
}

func (s *Guard) probe(name string) Probe {
	for _, p := range s.cfg.Probes {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// Active runs every probe once (LOOP-7) and handles each new finding
// (LOOP-9). Open active findings are first replayed from their stored
// reproducer: one that no longer fires is cleared, one that does stays open
// and is not handled again. It returns how many findings were new.
func (s *Guard) Active(ctx context.Context) (int, error) {
	s.mu.Lock()
	open := map[string]Record{}
	for id, r := range s.st.Open {
		if r.Finding.Check == CheckActive {
			open[id] = r
		}
	}
	s.mu.Unlock()

	var errs []error
	var notes []string
	var found []Finding
	// Replay what is open. A probe that is gone or errs keeps its finding
	// open: fail closed.
	for _, r := range open {
		rule, err := readRule(r.Finding.Rule)
		p := s.probe(rule.Subject)
		if err != nil || p == nil {
			found = append(found, r.Finding)
			continue
		}
		h := Hit{Subject: rule.Target, Oracle: rule.Oracle, Input: rule.Input}
		if o, err := p.Replay(ctx, h); err != nil || o != "" {
			found = append(found, r.Finding)
		}
	}
	for _, p := range s.cfg.Probes {
		if ctx.Err() != nil {
			break
		}
		hits, err := p.Run(ctx, s.cfg.Rounds)
		if err != nil && ctx.Err() == nil {
			notes = append(notes, safeName(p.Name()))
			errs = append(errs, fmt.Errorf("probe %s: %w", p.Name(), err))
		}
		for _, h := range hits {
			found = append(found, activeFinding(p.Name(), h))
		}
	}
	if ctx.Err() != nil {
		// Preempted: not measured, nothing cleared, offered again (L4).
		return 0, ctx.Err()
	}
	sort.Strings(notes)
	s.mu.Lock()
	s.probeNotes, s.forceActive = notes, false
	s.st.LastActive = s.cfg.Now()
	fresh := s.observeLocked(found, func(f Finding) bool { return f.Check == CheckActive })
	s.mu.Unlock()
	for _, f := range fresh {
		if err := s.handle(ctx, f); err != nil {
			errs = append(errs, err)
		}
	}
	s.mu.Lock()
	err := s.saveLocked()
	s.mu.Unlock()
	return len(fresh), errors.Join(append(errs, err)...)
}

// observeLocked records which findings in scope are still observed and
// returns the new ones, once each. Open findings in scope that were not
// observed are cleared; their evidence stays.
func (s *Guard) observeLocked(found []Finding, scope func(Finding) bool) []Finding {
	seen := map[string]bool{}
	var fresh []Finding
	for _, f := range found {
		if seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		if _, open := s.st.Open[f.ID]; !open {
			fresh = append(fresh, f)
		}
	}
	for id, r := range s.st.Open {
		if scope(r.Finding) && !seen[id] {
			delete(s.st.Open, id)
		}
	}
	return fresh
}

// canaryForms are the encodings of a planted value a reply is scanned for.
func canaryForms(v string) []string {
	return []string{v, jsonEscaped(v), hex.EncodeToString([]byte(v)),
		base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v))}
}

func jsonEscaped(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '<' || r == '>' || r == '&' || r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
