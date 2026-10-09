package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/modelroute"
)

// The capability-off lines (OP-9, OP9-status-a): each capability that is
// off on this box for host, configuration or a held decision names itself
// in STATUS in one owner-worded line, "<capability>: <state>; <fix>.", and
// the digest repeats it while the condition lasts. Every line is computed
// from live state on each read; none is latched.
//
// The fix clauses are the brief's Q1 default (open with Mark): kept here
// so a rewording is one edit.
const (
	fixUpdate  = "nothing to do; a later box version adds it"
	fixRestart = "restart the box"
)

// The lines. Each is checked by ownerWorded in the tests.
const (
	// C1: no machine runtime on this box, so neither the agent nor worker
	// tools run.
	agentNoRuntime = "Agent and worker tools: not set up on this box; " + fixUpdate + "."
	// C1: the machine plane (machines, their disk or the guest plane)
	// did not start.
	agentNoMachines = "Agent and worker tools: off, their machines did not start; " + fixRestart + "."
	// C1: the agent's image or launch file is missing.
	agentNoSoftware = "Agent: not set up, its software is missing on this box; " + fixUpdate + "."
	// C2: no model route is configured.
	modelUnset = "Model: not set up, so the agent cannot think or learn; " + fixUpdate + "."
	// C2: the model route does not answer.
	modelUnreachable = "Model: not reachable, so the agent cannot think and learning cannot test changes; " + fixRestart + "."
	// C2: no model provider is granted (A11's no-grant cause).
	modelNoGrant = "Model: no AI plan or key is connected, so no agent can think or learn; add one on the Wi-Fi page."
	// C2: the vault is not open, so the model route serves nothing.
	modelLocked = "Model: the vault is locked, so the agent cannot think or learn; unlock it on the local page."
	// C7: no recall directory or vault verifier.
	recallOffLine = "Memory across tasks: off on this box; " + fixUpdate + "."
	// C9: the question book or the box clock did not open.
	questionsOffLine = "Questions from agents: cannot reach you, and the time check is off; " + fixRestart + "."
	// C10: the machine plane is up but no worker image is registered.
	workersOffLine = "Worker tools: not set up on this box; " + fixUpdate + "."
	// C11: no update-check loop (Loop 3) is registered.
	updateChecksOff = "Update checks: not running on this box; " + fixUpdate + "."
	// C12: learning is on but routing changes are held.
	routingHeldLine = "Routing: learning cannot change how work is routed here; " + fixUpdate + "."
)

// capLineTexts are every line the registry can show, for the wording test.
func capLineTexts() []string {
	return []string{agentNoRuntime, agentNoMachines, agentNoSoftware, modelUnset, modelUnreachable, modelNoGrant, modelLocked,
		recallOffLine, questionsOffLine, workersOffLine, updateChecksOff, routingHeldLine}
}

// capClass is why a capability is off. An owner choice (LOOPS OFF, say)
// is never a STATUS line, only a digest listing.
type capClass int

const (
	capHost capClass = iota
	capConfig
	capHeld
	capOwnerChoice
)

type capEntry struct {
	key   string
	class capClass
	line  func() string // "" while the capability is on
}

// capLines is the registry.
type capLines struct {
	entries []capEntry
}

// newCapLines registers the C1–C12 rows over s's live state.
func newCapLines(s *capState) *capLines {
	r := &capLines{}
	r.add("agent", capHost, s.agentLine)
	r.add("model", capConfig, s.modelLine)
	r.add("recall", capConfig, s.recallLine)
	r.add("questions", capHost, s.questionsLine)
	r.add("workers", capConfig, s.workersLine)
	r.add("update-checks", capHeld, s.updatesLine)
	r.add("routing", capConfig, s.routingLine)
	return r
}

func (r *capLines) add(key string, class capClass, line func() string) {
	r.entries = append(r.entries, capEntry{key: key, class: class, line: line})
}

// wire puts every entry but owner choices into STATUS's notes. Call it
// once, before daemon.Run (the daemon copies the notes), right after the
// clock note so the clock stays first.
func (r *capLines) wire(cfg *daemon.Config) {
	var notes []func() string
	for _, e := range r.entries {
		if e.class != capOwnerChoice {
			notes = append(notes, e.line)
		}
	}
	cfg.Notes = append(cfg.Notes, notes...)
}

// Digest is every current line, owner choices included.
func (r *capLines) Digest() []string {
	var out []string
	for _, e := range r.entries {
		if l := e.line(); l != "" {
			out = append(out, l)
		}
	}
	return out
}

// check is ownerWorded over the registry's current lines.
func (r *capLines) check() error {
	var errs []error
	for _, e := range r.entries {
		if l := e.line(); l != "" {
			if err := ownerWorded(l); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", e.key, err))
			}
		}
	}
	return errors.Join(errs...)
}

var flagLike = regexp.MustCompile(`(^|\s)-[a-z]`)

// notPlain is a rune STATUS's plainLine drops.
func notPlain(r rune) bool {
	return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" .,;:()-", r))
}

// ownerWorded rejects a line the owner cannot act on: over 100
// characters, not "<capability>: <state>; <fix>.", or holding a flag
// name, a path, a socket name or formatted error text.
func ownerWorded(l string) error {
	switch {
	case utf8.RuneCountInString(l) > 100:
		return errors.New("over 100 characters")
	case !strings.HasSuffix(l, "."):
		return errors.New("not a sentence")
	case strings.Count(l, ": ") != 1:
		return errors.New(`not one "<capability>: " head`)
	case strings.Contains(l, ".sock"):
		return errors.New("names a socket")
	case strings.IndexFunc(l, notPlain) >= 0:
		// STATUS drops these (control plainLine): an apostrophe would
		// vanish, and "/" or "%" mean a path or formatted error text.
		return errors.New("holds a character STATUS drops")
	case flagLike.MatchString(l):
		return errors.New("names a flag")
	}
	_, fix, ok := strings.Cut(l, "; ")
	if !ok || strings.TrimSpace(strings.TrimSuffix(fix, ".")) == "" {
		return errors.New("no fix clause")
	}
	return nil
}

// capState is the live state the lines read. main sets it as the box
// opens; the zero value of each field means "on" (no line).
type capState struct {
	agent        atomic.Pointer[string] // C1's line, nil while the agent can run
	held         atomic.Bool            // the agent line already says why it is off (lateStatus.off)
	model        *modelProbe            // C2
	recallOff    atomic.Bool            // C7
	questionsOff atomic.Bool            // C9
	workersOff   atomic.Bool            // C10
	updates      atomic.Bool            // C11: an update-check source is registered
	learn        atomic.Pointer[learning]
}

func newCapState(modelSocket string) *capState {
	return &capState{model: newModelProbe(modelSocket)}
}

// machinesUnset records C1 when no machine runtime is set. agentOff is
// the boot-time agent line (memory plan, cgroups): when set it already
// says why, and the registry adds no second agent line.
func (s *capState) machinesUnset(runsc, agentOff string) {
	s.held.Store(agentOff != "")
	if runsc == "" && agentOff == "" {
		s.agentOff(agentNoRuntime)
	}
}

// agentOff sets C1's line; "" clears it.
func (s *capState) agentOff(line string) {
	if line == "" {
		s.agent.Store(nil)
		return
	}
	s.agent.Store(&line)
}

func (s *capState) recallWired(on bool)  { s.recallOff.Store(!on) }
func (s *capState) workers(on bool)      { s.workersOff.Store(!on) }
func (s *capState) learning(l *learning) { s.learn.Store(l) }

// updateChecks registers Loop 3's source (W5b); nil means none.
func (s *capState) updateChecks(src loops.Source) { s.updates.Store(src != nil) }

func (s *capState) agentLine() string {
	if l := s.agent.Load(); l != nil && !s.held.Load() {
		return *l
	}
	return ""
}

// agentNamed reports that the registry's line names the agent, so
// lateStatus adds no second one.
func (s *capState) agentNamed() bool { return s.agentLine() != "" }

func (s *capState) modelLine() string {
	if s.model == nil {
		return ""
	}
	return s.model.Line()
}

func (s *capState) recallLine() string    { return lineIf(s.recallOff.Load(), recallOffLine) }
func (s *capState) questionsLine() string { return lineIf(s.questionsOff.Load(), questionsOffLine) }
func (s *capState) workersLine() string   { return lineIf(s.workersOff.Load(), workersOffLine) }
func (s *capState) updatesLine() string   { return lineIf(!s.updates.Load(), updateChecksOff) }
func lineIf(off bool, line string) string {
	if off {
		return line
	}
	return ""
}

// routingLine is C12: learning on, but routing changes held (no routing
// socket). With learning off or not open it says nothing.
func (s *capState) routingLine() string {
	l := s.learn.Load()
	if l == nil || l.routing != nil || !l.learningOn() {
		return ""
	}
	return routingHeldLine
}

// modelProbeEvery is how long a model-route probe is believed.
const modelProbeEvery = time.Minute

// modelProbeWait bounds one probe, which STATUS waits on.
const modelProbeWait = 3 * time.Second

// modelProbe is C2's view of the model route, asked of the vault process
// at most once a minute through modelroute's state probe (CRED-5f-mr):
// whether it answers, whether a model provider is granted, and whether
// the vault is open. agentosd dials nothing itself (ARC2); modelroute is
// its one client of the vault process's model socket. A probe that gets
// no well-formed answer reads as not reachable, never as the last state.
type modelProbe struct {
	state func(context.Context) modelroute.ModelState // nil: no model route set up
	now   func() time.Time

	mu   sync.Mutex
	at   time.Time
	line string
	done bool
}

func newModelProbe(socket string) *modelProbe {
	p := &modelProbe{now: time.Now}
	if socket != "" {
		p.state = modelroute.NewStateProbe(socket)
	}
	return p
}

// Line is C2's line, "" while the model route can serve.
func (p *modelProbe) Line() string {
	if p.state == nil {
		return modelUnset
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if now := p.now(); !p.done || now.Sub(p.at) >= modelProbeEvery {
		ctx, cancel := context.WithTimeout(context.Background(), modelProbeWait)
		p.line = modelLine(p.state(ctx))
		cancel()
		p.at, p.done = now, true
	}
	return p.line
}

// modelLine is C2's line for st. With no grant, unlocking would not help,
// so that line comes before the locked one.
func modelLine(st modelroute.ModelState) string {
	switch {
	case !st.Reachable:
		return modelUnreachable
	case !st.Granted:
		return modelNoGrant
	case !st.Open:
		return modelLocked
	}
	return ""
}

// digestSources is DIG-1's one list of what the digest repeats: the
// registry, the loop scheduler's lines when learning opened, and the
// second line's when it is configured. Nothing sends the digest yet
// (DIG-1); main logs the list's size.
type digestSources []digestSource

type digestSource struct {
	name   string
	digest func() []string
}

func newDigestSources(reg *capLines, lp *learning, line *secondLine) digestSources {
	ds := digestSources{{"capabilities", reg.Digest}}
	if lp != nil {
		ds = append(ds, digestSource{"loops", lp.sched.Digest})
	}
	if line != nil {
		ds = append(ds, digestSource{"second line", line.Digest})
	}
	return ds
}

// logCapLines logs the lines standing at start, so the box log says what
// is off without a STATUS.
func logCapLines(reg *capLines) {
	for _, l := range reg.Digest() {
		log.Printf("capability off: %s", l)
	}
}
