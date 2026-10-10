package sim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Mutant reintroduces a known class of bug, so tests can show the sweep
// finds it. The empty Mutant is the real system.
type Mutant string

const (
	// MutantNoRecheck skips the authority recheck at dispatch (OP-3).
	MutantNoRecheck Mutant = "no-recheck"
	// MutantStaleRecheck answers the engine's second check, made because
	// something was journaled during the first, with the first decision:
	// as if the engine's e.seq guard were gone (OP-3).
	MutantStaleRecheck Mutant = "stale-recheck"
	// MutantSkipFsync acknowledges an append before it is durable (OP-4).
	MutantSkipFsync Mutant = "skip-fsync"
	// MutantTornErase acknowledges the erase rewrite before the directory
	// holding the renamed file is synced, so a power cut can bring the
	// erased content back (CAP-3).
	MutantTornErase Mutant = "torn-erase"
)

// Config is one simulation run.
type Config struct {
	Seed  int64
	Steps int // scheduled operations; 0 means 200
	// Judge is run on the durable journal after every boot and at the end
	// of the run. SIM-check's predicates plug in here.
	Judge  func(journal []byte) error
	Mutant Mutant
}

// Result is what a run leaves behind. The same Config always gives the
// same Result, byte for byte.
type Result struct {
	Journal []byte   // the durable journal at the end of the run
	Trace   []string // one line per scheduled operation and fault
	Err     error    // the first violation, or nil
}

// Violation is a broken invariant, located by seed and step so it replays.
type Violation struct {
	Seed   int64
	Step   int
	Rule   string // a SPEC requirement ID, or "judge"
	Detail string
}

func (v *Violation) Error() string {
	return fmt.Sprintf("seed %d step %d: %s: %s", v.Seed, v.Step, v.Rule, v.Detail)
}

var accounts = []string{"mail", "bank"}

type sim struct {
	cfg   Config
	rng   *rand.Rand
	clock *Clock
	disk  *Disk
	pol   *policy
	svc   *service
	eng   *journal.Engine
	ctx   context.Context
	next  int
	step  int
	depth int
	trace []string
	err   error
}

// Run drives the real journal engine through Config.Steps operations chosen
// by the seed, with crashes cut at write, fsync, rename and directory-sync
// points, and checks it against the fake world after every step.
func Run(cfg Config) Result {
	if cfg.Steps == 0 {
		cfg.Steps = 200
	}
	s := &sim{cfg: cfg, rng: rand.New(rand.NewSource(cfg.Seed)), clock: &Clock{t: epoch}, ctx: context.Background()}
	s.disk = newDisk(s.rng, cfg.Mutant, s.log)
	s.pol = &policy{s: s, grants: map[string]bool{}, stale: map[string]error{}}
	s.svc = &service{s: s, applied: map[string]int{}, keys: map[string]bool{}, took: map[string]bool{}}
	s.boot()
	for _, a := range accounts {
		s.runGrant(journal.ActionGrantChange, a)
	}
	for s.step = 1; s.step <= cfg.Steps && s.err == nil; s.step++ {
		s.op()
		if s.disk.Crashed() && s.err == nil {
			s.reboot()
		}
	}
	if s.err == nil {
		s.step = cfg.Steps + 1
		s.log("end: power cut and reopen")
		s.disk.PowerCut()
		s.boot()
	}
	return Result{Journal: s.disk.Durable(), Trace: s.trace, Err: s.err}
}

func (s *sim) log(line string) {
	s.trace = append(s.trace, fmt.Sprintf("%03d %s", s.step, line))
}

func (s *sim) violate(rule, format string, args ...any) {
	if s.err == nil {
		s.err = &Violation{Seed: s.cfg.Seed, Step: s.step, Rule: rule, Detail: fmt.Sprintf(format, args...)}
		s.log("VIOLATION " + s.err.Error())
	}
}

func (s *sim) reboot() {
	if s.rng.Intn(2) == 0 {
		s.log("reboot power")
		s.disk.PowerCut()
	} else {
		s.log("reboot kill")
		s.disk.Kill()
	}
	s.boot()
}

// boot opens the engine on the disk as the daemon does at start, rebuilds
// the grant projection, and checks the journal.
func (s *sim) boot() {
	for try := 0; ; try++ {
		s.disk.open()
		if try < 3 && s.rng.Intn(4) == 0 {
			s.disk.Arm(s.rng.Intn(3) + 1) // cut the records Open writes
		}
		eng, err := journal.Open(s.disk, s.pol, map[string]journal.Executor{"svc": s.svc, "broker": brokerExec{s.pol}},
			func(t string) string { return t }, journal.WithClock(s.clock.Now))
		if err != nil && s.disk.Crashed() {
			s.log("crash during open")
			s.disk.PowerCut()
			continue
		}
		if err != nil {
			s.violate("OP-4", "the journal does not reopen: %v", err)
			return
		}
		s.disk.Arm(0)
		s.eng = eng
		break
	}
	intents := map[string]journal.Intent{}
	for _, st := range s.eng.List() {
		intents[st.Intent.ID] = st.Intent
	}
	s.pol.rebuild(s.eng.Trail(), intents)
	s.checkErased()
	if s.cfg.Judge != nil && s.err == nil {
		if err := s.cfg.Judge(s.disk.Durable()); err != nil {
			s.violate("judge", "%v", err)
		}
	}
}

// op runs one scheduled operation.
func (s *sim) op() {
	s.clock.Advance(time.Duration(s.rng.Intn(5000)) * time.Millisecond)
	switch r := s.rng.Intn(100); {
	case r < 14:
		s.submitEffect()
	case r < 18:
		action := journal.ActionGrantChange
		if s.rng.Intn(2) == 0 {
			action = journal.ActionGrantRevoke
		}
		s.submit(grantIntent(s.newID("g"), action, accounts[s.rng.Intn(len(accounts))]))
	case r < 32:
		if id, ok := s.pick(journal.Pending); ok {
			st, err := s.eng.Authorize(s.ctx, id)
			s.log(fmt.Sprintf("authorize %s -> %s%s", id, st.State, errText(err)))
		}
	case r < 52:
		if id, ok := s.pick(journal.Authorized, journal.NotApplied); ok {
			s.dispatch(id)
		}
	case r < 57:
		rep := s.eng.Reconcile(s.ctx)
		s.log(fmt.Sprintf("reconcile %+v", rep))
	case r < 61:
		s.resolve()
	case r < 63:
		_, err := s.eng.Stop(s.ctx)
		s.log("stop" + errText(err))
	case r < 66:
		s.log("resume" + errText(s.eng.Resume()))
	case r < 70:
		s.erase()
	case r < 72:
		if id, ok := s.pick(journal.Succeeded, journal.NotApplied, journal.Denied); ok {
			_, err := s.eng.RecordQuality(id, journal.Quality{Verdict: journal.VerdictGood, Source: "owner"})
			s.log("quality " + id + errText(err))
		}
	case r < 92:
		n := s.rng.Intn(8) + 1
		s.log(fmt.Sprintf("arm crash in %d points", n))
		s.disk.Arm(n)
	case r < 96:
		s.log("reboot kill")
		s.disk.Kill()
		s.boot()
	default:
		s.log("reboot power")
		s.disk.PowerCut()
		s.boot()
	}
}

func (s *sim) newID(prefix string) string {
	s.next++
	return fmt.Sprintf("%s%d", prefix, s.next)
}

// marker is the content an effect intent carries, so CAP-3 can look for it
// in the bytes on disk.
func marker(id string) string { return "body-" + id + "-z" }

func (s *sim) submitEffect() {
	id := s.newID("e")
	origin := "owner"
	if s.rng.Intn(2) == 0 {
		origin = "guest:agent"
	}
	s.submit(journal.Intent{ID: id, Origin: origin, Account: accounts[s.rng.Intn(len(accounts))],
		Action: "send", Params: map[string]any{"body": marker(id)}, Executor: "svc"})
}

func grantIntent(id, action, target string) journal.Intent {
	return journal.Intent{ID: id, Origin: "owner", Account: journal.BrokerAccount, Action: action,
		Params: map[string]any{"target": target}, Executor: "broker"}
}

func (s *sim) submit(in journal.Intent) {
	st, err := s.eng.Submit(in)
	s.log(fmt.Sprintf("submit %s %s %s -> %s%s", in.ID, in.Account, in.Action, st.State, errText(err)))
}

func (s *sim) dispatch(id string) {
	delete(s.pol.stale, id)
	st, err := s.eng.Dispatch(s.ctx, id)
	state := string(st.State)
	if errors.Is(err, journal.ErrRecheck) {
		state = "recheck_failed"
	}
	s.log(fmt.Sprintf("dispatch %s -> %s%s", id, state, errText(err)))
}

// runGrant takes a grant change through its whole lifecycle at once, as
// the owner's command does.
func (s *sim) runGrant(action, target string) {
	in := grantIntent(s.newID("g"), action, target)
	s.submit(in)
	st, err := s.eng.Authorize(s.ctx, in.ID)
	s.log(fmt.Sprintf("authorize %s -> %s%s", in.ID, st.State, errText(err)))
	s.dispatch(in.ID)
}

// interleave runs another operation where the engine has let go of its
// lock (inside a policy check or an executor call), which is where real
// concurrency can reach it. It nests one level deep.
func (s *sim) interleave(where string) {
	if s.depth > 0 || s.err != nil || s.rng.Intn(5) != 0 {
		return
	}
	s.depth++
	defer func() { s.depth-- }()
	switch s.rng.Intn(4) {
	case 0, 1:
		s.log("nested revoke in " + where)
		s.runGrant(journal.ActionGrantRevoke, accounts[s.rng.Intn(len(accounts))])
	case 2:
		_, err := s.eng.Stop(s.ctx)
		s.log("nested stop in " + where + errText(err))
	default:
		n := s.rng.Intn(3) + 1
		s.log(fmt.Sprintf("nested arm crash in %d points in %s", n, where))
		s.disk.Arm(n)
	}
}

func (s *sim) resolve() {
	id, ok := s.pick(journal.OutcomeUnknown)
	if !ok {
		return
	}
	st, err := s.eng.Get(id)
	if err != nil || len(st.Attempts) == 0 {
		return
	}
	n := st.Attempts[len(st.Attempts)-1].N
	out := journal.Outcome{Result: journal.ResultNotApplied, Evidence: "owner checked"}
	if st.Intent.Account != journal.BrokerAccount {
		out.Result = s.svc.truth(id, n)
	}
	st, err = s.eng.Resolve(id, n, out, "owner")
	if err == nil {
		s.log(fmt.Sprintf("resolve ok %s#%d -> %s", id, n, st.State))
	} else {
		s.log(fmt.Sprintf("resolve %s#%d%s", id, n, errText(err)))
	}
}

func (s *sim) erase() {
	var ids []string
	for _, st := range s.eng.List() {
		if st.Intent.Account != journal.BrokerAccount && s.rng.Intn(3) == 0 {
			ids = append(ids, st.Intent.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	erased, held, err := s.eng.Erase(ids)
	if err != nil {
		s.log(fmt.Sprintf("erase %v%s", ids, errText(err)))
		return
	}
	s.log(fmt.Sprintf("erase ok %v held %v", erased, held))
	s.checkErased()
}

// checkErased: CAP-3. Once an erase is acknowledged, or the engine has
// opened, no erased intent's content is on disk, live or durable.
func (s *sim) checkErased() {
	for _, id := range s.eng.Erased() {
		m := []byte(marker(id))
		if bytes.Contains(s.disk.live, m) || bytes.Contains(s.disk.durable, m) {
			s.violate("CAP-3", "erased %s is still on disk", id)
			return
		}
	}
}

// pick returns a random intent in one of the given states.
func (s *sim) pick(states ...journal.State) (string, bool) {
	var ids []string
	for _, st := range s.eng.List() {
		for _, want := range states {
			if st.State == want {
				ids = append(ids, st.Intent.ID)
			}
		}
	}
	if len(ids) == 0 {
		return "", false
	}
	return ids[s.rng.Intn(len(ids))], true
}

// durablyDispatched reports whether the durable journal holds the
// dispatched record for one attempt.
func (s *sim) durablyDispatched(id string, n int) bool {
	for _, line := range bytes.Split(s.disk.durable, []byte("\n")) {
		if len(line) < 10 {
			continue
		}
		var r journal.Record
		if json.Unmarshal(line[9:], &r) == nil && r.Type == journal.RecDispatched && r.ID == id && r.Attempt == n {
			return true
		}
	}
	return false
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return " (" + strings.TrimPrefix(err.Error(), "journal: ") + ")"
}
