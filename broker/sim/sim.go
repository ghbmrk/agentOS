package sim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
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
	// MutantAckShortWrite reports a short write done: the torn prefix is
	// synced and acknowledged, and the next append glues a whole line to
	// it, which the journal can no longer read back (OP-4).
	MutantAckShortWrite Mutant = "ack-short-write"
	// MutantStopSkipsGen applies STOP to the engine without the owner
	// channel counting it, so a RESUME code texted before the STOP still
	// lifts it (CH-2, the bug d728b2b fixed).
	MutantStopSkipsGen Mutant = "stop-skips-gen"
)

// simOwner is the owner's number in every run: a synthetic number from the
// fictional 555-01xx range.
const simOwner = "+15555550100"

// Config is one simulation run.
type Config struct {
	Seed  int64
	Steps int // scheduled operations; 0 means 200
	// Judge is run on the journal the engine opened, after every boot and
	// at the end of the run. SIM-check's predicates plug in here. It is the
	// durable journal unless a sync failed during Open, when the page cache
	// may hold the cut tail the disk does not yet.
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

	// ch is the owner's text channel, built anew at every boot as the
	// daemon does; chStore is its durable state, kept across boots.
	ch      *owner.Channel
	chStore *owner.MemStore
	// acked is the highest journal seq the disk acknowledged (OP-4).
	acked uint64
	// ev counts owner texts and boots. issued is the event at which each
	// RESUME code was first texted, codes the same in order; lastStop and
	// lastBoot are the events of the latest STOP text and boot (CH-2).
	ev                 int
	issued             map[string]int
	codes              []string
	lastStop, lastBoot int
	// stopAcked: a STOP was recorded and no RESUME has lifted it since.
	stopAcked bool
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
	s.disk.written = s.ack
	s.disk.wrote = func(call string) {
		s.violate("OP-4", "%s after a failed write, before the journal was reopened", call)
	}
	s.chStore, s.issued = &owner.MemStore{}, map[string]int{}
	s.pol = &policy{s: s, grants: map[string]bool{}, stale: map[string]error{}}
	s.svc = &service{s: s, applied: map[string]int{}, keys: map[string]bool{}, took: map[string]bool{}}
	s.boot()
	for _, a := range accounts {
		s.runGrant(journal.ActionGrantChange, a)
	}
	for s.step = 1; s.step <= cfg.Steps && s.err == nil; s.step++ {
		s.op()
		s.checkHalted()
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
			// Cut or fail the records Open writes.
			if n := s.rng.Intn(3) + 1; s.rng.Intn(2) == 0 {
				s.disk.Fail(n)
			} else {
				s.disk.Arm(n)
			}
		}
		eng, err := journal.Open(s.disk, s.pol, map[string]journal.Executor{"svc": s.svc, "broker": brokerExec{s.pol}},
			func(t string) string { return t }, journal.WithClock(s.clock.Now))
		if err != nil && s.disk.Crashed() {
			s.log("crash during open")
			s.disk.PowerCut()
			continue
		}
		if err != nil && s.disk.Failed() {
			// The daemon exits and is restarted on the same page cache.
			s.log("fail during open" + errText(err))
			s.disk.Kill()
			continue
		}
		if err != nil {
			s.violate("OP-4", "the journal does not reopen: %v", err)
			return
		}
		s.disk.Disarm()
		s.eng = eng
		break
	}
	s.checkAcked()
	s.ev++
	s.lastBoot = s.ev
	ch, err := owner.New(owner.Config{Owner: simOwner, Engine: s.eng, Store: s.chStore, Rand: rngReader{s.rng},
		Now: s.clock.Now, Location: time.UTC,
		AfterFunc: func(time.Duration, func()) func() bool { return func() bool { return false } }})
	if err != nil {
		s.violate("CH-2", "the owner channel does not start: %v", err)
		return
	}
	s.ch = ch
	if s.stopAcked && !s.eng.Stopped() {
		s.violate("CH-2", "a recorded STOP did not survive the reboot")
	}
	s.checkHalted()
	intents := map[string]journal.Intent{}
	for _, st := range s.eng.List() {
		intents[st.Intent.ID] = st.Intent
	}
	s.pol.rebuild(s.eng.Trail(), intents)
	s.checkErased()
	if s.cfg.Judge != nil && s.err == nil {
		if err := s.cfg.Judge(bytes.Clone(s.disk.live)); err != nil {
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
	case r < 66:
		s.text()
	case r < 70:
		s.erase()
	case r < 72:
		if id, ok := s.pick(journal.Succeeded, journal.NotApplied, journal.Denied); ok {
			_, err := s.eng.RecordQuality(id, journal.Quality{Verdict: journal.VerdictGood, Source: "owner"})
			s.log("quality " + id + errText(err))
		}
	case r < 92:
		n := s.rng.Intn(8) + 1
		if s.rng.Intn(3) == 0 {
			s.log(fmt.Sprintf("arm fail in %d points", n))
			s.disk.Fail(n)
		} else {
			s.log(fmt.Sprintf("arm crash in %d points", n))
			s.disk.Arm(n)
		}
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
		s.stop("nested stop in " + where)
	default:
		n := s.rng.Intn(3) + 1
		if s.rng.Intn(3) == 0 {
			s.log(fmt.Sprintf("nested arm fail in %d points in %s", n, where))
			s.disk.Fail(n)
		} else {
			s.log(fmt.Sprintf("nested arm crash in %d points in %s", n, where))
			s.disk.Arm(n)
		}
	}
}

func (s *sim) resolve() {
	id, ok := s.pick(journal.OutcomeUnknown)
	if !ok {
		return
	}
	st, err := s.eng.Get(id)
	// The attempt the intent waits on: the latest, or the parked one an
	// owner's retry that did not go left behind (Status.Unclear).
	n := st.Outstanding()
	if err != nil || n == 0 {
		return
	}
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

// ack records the seq of an append the disk acknowledged.
func (s *sim) ack(line []byte) {
	var r journal.Record
	if len(line) > 9 && json.Unmarshal(line[9:], &r) == nil && r.Seq > s.acked {
		s.acked = r.Seq
	}
}

// checkAcked: OP-4. Every append the disk acknowledged is still in the
// journal the engine reopened, and readable.
func (s *sim) checkAcked() {
	recs, err := s.eng.ReadTrail()
	if err != nil {
		s.violate("OP-4", "the reopened journal does not read back: %v", err)
		return
	}
	var last uint64
	if len(recs) > 0 {
		last = recs[len(recs)-1].Seq
	}
	if last < s.acked {
		s.violate("OP-4", "acknowledged record seq %d lost; the journal ends at seq %d", s.acked, last)
	}
}

// checkHalted: OP-4. Once a journal write has failed, the engine is halted
// until it is reopened: broken or stopped, never running on.
func (s *sim) checkHalted() {
	if s.err == nil && s.disk.Failed() && !s.eng.Halted() {
		s.violate("OP-4", "the engine is not halted after a failed write")
	}
}

// codeText finds the code in the channel's RESUME challenge.
var codeText = regexp.MustCompile(`RESUME ([0-9]{6})`)

// text sends the owner a short burst of STOP and RESUME texts, as a person
// does, sometimes minutes after the last burst, so codes expire and the
// hourly limits refill. A burst can hold STOP, RESUME, STOP, RESUME <code>
// with no reboot between: the order a stale challenge needs.
func (s *sim) text() {
	if s.rng.Intn(2) == 0 {
		s.clock.Advance(time.Duration(s.rng.Intn(20)) * time.Minute)
	}
	for n := 1 + s.rng.Intn(4); n > 0 && s.err == nil && !s.disk.Crashed(); n-- {
		switch r := s.rng.Intn(10); {
		case r < 3:
			s.stop("")
		case r < 6 || len(s.codes) == 0:
			s.send("RESUME")
		default:
			// A code from any challenge so far: the latest is the one that
			// should work, the rest must not.
			c := s.codes[len(s.codes)-1]
			if s.rng.Intn(2) == 0 {
				c = s.codes[s.rng.Intn(len(s.codes))]
			}
			s.send("RESUME " + c)
		}
	}
}

// stop sends STOP in one of the forms the channel accepts.
func (s *sim) stop(note string) {
	text := []string{"STOP", "stop", fmt.Sprintf("STOP %06d", s.rng.Intn(1_000_000))}[s.rng.Intn(3)]
	if note != "" {
		s.log(note)
	}
	acked := false
	if s.cfg.Mutant == MutantStopSkipsGen {
		s.ev++
		s.lastStop = s.ev
		_, err := s.eng.Stop(s.ctx)
		s.log(fmt.Sprintf("text %q -> engine stop%s", text, errText(err)))
		acked = err == nil
	} else {
		out := s.send(text)
		s.lastStop = s.ev
		acked = len(out) > 0 && strings.HasPrefix(out[0], "Stopped.")
	}
	if acked {
		// The owner was told "Stopped.": that must hold across a restart.
		s.stopAcked = true
	}
}

// send hands the channel one owner text and checks CH-2: a RESUME lifts
// STOP only with a code texted after the latest STOP and the latest boot.
func (s *sim) send(text string) []string {
	s.ev++
	was := s.eng.Stopped()
	out := s.ch.Handle(s.ctx, simOwner, text)
	s.log(fmt.Sprintf("text %q -> %q", text, strings.Join(out, " | ")))
	for _, o := range out {
		if m := codeText.FindStringSubmatch(o); m != nil {
			if _, ok := s.issued[m[1]]; !ok {
				s.issued[m[1]] = s.ev
				s.codes = append(s.codes, m[1])
			}
		}
	}
	if len(out) > 0 && strings.HasPrefix(out[0], "RESUME failed to record") {
		// The RESUME record may have reached the page cache, so a restart
		// can bring it back (see ASSUMPTIONS A9).
		s.stopAcked = false
	}
	if !was || s.eng.Stopped() {
		return out
	}
	s.stopAcked = false
	code := strings.TrimSpace(strings.TrimPrefix(text, "RESUME"))
	at, ok := s.issued[code]
	if !ok || at <= s.lastStop || at <= s.lastBoot {
		s.violate("CH-2", "%q lifted STOP with a code not texted since the latest STOP and boot", text)
	}
	return out
}

// rngReader feeds the channel's codes from the seed.
type rngReader struct{ r *rand.Rand }

func (r rngReader) Read(p []byte) (int, error) { return r.r.Read(p) }

func errText(err error) string {
	if err == nil {
		return ""
	}
	return " (" + strings.TrimPrefix(err.Error(), "journal: ") + ")"
}
