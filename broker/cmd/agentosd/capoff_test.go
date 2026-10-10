package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/localui"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: OP-9

const clockNoteForTest = "Time check: clock note."

// capBox is a broker wired as agentosd wires the registry: the clock note
// first, then the registry, then whatever the test adds, with the agent
// line read through lateStatus.
type capBox struct {
	t      *testing.T
	dir    string
	cfg    daemon.Config
	caps   *capState
	reg    *capLines
	agent  *lateStatus
	d      *daemon.Daemon
	ctx    context.Context
	cancel context.CancelFunc
}

func newCapBox(t *testing.T) *capBox { return newCapBoxWith(t, nil) }

// newCapBoxWith lets add register more entries before the registry is
// wired.
func newCapBoxWith(t *testing.T, add func(*capLines)) *capBox {
	t.Helper()
	dir := t.TempDir()
	b := &capBox{t: t, dir: dir, caps: newCapState(""), agent: &lateStatus{}}
	b.cfg = daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	// A model route that answers, so only the case under test is off.
	b.caps.model = reachableModel(t)
	b.caps.updateChecks(stubUpdates{})
	b.cfg.Notes = []func() string{func() string { return clockNoteForTest }}
	b.reg = newCapLines(b.caps)
	if add != nil {
		add(b.reg)
	}
	b.reg.wire(&b.cfg)
	b.agent.caps = b.caps
	b.cfg.AgentStatus = b.agent.Status
	return b
}

// run starts the daemon; call it once every note is wired.
func (b *capBox) run() {
	b.t.Helper()
	b.ctx, b.cancel = context.WithCancel(context.Background())
	d, err := daemon.Run(b.ctx, b.cfg)
	if err != nil {
		b.t.Fatal(err)
	}
	b.d = d
	b.t.Cleanup(func() { b.cancel(); d.Wait() })
}

// status is STATUS as the owner reads it (control.Handler.Status).
func (b *capBox) status() string {
	// As daemon.Run wires it: the agent line, else the admission summary.
	machines := func() string {
		if l := b.cfg.AgentStatus(); l != "" {
			return l
		}
		return b.d.Admission().Summary()
	}
	h := &control.Handler{Engine: b.d.Engine(), Machines: machines, Notes: b.cfg.Notes}
	return h.Status()
}

// reachableModel is a model route whose vault process answers: granted
// and open.
func reachableModel(t *testing.T) *modelProbe {
	t.Helper()
	return newModelProbe(serveFakeVault(t, filepath.Join(shortDir(t), "m.sock"), modelOn).sock)
}

var modelOn = modelroute.ModelState{Granted: true, Open: true}

// fakeVault stands in for the vault process on its model socket: it
// answers the broker's state probe with st. Stopping it leaves the socket
// file behind, as a vault process that stopped answering does.
type fakeVault struct {
	sock string
	st   atomic.Pointer[modelroute.ModelState]
	srv  *http.Server
}

func serveFakeVault(t *testing.T, sock string, st modelroute.ModelState) *fakeVault {
	t.Helper()
	f := &fakeVault{sock: sock}
	f.set(st)
	f.start(t)
	return f
}

func (f *fakeVault) set(st modelroute.ModelState) { f.st.Store(&st) }

func (f *fakeVault) start(t *testing.T) {
	t.Helper()
	os.Remove(f.sock)
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	f.srv = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(modelroute.HeaderState) == "" {
			http.Error(w, "not a state request", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(f.st.Load())
	})}
	go f.srv.Serve(ln)
	t.Cleanup(func() { f.srv.Close() })
}

// stop stops answering; the socket file stays.
func (f *fakeVault) stop() { f.srv.Close() }

// staleModel is a model route whose socket file is there with nothing
// answering.
func staleModel(t *testing.T) *modelProbe {
	t.Helper()
	f := serveFakeVault(t, filepath.Join(shortDir(t), "m.sock"), modelOn)
	f.stop()
	if _, err := os.Stat(f.sock); err != nil {
		t.Fatal(err)
	}
	return newModelProbe(f.sock)
}

// modelWith is a model route whose vault process answers st.
func modelWith(t *testing.T, st modelroute.ModelState) *modelProbe {
	t.Helper()
	return newModelProbe(serveFakeVault(t, filepath.Join(shortDir(t), "m.sock"), st).sock)
}

// shortDir is a temporary directory short enough for a socket path.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "cap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// stubUpdates stands in for maintain.Loop3 once W5b constructs it.
type stubUpdates struct{}

func (stubUpdates) Loop() loops.Loop { return loops.Maintain }
func (stubUpdates) Next(context.Context, bool) (loops.Job, bool) {
	return loops.Job{}, false
}

// capCase is one capability-off case: induce turns it on in b, and name
// is the words its line starts with.
type capCase struct {
	row, name string
	learn     bool // needs the learning plane open
	induce    func(t *testing.T, b *capBox)
	clear     func(t *testing.T, b *capBox) // nil: holds for the process's life
}

func capCases() []capCase {
	return []capCase{
		{row: "C1_runsc_empty", name: "Agent and worker tools:", induce: func(t *testing.T, b *capBox) {
			b.caps.machinesUnset("", "")
		}},
		{row: "C1_vm_open_fails", name: "Agent and worker tools:", induce: func(t *testing.T, b *capBox) {
			b.caps.agentOff(agentNoMachines)
		}},
		{row: "C1_guest_plane_fails", name: "Agent and worker tools:", induce: func(t *testing.T, b *capBox) {
			b.caps.agentOff(agentNoMachines)
		}},
		{row: "C1_image_missing", name: "Agent software:", induce: func(t *testing.T, b *capBox) {
			_, err := agentSpec(images{}, "openclaw", filepath.Join(b.dir, "launch.json"), defaultAgentMemMB)
			if err == nil {
				t.Fatal("an unregistered agent image gave a spec")
			}
			b.caps.agentOff(agentNoSoftware)
		}},
		{row: "C2_model_unset", name: "Model:", induce: func(t *testing.T, b *capBox) {
			b.caps.model = newModelProbe("")
		}},
		{row: "C2_model_unreachable", name: "Model:", induce: func(t *testing.T, b *capBox) {
			b.caps.model = newModelProbe(filepath.Join(shortDir(t), "gone.sock"))
		}},
		{row: "C2_model_stale_socket", name: "Model:", induce: func(t *testing.T, b *capBox) {
			b.caps.model = staleModel(t)
		}},
		{row: "C2_model_no_grant", name: "Model:", induce: func(t *testing.T, b *capBox) {
			b.caps.model = modelWith(t, modelroute.ModelState{Open: true})
		}},
		{row: "C2_model_locked", name: "Model:", induce: func(t *testing.T, b *capBox) {
			b.caps.model = modelWith(t, modelroute.ModelState{Granted: true})
		}},
		{row: "C7_recall_off", name: "Memory across tasks:", induce: func(t *testing.T, b *capBox) {
			b.caps.recallWired(false)
		}},
		{row: "C9_questions_failed", name: "Questions from agents:", induce: func(t *testing.T, b *capBox) {
			// A question book whose state is a directory does not load.
			qs := &questions{}
			qs.start(b.ctx, b.d, &preempter{}, questionConfig{Path: b.dir, ClockPath: filepath.Join(b.dir, "clock.json")}, b.caps)
			if qs.b.Load() != nil {
				t.Fatal("the questions plane opened")
			}
		}},
		{row: "C10_worker_image_empty", name: "Worker tools:", induce: func(t *testing.T, b *capBox) {
			b.caps.workers(workerTools(nil, images{}, "", "sleep infinity", 2048, workerGates{}) != nil)
		}},
		{row: "C10_worker_image_unregistered", name: "Worker tools:", induce: func(t *testing.T, b *capBox) {
			b.caps.workers(workerTools(nil, images{"other": "/x"}, "worker", "sleep infinity", 2048, workerGates{}) != nil)
		}},
		{row: "C11_update_checks", name: "Update checks:", induce: func(t *testing.T, b *capBox) {
			b.caps.updateChecks(nil)
		}, clear: func(t *testing.T, b *capBox) {
			b.caps.updateChecks(stubUpdates{})
		}},
		{row: "C12_routing_held", name: "Routing:", learn: true, induce: func(t *testing.T, b *capBox) {
			// Opened with no routing socket: routing changes are held.
		}, clear: func(t *testing.T, b *capBox) {
			if got, ok := b.cfg.Settings(b.ctx, "LEARNING OFF", true); !ok {
				t.Fatalf("LEARNING OFF: %q", got)
			}
		}},
	}
}

// openCapLearning opens the learning plane on b with no routing socket.
func openCapLearning(t *testing.T, b *capBox) *learning {
	t.Helper()
	lp, err := openLearning(learnPaths{Dir: b.dir, Spare: filepath.Join(b.dir, "spare.json")}, true, &b.cfg)
	if err != nil {
		t.Fatal(err)
	}
	b.caps.learning(lp)
	return lp
}

// startCapBox opens what c needs and runs the daemon.
func startCapBox(t *testing.T, c capCase) *capBox {
	b := newCapBox(t)
	var lp *learning
	if c.learn {
		lp = openCapLearning(t, b)
	}
	b.run()
	if lp != nil {
		attachForTest(t, lp, b.ctx, b.cancel, b.d)
	}
	return b
}

// linesNaming are STATUS's sentences that start with name.
func linesNaming(status, name string) int { return strings.Count(status, name) }

// OP-9: each capability that is off for host, configuration or a held
// decision has exactly one owner-worded STATUS line, ≤100 characters, with
// what would fix it; with the condition absent, no such line.
func TestEveryOffCapabilityHasOneStatusLine(t *testing.T) {
	for _, c := range capCases() {
		t.Run(c.row, func(t *testing.T) {
			b := startCapBox(t, c)
			if c.learn {
				// Learning opened: the line stands from the start.
			} else {
				s := b.status()
				for _, l := range capLineTexts() {
					if strings.Contains(s, l) {
						t.Fatalf("condition absent, %q in %q", l, s)
					}
				}
			}
			c.induce(t, b)
			s := b.status()
			if n := linesNaming(s, c.name); n != 1 {
				t.Fatalf("%d %q lines in %q", n, c.name, s)
			}
			line := b.lineFor(c.name)
			if err := ownerWorded(line); err != nil {
				t.Errorf("%q: %v", line, err)
			}
			if !strings.Contains(s, line) {
				t.Errorf("STATUS %q lacks %q", s, line)
			}
			if strings.HasPrefix(c.name, "Agent") && strings.Contains(s, agentNotSet) {
				t.Errorf("a second agent line: %q", s)
			}
			if c.clear != nil {
				c.clear(t, b)
				if n := linesNaming(b.status(), c.name); n != 0 {
					t.Errorf("cleared, still %q", b.status())
				}
			}
		})
	}
}

// lineFor is the registry's current line that starts with name.
func (b *capBox) lineFor(name string) string {
	for _, l := range b.reg.Digest() {
		if strings.HasPrefix(l, name) {
			return l
		}
	}
	b.t.Fatalf("no registry line for %q in %q", name, b.reg.Digest())
	return ""
}

// OP-9 (digest): each line is in the registry's Digest while its
// condition holds and gone from the next Digest after it clears.
func TestCapabilityLinesRepeatInTheDigestWhileTheyLast(t *testing.T) {
	inDigest := func(b *capBox, name string) int {
		n := 0
		for _, l := range b.reg.Digest() {
			if strings.HasPrefix(l, name) {
				n++
			}
		}
		return n
	}
	for _, c := range capCases() {
		t.Run(c.row, func(t *testing.T) {
			b := startCapBox(t, c)
			c.induce(t, b)
			for range 2 { // every digest, not once
				if n := inDigest(b, c.name); n != 1 {
					t.Fatalf("%d %q lines in %q", n, c.name, b.reg.Digest())
				}
			}
			if c.clear != nil {
				c.clear(t, b)
				if n := inDigest(b, c.name); n != 0 {
					t.Fatalf("cleared, digest still %q", b.reg.Digest())
				}
			}
		})
	}
	// C2: the model socket comes back; the next probe, at most a minute
	// on, drops the line.
	t.Run("C2_socket_comes_back", func(t *testing.T) {
		sock := filepath.Join(shortDir(t), "m.sock")
		now := time.Unix(1_800_000_000, 0)
		p := newModelProbe(sock)
		p.now = func() time.Time { return now }
		caps := newCapState("")
		caps.model = p
		caps.updateChecks(stubUpdates{})
		reg := newCapLines(caps)
		if d := reg.Digest(); len(d) != 1 || d[0] != modelUnreachable {
			t.Fatalf("socket down: %q", d)
		}
		serveFakeVault(t, sock, modelOn)
		now = now.Add(modelProbeEvery)
		if d := reg.Digest(); len(d) != 0 {
			t.Fatalf("socket back: %q", d)
		}
	})
	// C1, C7, C9 and C10 hold for the process's life; clearing their
	// state clears the line all the same (computed live, never latched).
	t.Run("live_not_latched", func(t *testing.T) {
		caps := newCapState("")
		caps.model = reachableModel(t)
		caps.updateChecks(stubUpdates{})
		reg := newCapLines(caps)
		caps.agentOff(agentNoSoftware)
		caps.recallWired(false)
		caps.questionsOff.Store(true)
		caps.workers(false)
		if d := reg.Digest(); len(d) != 4 {
			t.Fatalf("held: %q", d)
		}
		caps.agentOff("")
		caps.recallWired(true)
		caps.questionsOff.Store(false)
		caps.workers(true)
		if d := reg.Digest(); len(d) != 0 {
			t.Fatalf("cleared: %q", d)
		}
	})
}

// OP-9: the model probe is cached at most a minute, so STATUS does not
// ask the vault process on every text, and is not stale for longer.
func TestModelProbeIsCachedAMinute(t *testing.T) {
	f := serveFakeVault(t, filepath.Join(shortDir(t), "m.sock"), modelOn)
	now := time.Unix(1_800_000_000, 0)
	p := newModelProbe(f.sock)
	p.now = func() time.Time { return now }
	if l := p.Line(); l != "" {
		t.Fatalf("reachable: %q", l)
	}
	f.stop()
	now = now.Add(modelProbeEvery - time.Second)
	if l := p.Line(); l != "" {
		t.Fatalf("within the minute: %q", l)
	}
	now = now.Add(time.Second)
	if l := p.Line(); l != modelUnreachable {
		t.Fatalf("after the minute: %q", l)
	}
}

// OP-9: the registry is in STATUS when the learning plane failed to open,
// and its Digest still returns lines then.
func TestCapabilityLinesWithoutTheLearningPlane(t *testing.T) {
	b := newCapBox(t)
	learningOff(&b.cfg)
	b.caps.recallWired(false)
	b.caps.updateChecks(nil)
	b.run()
	s := b.status()
	for _, want := range []string{recallOffLine, updateChecksOff, learningOffNote} {
		if !strings.Contains(s, want) {
			t.Errorf("STATUS %q lacks %q", s, want)
		}
	}
	if d := b.reg.Digest(); len(d) != 2 {
		t.Fatalf("digest: %q", d)
	}
	if strings.Contains(s, "Routing:") {
		t.Errorf("routing line with no learning plane: %q", s)
	}
}

// OP-9: no registry line holds a flag name, a path, a socket name or
// error text; a planted one fails.
func TestCapabilityLinesAreOwnerWorded(t *testing.T) {
	for _, l := range capLineTexts() {
		if err := ownerWorded(l); err != nil {
			t.Errorf("%q: %v", l, err)
		}
	}
	for _, bad := range []string{
		"Model: -egress is empty; restart me.",
		"Agent: off, /var/lib/agentos/machines is missing; restart me.",
		"Model: model.sock refused; restart me.",
		"Agent: off, vm open: permission denied; restart me.",
		"Worker tools: off, image %q; restart me.",
		"Model: can't be reached; restart me.",
		"Worker tools: not set up on this box.",
		"Worker tools: not set up on this box; " + strings.Repeat("an update will add them ", 4) + ".",
	} {
		if ownerWorded(bad) == nil {
			t.Errorf("planted line passed: %q", bad)
		}
	}
	// A planted entry fails the scan of the registry itself.
	caps := newCapState("")
	caps.model = reachableModel(t)
	caps.updateChecks(stubUpdates{})
	reg := newCapLines(caps)
	reg.add("planted", capConfig, func() string { return "Model: -egress is empty; restart me." })
	if reg.check() == nil {
		t.Error("a registry holding a flag name passed")
	}
}

// OP-9 (digest sources): DIG-1's one list holds the registry, the loop
// scheduler's digest when learning opened, and the second line's when it
// is configured.
func TestDigestSourcesHoldTheRegistry(t *testing.T) {
	b := newCapBox(t)
	lp := openCapLearning(t, b)
	line := &secondLine{}
	names := func(ds digestSources) (out []string) {
		for _, s := range ds {
			out = append(out, s.name)
		}
		return out
	}
	if got := names(newDigestSources(b.reg, nil, nil)); strings.Join(got, ",") != "capabilities" {
		t.Fatalf("no learning, no second line: %q", got)
	}
	ds := newDigestSources(b.reg, lp, line)
	if got := names(ds); strings.Join(got, ",") != "capabilities,loops,second line" {
		t.Fatalf("all: %q", got)
	}
	b.caps.updateChecks(nil)
	if d := ds[0].digest(); !slices.Contains(d, updateChecksOff) || !slices.Equal(d, b.reg.Digest()) {
		t.Fatalf("registry digest: %q", d)
	}
}

// OP-9: the clock note stays first, the registry follows it, and notes
// wired after it keep their place.
func TestCapabilityLinesFollowTheClockNote(t *testing.T) {
	b := newCapBox(t)
	b.cfg.Notes = append(b.cfg.Notes, func() string { return "Later note." })
	b.caps.recallWired(false)
	b.run()
	s := b.status()
	c, r, l := strings.Index(s, clockNoteForTest), strings.Index(s, recallOffLine), strings.Index(s, "Later note.")
	if c < 0 || r < 0 || l < 0 || !(c < r && r < l) {
		t.Fatalf("order: %q", s)
	}
}

// OP-9: an owner choice is never a STATUS line, only a digest listing.
func TestOwnerChoicesAreDigestOnly(t *testing.T) {
	b := newCapBoxWith(t, func(reg *capLines) {
		reg.add("choice", capOwnerChoice, func() string { return "Spare-time work: off; reply LOOPS ON to restart it." })
	})
	b.run()
	if strings.Contains(b.status(), "LOOPS ON") {
		t.Fatalf("owner choice in STATUS: %q", b.status())
	}
	if d := b.reg.Digest(); len(d) != 1 {
		t.Fatalf("digest: %q", d)
	}
}

// REQ: A11, OP-9
// A11: with learning on but unable to run, STATUS names the cause: the
// memory too small, no builder, no model socket, or no model grant, each
// alone.
func TestLearningUnableToRunNamesTheCause(t *testing.T) {
	for _, c := range []struct {
		name   string
		induce func(b *capBox, lp *learning)
		want   string
	}{
		{"memory_too_small", func(b *capBox, lp *learning) { lp.noRoom.Store(true) }, noRoomNote},
		{"no_builder", func(b *capBox, lp *learning) { lp.builderOff.Store(true) }, builderOffNote},
		{"no_model_socket", func(b *capBox, lp *learning) {
			b.caps.model = newModelProbe(filepath.Join(shortDir(t), "gone.sock"))
		}, modelUnreachable},
		{"no_model_grant", func(b *capBox, lp *learning) {
			b.caps.model = modelWith(t, modelroute.ModelState{Open: true})
		}, modelNoGrant},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newCapBox(t)
			lp := openCapLearning(t, b)
			b.run()
			attachForTest(t, lp, b.ctx, b.cancel, b.d)
			if !lp.learningOn() {
				t.Fatal("learning is not on")
			}
			before := b.status()
			for _, l := range []string{noRoomNote, builderOffNote, builderUnsetNote, modelUnreachable, modelUnset, modelNoGrant, modelLocked} {
				if strings.Contains(before, l) {
					t.Fatalf("a cause before any: %q", before)
				}
			}
			c.induce(b, lp)
			s := b.status()
			// STATUS drops apostrophes (control plainLine).
			if !strings.Contains(s, strings.ReplaceAll(c.want, "'", "")) {
				t.Fatalf("STATUS %q does not name %q", s, c.want)
			}
			if !strings.Contains(strings.ToLower(c.want), "learn") {
				t.Errorf("cause line %q does not say learning is affected", c.want)
			}
		})
	}
}

// OP-9: a plain file where the socket belongs reads as not reachable.
func TestModelProbeWantsASocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "m.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if l := newModelProbe(path).Line(); l != modelUnreachable {
		t.Fatalf("plain file: %q", l)
	}
}

// REQ: OP-9, A11, CRED-5
// OP-9 C2 (CRED-5f-mr): one probe, one vault process, each condition in
// turn. Each gives its one line, and the line clears at the next probe
// after the condition does. A stale socket reads as not reachable, never
// as the last good state.
func TestModelLinesFollowTheVaultProcess(t *testing.T) {
	f := serveFakeVault(t, filepath.Join(shortDir(t), "m.sock"), modelroute.ModelState{})
	now := time.Unix(1_800_000_000, 0)
	p := newModelProbe(f.sock)
	p.now = func() time.Time { return now }
	caps := newCapState("")
	caps.model = p
	caps.updateChecks(stubUpdates{})
	reg := newCapLines(caps)
	step := func(name, want string) {
		t.Helper()
		var got []string
		if want != "" {
			got = []string{want}
		}
		if d := reg.Digest(); !slices.Equal(d, got) {
			t.Fatalf("%s: %q, want %q", name, d, got)
		}
		now = now.Add(modelProbeEvery)
	}
	step("no grant, locked", modelNoGrant)
	f.set(modelroute.ModelState{Granted: true})
	step("granted, locked", modelLocked)
	f.set(modelOn)
	step("granted, open", "")
	f.stop()
	step("stale socket", modelUnreachable)
	f.start(t)
	step("answering again", "")
	f.set(modelroute.ModelState{Granted: true})
	step("locked again", modelLocked)
	f.set(modelroute.ModelState{Open: true})
	step("grant withdrawn", modelNoGrant)
}

// REQ: OP-9, A11
// OP-9 (UX blocker on #566, a CH-12 repeat): the no-grant line's fix
// names only a step the box serves. agentosd does not serve the local
// page's API-key step yet (localui.AgentosdSetup.ConnectAPIKey), so the
// line names no page and says a later box version adds it. When the step
// is served this fails, and the line must name where the owner adds one.
func TestModelNoGrantNamesAServedStep(t *testing.T) {
	served := localui.AgentosdSetup{}.ConnectAPIKey("openai", "sk-synthetic-not-a-key") == nil
	_, fix, _ := strings.Cut(modelNoGrant, "; ")
	switch {
	case !served && (strings.Contains(fix, "page") || !strings.Contains(fix, "later box version")):
		t.Fatalf("adding a key is not served, but the fix reads %q", fix)
	case served && !strings.Contains(fix, "page"):
		t.Fatalf("adding a key is served now; name where in %q", fix)
	}
}
