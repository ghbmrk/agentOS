package loopbuild

// REQ: LOOP-2, LOOP-6, CHG-1, CHG-5, OP-8, REV-5

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
)

// machines is a fake vm manager. Its guest runs as each machine is
// created: it opens the machine's services, as the vm manager does at
// start, and acts as the builder inside.
type machines struct {
	mu        sync.Mutex
	ms        map[string]vm.Machine
	destroyed []string
	services  vm.Services
	guest     func(id, dir string)
	forkBase  string
	// image and public, when set, make the manager report a machine that
	// is not what was asked for.
	image  string
	public bool
}

func (f *machines) Create(_ context.Context, id string, s vm.Spec) (vm.Machine, error) {
	m := vm.Machine{ID: id, Spec: s, Label: s.Label, State: vm.Running, ForkBase: f.forkBase}
	if f.image != "" {
		m.Spec.Image = f.image
	}
	if f.public {
		m.Label = vm.Public
	}
	f.mu.Lock()
	f.ms[id] = m
	f.mu.Unlock()
	dir, err := f.services.Open(id)
	if err != nil {
		return vm.Machine{}, err
	}
	if f.guest != nil {
		go f.guest(id, dir)
	}
	return m, nil
}

func (f *machines) Get(id string) (vm.Machine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.ms[id]
	if !ok {
		return vm.Machine{}, vm.ErrUnknown
	}
	return m, nil
}

func (f *machines) Resume(context.Context, string) error { return nil }

func (f *machines) Destroy(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.ms[id]; !ok {
		return vm.ErrUnknown
	}
	delete(f.ms, id)
	f.destroyed = append(f.destroyed, id)
	return nil
}

func (f *machines) Machines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id := range f.ms {
		out = append(out, id)
	}
	return out
}

func (f *machines) spec(id string) vm.Spec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ms[id].Spec
}

// guestClient talks to a machine's broker socket, as the guest does.
func guestClient(dir string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, Socket))
	}}}
}

func call(c *http.Client, method, path string, body any) (int, string) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://builder"+path, rd)
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func newBuilder(t *testing.T, f *machines, mod func(*Config)) *Builder {
	t.Helper()
	f.ms = map[string]vm.Machine{}
	cfg := Config{Dir: t.TempDir(), Machines: f, Image: "builder", Poll: 10 * time.Millisecond, Logf: t.Logf}
	if mod != nil {
		mod(&cfg)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.services = b.Services(nil)
	return b
}

func brief(class change.Class) loops.Brief {
	return loops.Brief{
		Hypothesis: loops.Hypothesis{Signal: loops.SignalCorrection, Class: class, Key: "correction:mail/send",
			Evidence: []journal.Status{
				{Intent: journal.Intent{ID: "t1", GoalID: "g1", Account: "mail", Action: "send", Params: map[string]any{"subject": "[redacted]"}}, State: journal.Succeeded},
				{Intent: journal.Intent{ID: "b1", GoalID: "g1", Account: journal.BrokerAccount, Action: "note"}},
			}},
		Dev: []change.Case{
			{ID: "c-explicit", Input: []byte(`{"q":1}`), Expect: []byte(`"v2"`), Outcome: change.Accepted},
			{ID: "c-implicit", Implicit: true},
		},
	}
}

// C-3c-1, C-3c-2: one fresh private machine per job, of the builder image
// in the experiments class, whose socket serves the brief (explicit cases
// only), one candidate, and the model route; everything else is 404. A
// submission outside the class's namespace, too big, or not text is
// refused and may be sent again; the machine is destroyed after.
func TestABuilderMachineServesOnlyItsJob(t *testing.T) {
	f := &machines{}
	refusals := map[string]int{}
	var got Brief
	f.guest = func(id, dir string) {
		c := guestClient(dir)
		code, body := call(c, "GET", "/brief", nil)
		if code != 200 || json.Unmarshal([]byte(body), &got) != nil {
			t.Errorf("brief: %d %s", code, body)
		}
		for _, p := range []string{"/mcp", "/owner", "/tree", "/managed_tree", "/cleanroom/result", "/"} {
			if code, _ := call(c, "GET", p, nil); code != 404 {
				t.Errorf("%s answered %d", p, code)
			}
		}
		big := map[string]string{}
		for i := 0; i <= MaxFiles; i++ {
			big["procedures/p"+strings.Repeat("x", i)] = "v"
		}
		for name, sub := range map[string]Submission{
			"other namespace": {Files: map[string]string{"security/x": "v"}},
			"routing":         {Files: map[string]string{"routing/rule.json": "{}"}},
			"escape":          {Files: map[string]string{"procedures/../security/x": "v"}},
			"absolute":        {Files: map[string]string{"/procedures/mail": "v"}},
			"bare namespace":  {Files: map[string]string{"procedures": "v"}},
			"binary":          {Files: map[string]string{"procedures/mail": "a\x00b"}},
			"file too big":    {Files: map[string]string{"procedures/mail": strings.Repeat("v", MaxFileBytes+1)}},
			"too many files":  {Files: big},
			"empty":           {Files: map[string]string{}},
		} {
			code, _ := call(c, "POST", "/candidate", sub)
			refusals[name] = code
		}
		if code, body := call(c, "POST", "/candidate", Submission{Files: map[string]string{"procedures/mail": "v2"}}); code != 200 {
			t.Errorf("candidate: %d %s", code, body)
		}
	}
	b := newBuilder(t, f, nil)
	cand, err := b.Build(context.Background(), brief(change.ClassProcedure))
	if err != nil {
		t.Fatal(err)
	}
	if string(cand.Files["procedures/mail"]) != "v2" || len(cand.Files) != 1 || cand.Public || cand.Source != change.Local {
		t.Fatalf("candidate %+v", cand)
	}
	for name, code := range refusals {
		if code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %d, want 422", name, code)
		}
	}
	if got.Key != "correction:mail/send" || got.Writes != "procedures" || len(got.Cases) != 1 || got.Cases[0].ID != "c-explicit" ||
		len(got.Steps) != 1 || got.Steps[0].Account != "mail" {
		t.Fatalf("brief %+v", got)
	}
	if len(f.destroyed) != 1 || !strings.HasPrefix(f.destroyed[0], Prefix) {
		t.Fatalf("destroyed %v", f.destroyed)
	}
	if len(f.Machines()) != 0 {
		t.Fatal("a builder machine outlived its job")
	}
}

func TestTheMachineIsAFreshPrivateExperiment(t *testing.T) {
	f := &machines{}
	var spec vm.Spec
	f.guest = func(id, dir string) {
		spec = f.spec(id)
		call(guestClient(dir), "POST", "/candidate", Submission{Files: map[string]string{"skills/k.json": "{}"}})
	}
	b := newBuilder(t, f, nil)
	if _, err := b.Build(context.Background(), brief(change.ClassSkill)); err != nil {
		t.Fatal(err)
	}
	if spec.Image != "builder" || spec.Label != vm.Private || spec.Class != admission.Experiment || spec.MemMB != DefaultMemMB {
		t.Fatalf("spec %+v", spec)
	}

	// L3 S2 on #126: a forked machine, another image, or a public label
	// is refused and destroyed.
	for name, f2 := range map[string]*machines{
		"forked":        {forkBase: "agent@snap"},
		"another image": {image: "openclaw"},
		"public":        {public: true},
	} {
		b2 := newBuilder(t, f2, func(c *Config) { c.Timeout = time.Second })
		if _, err := b2.Build(context.Background(), brief(change.ClassSkill)); !errors.Is(err, ErrNotClean) {
			t.Fatalf("%s machine: %v", name, err)
		}
		if len(f2.Machines()) != 0 {
			t.Fatalf("a refused %s machine was kept", name)
		}
	}
}

// No builder for a class outside procedures, skills and context: no
// machine is made (C-3c-4).
func TestNoBuilderForOtherClasses(t *testing.T) {
	f := &machines{}
	b := newBuilder(t, f, nil)
	for _, c := range []change.Class{change.ClassRouting, change.ClassAuthority, change.ClassGovernance, change.ClassGuestImage} {
		if _, err := b.Build(context.Background(), brief(c)); !errors.Is(err, ErrClass) {
			t.Fatalf("%s: %v", c, err)
		}
	}
	if len(f.destroyed) != 0 || len(f.Machines()) != 0 {
		t.Fatal("a machine was made")
	}
}

// A job that submits nothing ends at its time; one whose ctx ends stops;
// the machine is destroyed either way.
func TestAJobEndsAtItsTime(t *testing.T) {
	f := &machines{}
	b := newBuilder(t, f, func(c *Config) { c.Timeout = 50 * time.Millisecond })
	if _, err := b.Build(context.Background(), brief(change.ClassProcedure)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.guest = func(string, string) { cancel() }
	if _, err := b.Build(ctx, brief(change.ClassProcedure)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if len(f.destroyed) != 2 || len(f.Machines()) != 0 {
		t.Fatalf("destroyed %v", f.destroyed)
	}
}

// C-3c-1: one job at a time.
func TestOneJobAtATime(t *testing.T) {
	f := &machines{}
	var mu sync.Mutex
	live, most := 0, 0
	f.guest = func(id, dir string) {
		mu.Lock()
		live++
		most = max(most, live)
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		live--
		mu.Unlock()
		call(guestClient(dir), "POST", "/candidate", Submission{Files: map[string]string{"procedures/mail": "v"}})
	}
	b := newBuilder(t, f, nil)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.Build(context.Background(), brief(change.ClassProcedure)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if most != 1 {
		t.Fatalf("%d jobs at once", most)
	}
}

// Builder machines never reach the guest plane (where managed_tree and
// executors are): their IDs go to the builder's socket or nowhere, and
// every other machine goes to next.
func TestBuilderMachinesNeverReachTheGuestPlane(t *testing.T) {
	f := &machines{}
	b := newBuilder(t, f, nil)
	next := &recorder{}
	s := b.Services(next)
	if _, err := s.Open(Prefix + "stray"); err == nil {
		t.Fatal("a builder machine with no job got services")
	}
	s.Close(Prefix + "stray")
	if _, err := s.Open("agent"); err != nil {
		t.Fatal(err)
	}
	s.Close("agent")
	if strings.Join(next.calls, ",") != "open agent,close agent" {
		t.Fatalf("next got %v", next.calls)
	}
	if _, err := b.Open("agent"); err == nil {
		t.Fatal("the builder served a machine that is not a builder's")
	}
}

type recorder struct{ calls []string }

func (r *recorder) Open(id string) (string, error) {
	r.calls = append(r.calls, "open "+id)
	return "", nil
}
func (r *recorder) Close(id string) { r.calls = append(r.calls, "close "+id) }

// C-3c-5: the model route is metered, and refused once the job has used
// its token cap.
func TestTheModelRouteHasAJobCap(t *testing.T) {
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	f := &machines{}
	var codes []int
	f.guest = func(id, dir string) {
		c := guestClient(dir)
		for i := 0; i < 2; i++ {
			code, _ := call(c, "POST", "/model/v1/chat/completions", map[string]any{"max_tokens": 10, "messages": []any{map[string]any{"role": "user", "content": strings.Repeat("x", 400)}}})
			codes = append(codes, code)
		}
		call(c, "POST", "/candidate", Submission{Files: map[string]string{"procedures/mail": "v"}})
	}
	served := 0
	b := newBuilder(t, f, func(c *Config) {
		c.Meter, c.JobTokens = mtr, 50
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				served++
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"usage":{"prompt_tokens":100,"completion_tokens":10}}`)
			})
		}
	})
	if _, err := b.Build(context.Background(), brief(change.ClassProcedure)); err != nil {
		t.Fatal(err)
	}
	if len(codes) != 2 || codes[0] != 200 || codes[1] != http.StatusTooManyRequests || served != 1 {
		t.Fatalf("codes %v, served %d", codes, served)
	}
}

// Security F1 on #126 ("count, not content"; arbitrator on #109, change
// C17): a task the owner accepted only implicitly is counted in the brief,
// its steps' account, action and state, but none of its values reaches
// the model-backed builder.
func TestAnImplicitTasksValuesNeverReachTheBrief(t *testing.T) {
	f := &machines{}
	var got Brief
	f.guest = func(id, dir string) {
		c := guestClient(dir)
		if _, body := call(c, "GET", "/brief", nil); json.Unmarshal([]byte(body), &got) != nil {
			t.Errorf("brief %s", body)
		}
		call(c, "POST", "/candidate", Submission{Files: map[string]string{"procedures/mail": "v"}})
	}
	br := brief(change.ClassProcedure)
	implicit := journal.Quality{Verdict: journal.VerdictGood, Source: "owner" + change.ImplicitSuffix}
	br.Hypothesis.Evidence = append(br.Hypothesis.Evidence,
		journal.Status{Intent: journal.Intent{ID: "i1", GoalID: "g2", Account: "mail", Action: "draft", Params: map[string]any{"subject": "CANARY-implicit"}}, State: journal.NotApplied},
		journal.Status{Intent: journal.Intent{ID: "i2", GoalID: "g2", Account: "mail", Action: "send", Params: map[string]any{"to": "CANARY-implicit"}}, State: journal.Succeeded, Quality: implicit},
	)
	b := newBuilder(t, f, nil)
	if _, err := b.Build(context.Background(), br); err != nil {
		t.Fatal(err)
	}
	if len(got.Steps) != 3 || got.Steps[0].Params == nil {
		t.Fatalf("steps %+v", got.Steps)
	}
	for _, s := range got.Steps[1:] {
		if s.Account != "mail" || s.Action == "" || s.State == "" || s.Params != nil {
			t.Fatalf("implicit step %+v", s)
		}
	}
}

// Security R3 on #126: one model call in flight per job, so concurrent
// calls cannot overshoot the job's token cap.
func TestConcurrentModelCallsKeepTheJobCap(t *testing.T) {
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.DefaultMachineCap, OverallCap: meter.DefaultOverallCap})
	if err != nil {
		t.Fatal(err)
	}
	f := &machines{}
	f.guest = func(id, dir string) {
		c := guestClient(dir)
		var wg sync.WaitGroup
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				call(c, "POST", "/model/v1/chat/completions", map[string]any{"max_tokens": 10})
			}()
		}
		wg.Wait()
		call(c, "POST", "/candidate", Submission{Files: map[string]string{"procedures/mail": "v"}})
	}
	var mu sync.Mutex
	served := 0
	b := newBuilder(t, f, func(c *Config) {
		c.Meter, c.JobTokens = mtr, 50
		c.Model = func(string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				mu.Lock()
				served++
				mu.Unlock()
				time.Sleep(50 * time.Millisecond)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"usage":{"prompt_tokens":100,"completion_tokens":10}}`)
			})
		}
	})
	if _, err := b.Build(context.Background(), brief(change.ClassProcedure)); err != nil {
		t.Fatal(err)
	}
	if served != 1 {
		t.Fatalf("served %d model calls past a 50-token cap", served)
	}
}

// L3 MUST 2 on #126: a builder holds at most maxConns connections to its
// socket; one past that is not served until another closes, so a
// compromised builder cannot use up agentosd's file descriptors.
func TestABuilderHoldsFewConnections(t *testing.T) {
	f := &machines{}
	served := make(chan bool, 1)
	f.guest = func(id, dir string) {
		sock := filepath.Join(dir, Socket)
		var held []net.Conn
		for i := 0; i < maxConns; i++ {
			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Error(err)
				return
			}
			held = append(held, c)
		}
		// Each held connection is accepted (it is served when written to).
		for _, c := range held {
			io.WriteString(c, "GET /brief HTTP/1.1\r\nHost: b\r\n\r\n")
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(make([]byte, 1)); err != nil {
				t.Errorf("a connection within the cap was not served: %v", err)
			}
		}
		extra, err := net.Dial("unix", sock)
		if err != nil {
			t.Error(err)
			return
		}
		io.WriteString(extra, "GET /brief HTTP/1.1\r\nHost: b\r\n\r\n")
		extra.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err = extra.Read(make([]byte, 1))
		served <- err == nil
		extra.Close()
		for _, c := range held {
			c.Close()
		}
		call(guestClient(dir), "POST", "/candidate", Submission{Files: map[string]string{"procedures/mail": "v"}})
	}
	b := newBuilder(t, f, nil)
	if _, err := b.Build(context.Background(), brief(change.ClassProcedure)); err != nil {
		t.Fatal(err)
	}
	if <-served {
		t.Fatalf("connection %d was served", maxConns+1)
	}
}

// W3-builder-image: a builder that has nothing to submit says so on
// /done, and the job ends at once with no result, instead of holding the
// one builder slot until its time runs out. /done takes no candidate.
func TestABuilderCanGiveUp(t *testing.T) {
	f := &machines{}
	codes := make(chan int, 2)
	f.guest = func(id, dir string) {
		c := guestClient(dir)
		code, _ := call(c, "GET", "/done", nil)
		codes <- code
		code, _ = call(c, "POST", "/done", nil)
		codes <- code
	}
	b := newBuilder(t, f, func(c *Config) { c.Timeout = time.Minute })
	start := time.Now()
	if _, err := b.Build(context.Background(), brief(change.ClassProcedure)); !errors.Is(err, ErrNoResult) {
		t.Fatalf("gave up: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the job waited out its time after the builder gave up")
	}
	if a, p := <-codes, <-codes; a != http.StatusMethodNotAllowed || p != 200 {
		t.Fatalf("/done answered %d, %d", a, p)
	}
}

// L3 on #131: a job ends once. After /done or an accepted candidate,
// another /done or /candidate gets 409 and changes nothing (closing the
// job twice would panic the broker); a body past twice the candidate
// limit gets 413 before it is decoded.
func TestAJobEndsOnce(t *testing.T) {
	post := func(s *session, h http.HandlerFunc, body string) int {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		return w.Code
	}
	cand := `{"files":{"procedures/mail":"v"}}`

	s := &session{ns: "procedures", done: make(chan struct{})}
	if c := post(s, s.giveUp, ""); c != 200 {
		t.Fatalf("/done: %d", c)
	}
	if c1, c2 := post(s, s.giveUp, ""), post(s, s.candidate, cand); c1 != http.StatusConflict || c2 != http.StatusConflict {
		t.Fatalf("after /done: /done %d, /candidate %d", c1, c2)
	}
	if s.end() != nil {
		t.Fatal("a candidate after /done was kept")
	}

	s = &session{ns: "procedures", done: make(chan struct{})}
	if c := post(s, s.candidate, cand); c != 200 {
		t.Fatalf("/candidate: %d", c)
	}
	if c1, c2 := post(s, s.giveUp, ""), post(s, s.candidate, `{"files":{"procedures/mail":"v2"}}`); c1 != http.StatusConflict || c2 != http.StatusConflict {
		t.Fatalf("after a candidate: /done %d, /candidate %d", c1, c2)
	}
	if got := s.end(); string(got["procedures/mail"]) != "v" {
		t.Fatalf("kept %v", got)
	}

	s = &session{ns: "procedures", done: make(chan struct{})}
	if c := post(s, s.candidate, strings.Repeat(" ", 2*MaxCandidateBytes+1)); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", c)
	}
}

// L3 on #131: a request that does not finish arriving within the read
// timeout is cut off, so a builder cannot hold a connection by trickling
// a body.
func TestASlowRequestIsCutOff(t *testing.T) {
	was := readTimeout
	readTimeout = 200 * time.Millisecond
	t.Cleanup(func() { readTimeout = was })
	f := &machines{}
	cut := make(chan error, 1)
	f.guest = func(id, dir string) {
		c, err := net.Dial("unix", filepath.Join(dir, Socket))
		if err != nil {
			cut <- err
			return
		}
		defer c.Close()
		io.WriteString(c, "POST /candidate HTTP/1.1\r\nHost: b\r\nContent-Length: 100\r\n\r\n{")
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = io.ReadAll(c)
		cut <- err
		call(guestClient(dir), "POST", "/done", nil)
	}
	b := newBuilder(t, f, nil)
	b.Build(context.Background(), brief(change.ClassProcedure))
	if err := <-cut; err != nil {
		t.Fatalf("the slow request was not cut off: %v", err)
	}
}

// Potency R1 on #126 (BOARD W3-builder-tune): every job leaves one
// count-only log line, its outcome, tokens and time, so the first jobs'
// numbers can retune the token cap and the timeout. It names no brief or
// candidate content.
func TestEveryJobLogsItsNumbers(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	logf := func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(f, a...))
	}
	jobs := func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, l := range lines {
			if strings.Contains(l, " job ") {
				out = append(out, l)
			}
		}
		return out
	}
	f := &machines{}
	f.guest = func(id, dir string) {
		call(guestClient(dir), "POST", "/candidate", Submission{Files: map[string]string{"procedures/mail": "CANARY-content"}})
	}
	b := newBuilder(t, f, func(c *Config) { c.Logf = logf })
	if _, err := b.Build(context.Background(), brief(change.ClassProcedure)); err != nil {
		t.Fatal(err)
	}
	f.guest = func(id, dir string) { call(guestClient(dir), "POST", "/done", nil) }
	b.Build(context.Background(), brief(change.ClassProcedure))
	got := jobs()
	if len(got) != 2 || !strings.Contains(got[0], "outcome candidate") || !strings.Contains(got[1], "outcome no candidate") ||
		!strings.Contains(got[0], "tokens 0") || !strings.Contains(got[0], "correction") {
		t.Fatalf("job lines %q", got)
	}
	for _, l := range got {
		if strings.Contains(l, "CANARY") || strings.Contains(l, "subject") {
			t.Fatalf("a job line holds content: %q", l)
		}
	}
}
