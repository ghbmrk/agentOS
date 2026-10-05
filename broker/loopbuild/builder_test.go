package loopbuild

// REQ: LOOP-2, LOOP-6, CHG-1, OP-8, REV-5

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
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
}

func (f *machines) Create(_ context.Context, id string, s vm.Spec) (vm.Machine, error) {
	m := vm.Machine{ID: id, Spec: s, Label: s.Label, State: vm.Running, ForkBase: f.forkBase}
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

	f2 := &machines{forkBase: "agent@snap"}
	b2 := newBuilder(t, f2, nil)
	if _, err := b2.Build(context.Background(), brief(change.ClassSkill)); !errors.Is(err, ErrNotClean) {
		t.Fatalf("forked machine: %v", err)
	}
	if len(f2.Machines()) != 0 {
		t.Fatal("a refused machine was kept")
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
