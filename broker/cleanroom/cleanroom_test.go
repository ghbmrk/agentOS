package cleanroom

// REQ: OSS-2, OSS-3, OSS-5

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/hint"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
)

// fakeVMs stands in for vm.Manager: it opens and closes services the way
// the manager does, and runs guest(id, dir) for each machine it creates.
type fakeVMs struct {
	mu        sync.Mutex
	svc       vm.Services
	ms        map[string]*vm.Machine
	created   []vm.Machine
	resumed   []string
	createErr error
	guest     func(id, dir string)
	wg        sync.WaitGroup // guests running
	onGet     func(id string)
}

func newFake() *fakeVMs { return &fakeVMs{ms: map[string]*vm.Machine{}} }

func (f *fakeVMs) Create(_ context.Context, id string, s vm.Spec) (vm.Machine, error) {
	f.mu.Lock()
	if err := f.createErr; err != nil {
		f.mu.Unlock()
		return vm.Machine{}, err
	}
	if f.ms[id] != nil {
		f.mu.Unlock()
		return vm.Machine{}, vm.ErrExists
	}
	f.mu.Unlock()
	dir, err := f.svc.Open(id)
	if err != nil {
		return vm.Machine{}, err
	}
	m := vm.Machine{ID: id, Spec: s, Label: s.Label, State: vm.Running}
	f.mu.Lock()
	f.ms[id] = &m
	f.created = append(f.created, m)
	out := m
	g := f.guest
	if g != nil {
		f.wg.Add(1)
	}
	f.mu.Unlock()
	if g != nil {
		go func() { defer f.wg.Done(); g(id, dir) }()
	}
	return out, nil
}

func (f *fakeVMs) Get(id string) (vm.Machine, error) {
	if f.onGet != nil {
		f.onGet(id)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.ms[id]; m != nil {
		return *m, nil
	}
	return vm.Machine{}, vm.ErrUnknown
}

func (f *fakeVMs) set(id string, fn func(*vm.Machine)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := f.ms[id]; m != nil {
		fn(m)
	}
}

func (f *fakeVMs) Resume(_ context.Context, id string) error {
	if _, err := f.svc.Open(id); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resumed = append(f.resumed, id)
	if m := f.ms[id]; m != nil {
		m.State = vm.Running
	}
	return nil
}

func (f *fakeVMs) Destroy(_ context.Context, id string) error {
	f.mu.Lock()
	_, ok := f.ms[id]
	delete(f.ms, id)
	f.mu.Unlock()
	if !ok {
		return vm.ErrUnknown
	}
	f.svc.Close(id)
	return nil
}

func (f *fakeVMs) Machines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for id := range f.ms {
		out = append(out, id)
	}
	return out
}

func (f *fakeVMs) live() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ms)
}

func (f *fakeVMs) creates() []vm.Machine {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]vm.Machine(nil), f.created...)
}

type rig struct {
	t   *testing.T
	f   *fakeVMs
	b   *Builder
	cfg Config
}

func newRig(t *testing.T, mod func(*Config)) *rig {
	t.Helper()
	f := newFake()
	cfg := Config{Dir: t.TempDir(), Machines: f, Image: "cleanroom", Poll: 10 * time.Millisecond, Retry: 10 * time.Millisecond, Timeout: 5 * time.Second}
	if mod != nil {
		mod(&cfg)
	}
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = b.Services(nil)
	return &rig{t: t, f: f, b: b, cfg: cfg}
}

// run starts the builder and stops it when the test ends.
func (r *rig) run() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.b.Run(ctx); close(done) }()
	r.t.Cleanup(func() { cancel(); <-done })
}

func canon(t *testing.T, kind string, fields map[string]string) []byte {
	t.Helper()
	c, err := hint.Default().Canonical(hint.Hint{Kind: kind, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func skillHint(t *testing.T) []byte {
	return canon(t, "skill_gap", map[string]string{"domain": "calendar", "format": "ics", "failure": "timezone", "frequency": "sometimes"})
}

// skillHintN is a skill hint that differs from skillHint and from every
// other n.
func skillHintN(t *testing.T, n int) []byte {
	domains := []string{"email", "contacts", "documents", "spreadsheets", "files"}
	return canon(t, "skill_gap", map[string]string{"domain": domains[n], "format": "ics", "failure": "timezone", "frequency": "once"})
}

var dayN struct {
	sync.Mutex
	t time.Time
}

// nextDay is a fresh day for each batch, since the outbox takes a day once.
func nextDay() string {
	dayN.Lock()
	defer dayN.Unlock()
	if dayN.t.IsZero() {
		dayN.t = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	dayN.t = dayN.t.AddDate(0, 0, 1)
	return dayN.t.Format("2006-01-02")
}

func vulnHint(t *testing.T) []byte {
	return canon(t, "vuln", map[string]string{"class": "prompt_injection", "vector": "email_html"})
}

// client speaks HTTP over a clean room's broker socket, as its guest would.
func client(dir string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(dir, Socket))
		},
	}}
}

func call(c *http.Client, method, path string, body []byte) (int, string) {
	req, _ := http.NewRequest(method, "http://broker"+path, bytes.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func goodResult() []byte {
	b, _ := json.Marshal(Result{
		Files:    map[string]string{"skill/SKILL.md": "# ics timezones\n", "skill/test_tz.py": "def test(): pass\n"},
		Fixtures: Fixtures{Passed: 3},
	})
	return b
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *rig) outcomes() []Outcome {
	o, err := r.b.Outcomes()
	if err != nil {
		r.t.Fatal(err)
	}
	return o
}

// OSS-2: a hint gets a fresh public machine on the clean-room image that
// sees only the hint, builds, and submits; the result is stored with its
// provenance, and the machine is destroyed.
func TestCleanRoomBuildsArtifactFromHint(t *testing.T) {
	r := newRig(t, nil)
	h := skillHint(t)
	var got string
	r.f.guest = func(id, dir string) {
		c := client(dir)
		_, got = call(c, "GET", "/cleanroom/hint", nil)
		if code, body := call(c, "POST", "/cleanroom/result", goodResult()); code != 200 {
			t.Errorf("result: %d %s", code, body)
		}
	}
	if err := r.b.Send(nextDay(), [][]byte{h}); err != nil {
		t.Fatal(err)
	}
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if got != string(h) {
		t.Fatalf("clean room saw %q, want the canonical hint", got)
	}
	o := r.outcomes()[0]
	if o.Result != "built" || o.Kind != "skill_gap" || o.Artifact == "" {
		t.Fatalf("outcome %+v", o)
	}
	waitFor(t, "machine destroyed", func() bool { return r.f.live() == 0 })
	ms := r.f.creates()
	if len(ms) != 1 {
		t.Fatalf("%d machines created", len(ms))
	}
	m := ms[0]
	if !strings.HasPrefix(m.ID, Prefix) || m.Spec.Image != "cleanroom" || m.Spec.Label != vm.Public || m.Spec.Class != admission.Experiment || m.ForkBase != "" {
		t.Fatalf("clean room spec %+v", m)
	}
	pub, err := r.b.Store().Publishable()
	if err != nil || len(pub) != 1 {
		t.Fatalf("publishable %v %v", pub, err)
	}
	man := pub[0].Manifest()
	if man.Output != "skill" || man.Embargo || string(man.Hint) != string(h) || man.Machine != m.ID || man.Image != "cleanroom" || man.ClaimedFixtures.Passed != 3 || len(man.Files) != 2 {
		t.Fatalf("manifest %+v", man)
	}
	if data, err := pub[0].ReadFile("skill/SKILL.md"); err != nil || string(data) != "# ics timezones\n" {
		t.Fatalf("file %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(r.cfg.Dir, "sockets", m.ID)); !os.IsNotExist(err) {
		t.Fatal("socket directory left behind")
	}
}

// OSS-2: the clean room's socket serves the hint, the result, and the
// model route, nothing else: no executor tools, no owner channel.
func TestCleanRoomHasNoPrivateServices(t *testing.T) {
	r := newRig(t, nil)
	codes := map[string]int{}
	r.f.guest = func(id, dir string) {
		c := client(dir)
		for _, p := range []string{"/mcp", "/owner/next", "/owner/reply", "/", "/journal", "/vault", "/recall", "/cleanroom/../mcp"} {
			code, _ := call(c, "POST", p, []byte(`{}`))
			codes["POST "+p] = code
			code, _ = call(c, "GET", p, nil)
			codes["GET "+p] = code
		}
		codes["model"], _ = call(c, "POST", "/model/v1/chat/completions", []byte(`{}`))
		codes["hint-post"], _ = call(c, "POST", "/cleanroom/hint", nil)
		call(c, "POST", "/cleanroom/result", goodResult())
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	for k, code := range codes {
		switch k {
		case "model":
			if code != http.StatusServiceUnavailable {
				t.Errorf("%s: %d, want 503 with no model configured", k, code)
			}
		case "hint-post":
			if code != http.StatusMethodNotAllowed {
				t.Errorf("%s: %d", k, code)
			}
		default:
			if code != http.StatusNotFound && code != http.StatusMovedPermanently {
				t.Errorf("%s: %d, want 404", k, code)
			}
		}
	}
}

// OSS-2: model calls from a clean room go through the OP-8 meter under its
// own machine ID.
func TestCleanRoomModelCallsAreMetered(t *testing.T) {
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"), MachineCap: meter.Limits{Calls: 10, Tokens: 1 << 30}, OverallCap: meter.Limits{Calls: 10, Tokens: 1 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	var routed []string
	var mu sync.Mutex
	r := newRig(t, func(c *Config) {
		c.Meter = mtr
		c.Model = func(machine string) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				mu.Lock()
				routed = append(routed, machine+" "+req.URL.Path)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":5,"completion_tokens":2}}`)
			})
		}
	})
	var id string
	r.f.guest = func(mid, dir string) {
		id = mid
		c := client(dir)
		if code, body := call(c, "POST", "/model/v1/chat/completions", []byte(`{"model":"m","messages":[]}`)); code != 200 {
			t.Errorf("model: %d %s", code, body)
		}
		call(c, "POST", "/cleanroom/result", goodResult())
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if len(routed) != 1 || routed[0] != id+" /v1/chat/completions" {
		t.Fatalf("routed %v", routed)
	}
	if u := mtr.Usage(id); u.Calls != 1 {
		t.Fatalf("meter saw %+v", u)
	}
	if _, err := New(Config{Dir: t.TempDir(), Machines: newFake(), Image: "x", Model: func(string) http.Handler { return nil }}); err == nil {
		t.Fatal("model route without a meter accepted")
	}
}

// OSS-1, OSS-2: the clean room takes only the exact canonical form of a
// valid hint, and a batch whole or not at all.
func TestSendTakesOnlyCanonicalHints(t *testing.T) {
	r := newRig(t, nil)
	good := skillHint(t)
	bad := map[string]string{
		"reordered":       `{"kind":"skill_gap","schema":1,"embargo":false,"fields":{"domain":"calendar","failure":"timezone","format":"ics"}}`,
		"spaced":          strings.Replace(string(good), ",", ", ", 1),
		"embargo flipped": strings.Replace(string(good), `"embargo":false`, `"embargo":true`, 1),
		"other schema":    strings.Replace(string(good), `"schema":1`, `"schema":2`, 1),
		"unlisted value":  strings.Replace(string(good), `"calendar"`, `"my_bank"`, 1),
		"extra key":       strings.Replace(string(good), `{"schema"`, `{"note":"x","schema"`, 1),
		"escaped":         strings.Replace(string(good), `"ics"`, `"\u0069cs"`, 1),
		"trailing":        string(good) + " ",
		"not json":        "hello",
	}
	for name, h := range bad {
		if err := r.b.Send(nextDay(), [][]byte{good, []byte(h)}); !errors.Is(err, ErrHint) {
			t.Errorf("%s: %v, want ErrHint", name, err)
		}
	}
	jobs, _ := r.b.queued()
	if len(jobs) != 0 {
		t.Fatalf("%d jobs queued from refused batches", len(jobs))
	}
	if err := r.b.Send(nextDay(), [][]byte{good, vulnHint(t)}); err != nil {
		t.Fatal(err)
	}
	jobs, _ = r.b.queued()
	if len(jobs) != 2 || jobs[0].Hint != string(good) {
		t.Fatalf("queued %+v", jobs)
	}
}

func TestSendBoundsTheQueue(t *testing.T) {
	r := newRig(t, func(c *Config) { c.MaxQueue = 2 })
	if err := r.b.Send(nextDay(), [][]byte{skillHint(t), vulnHint(t), skillHintN(t, 0)}); !errors.Is(err, ErrFull) {
		t.Fatalf("over the bound: %v", err)
	}
	if err := r.b.Send(nextDay(), [][]byte{skillHint(t), vulnHint(t)}); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Send(nextDay(), [][]byte{skillHintN(t, 1)}); !errors.Is(err, ErrFull) {
		t.Fatalf("full queue: %v", err)
	}
}

// OSS-5, hint K2: a regression rebuilt from a vuln hint is held for the
// private-report path and is not publishable until that path clears it.
func TestVulnRegressionIsEmbargoed(t *testing.T) {
	r := newRig(t, nil)
	r.f.guest = func(id, dir string) { call(client(dir), "POST", "/cleanroom/result", goodResult()) }
	r.b.Send(nextDay(), [][]byte{vulnHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	st := r.b.Store()
	pub, _ := st.Publishable()
	emb, _ := st.Embargoed()
	if len(pub) != 0 || len(emb) != 1 {
		t.Fatalf("publishable %d, embargoed %d", len(pub), len(emb))
	}
	m := emb[0].Manifest()
	if !m.Embargo || m.Output != "regression" {
		t.Fatalf("manifest %+v", m)
	}
	if err := st.ClearEmbargo(m.ID); err != nil {
		t.Fatal(err)
	}
	pub, _ = st.Publishable()
	emb, _ = st.Embargoed()
	if len(pub) != 1 || len(emb) != 0 {
		t.Fatalf("after clearing: publishable %d, embargoed %d", len(pub), len(emb))
	}
}

// OSS-3: a clean room that has received private data (its label rose)
// publishes nothing.
func TestCleanRoomWithPrivateLabelPublishesNothing(t *testing.T) {
	r := newRig(t, nil)
	var code int
	r.f.guest = func(id, dir string) {
		r.f.set(id, func(m *vm.Machine) { m.Label = vm.Private })
		code, _ = call(client(dir), "POST", "/cleanroom/result", goodResult())
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if code != http.StatusForbidden {
		t.Fatalf("result from a private machine: %d", code)
	}
	if o := r.outcomes()[0]; o.Result != "failed" {
		t.Fatalf("outcome %+v", o)
	}
	pub, _ := r.b.Store().Publishable()
	emb, _ := r.b.Store().Embargoed()
	if len(pub)+len(emb) != 0 {
		t.Fatal("artifact stored from a private machine")
	}
}

// OSS-2: a machine that is not a fresh public machine on the clean-room
// image never runs a job to the end.
func TestNotACleanMachineFails(t *testing.T) {
	for name, mod := range map[string]func(*vm.Machine){
		"forked":      func(m *vm.Machine) { m.ForkBase = "s1" },
		"other image": func(m *vm.Machine) { m.Spec.Image = "openclaw" },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			r.f.guest = func(id, dir string) {
				r.f.set(id, mod)
				call(client(dir), "POST", "/cleanroom/result", goodResult())
			}
			r.b.Send(nextDay(), [][]byte{skillHint(t)})
			r.run()
			waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
			r.f.wg.Wait()
			if o := r.outcomes()[0]; o.Result != "failed" {
				t.Fatalf("outcome %+v", o)
			}
		})
	}
}

// OSS-2: output must have passed its own tests on the synthetic fixtures,
// and be plain files with safe paths; a refused result can be fixed and
// sent again, an accepted one ends the job.
func TestResultRules(t *testing.T) {
	r := newRig(t, nil)
	res := func(files map[string]string, f Fixtures) []byte {
		b, _ := json.Marshal(Result{Files: files, Fixtures: f})
		return b
	}
	ok := map[string]string{"a.md": "x"}
	cases := map[string]struct {
		body []byte
		want int
	}{
		"untested":       {res(ok, Fixtures{}), 422},
		"failing":        {res(ok, Fixtures{Passed: 2, Failed: 1}), 422},
		"no files":       {res(nil, Fixtures{Passed: 1}), 422},
		"dotdot":         {res(map[string]string{"../x": "x"}, Fixtures{Passed: 1}), 422},
		"absolute":       {res(map[string]string{"/etc/x": "x"}, Fixtures{Passed: 1}), 422},
		"hidden":         {res(map[string]string{".git/config": "x"}, Fixtures{Passed: 1}), 422},
		"empty segment":  {res(map[string]string{"a//b": "x"}, Fixtures{Passed: 1}), 422},
		"file and dir":   {res(map[string]string{"a": "x", "a/b": "y"}, Fixtures{Passed: 1}), 422},
		"big file":       {res(map[string]string{"a": strings.Repeat("x", MaxFileBytes+1)}, Fixtures{Passed: 1}), 422},
		"unknown field":  {[]byte(`{"files":{"a":"x"},"fixtures":{"passed":1},"label":"public"}`), 400},
		"too large":      {bytes.Repeat([]byte("x"), MaxResultBytes+1), 413},
		"accepted":       {res(ok, Fixtures{Passed: 1}), 200},
		"after accepted": {res(ok, Fixtures{Passed: 1}), 409},
	}
	order := []string{"untested", "failing", "no files", "dotdot", "absolute", "hidden", "empty segment", "file and dir", "big file", "unknown field", "too large", "accepted", "after accepted"}
	got := map[string]int{}
	r.f.guest = func(id, dir string) {
		c := client(dir)
		for _, k := range order {
			got[k], _ = call(c, "POST", "/cleanroom/result", cases[k].body)
		}
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	waitFor(t, "guest done", func() bool { return r.f.live() == 0 })
	for _, k := range order {
		if k == "after accepted" && got[k] == 0 {
			continue // the socket closed with the job, also a refusal
		}
		if got[k] != cases[k].want {
			t.Errorf("%s: %d, want %d", k, got[k], cases[k].want)
		}
	}
}

// OSS-2: a clean room that never answers is destroyed at its deadline and
// tried once more on a fresh machine, then the job fails.
func TestSilentCleanRoomTimesOut(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Timeout = 50 * time.Millisecond })
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if o := r.outcomes()[0]; o.Result != "failed" || o.Reason != "timed out" {
		t.Fatalf("outcome %+v", o)
	}
	if n := len(r.f.creates()); n != 2 {
		t.Fatalf("%d machines, want 2 attempts", n)
	}
	waitFor(t, "machines destroyed", func() bool { return r.f.live() == 0 })
}

// RES-1: a preempted clean room is resumed on the same socket.
func TestPreemptedCleanRoomResumes(t *testing.T) {
	r := newRig(t, nil)
	release := make(chan struct{})
	r.f.guest = func(id, dir string) {
		r.f.set(id, func(m *vm.Machine) { m.State = vm.Preempted })
		<-release
		call(client(dir), "POST", "/cleanroom/result", goodResult())
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "resume", func() bool { r.f.mu.Lock(); defer r.f.mu.Unlock(); return len(r.f.resumed) > 0 })
	close(release)
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if o := r.outcomes()[0]; o.Result != "built" {
		t.Fatalf("outcome %+v", o)
	}
}

// A machine that cannot be created (no spare capacity) leaves the job
// queued without spending an attempt.
func TestNoCapacityKeepsJobQueued(t *testing.T) {
	r := newRig(t, nil)
	r.f.createErr = fmt.Errorf("vm: %w", admission.ErrNoRoom)
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	time.Sleep(100 * time.Millisecond)
	jobs, _ := r.b.queued()
	if len(jobs) != 1 || jobs[0].Attempts != 0 || len(r.outcomes()) != 0 {
		t.Fatalf("jobs %+v outcomes %v", jobs, r.outcomes())
	}
	r.f.mu.Lock()
	r.f.createErr = nil
	r.f.guest = func(id, dir string) { call(client(dir), "POST", "/cleanroom/result", goodResult()) }
	r.f.mu.Unlock()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
}

// A restart keeps queued jobs and destroys clean rooms a previous run left
// behind; other machines are untouched.
func TestRestartKeepsQueueAndDestroysLeftovers(t *testing.T) {
	r := newRig(t, nil)
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	f := r.f
	f.ms["cr-old"] = &vm.Machine{ID: "cr-old", State: vm.Stopped}
	f.ms["owner-task"] = &vm.Machine{ID: "owner-task", State: vm.Running, Label: vm.Private}
	b2, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.svc = b2.Services(nil)
	f.guest = func(id, dir string) { call(client(dir), "POST", "/cleanroom/result", goodResult()) }
	r.b = b2
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if _, err := f.Get("cr-old"); err == nil {
		t.Fatal("leftover clean room not destroyed")
	}
	if _, err := f.Get("owner-task"); err != nil {
		t.Fatal("non-clean-room machine destroyed")
	}
}

// OSS-2: the services mux never hands a clean-room ID to the guest plane,
// and serves a clean-room ID only while its job runs; every other machine
// goes to the plane.
func TestServicesKeepCleanRoomsOffThePlane(t *testing.T) {
	r := newRig(t, nil)
	plane := &recSvc{}
	svc := r.b.Services(plane)
	if _, err := svc.Open("cr-123456789abc"); err == nil {
		t.Fatal("clean-room ID with no job was served")
	}
	if _, err := svc.Open("owner-task"); err != nil {
		t.Fatal(err)
	}
	svc.Close("cr-123456789abc")
	svc.Close("owner-task")
	if strings.Join(plane.calls, ",") != "open owner-task,close owner-task" {
		t.Fatalf("plane saw %v", plane.calls)
	}
}

type recSvc struct{ calls []string }

func (s *recSvc) Open(id string) (string, error) {
	s.calls = append(s.calls, "open "+id)
	return "/plane/" + id, nil
}
func (s *recSvc) Close(id string) { s.calls = append(s.calls, "close "+id) }

// OSS-3: an artifact's files are checked against its manifest when read.
func TestArtifactTamperIsDetected(t *testing.T) {
	r := newRig(t, nil)
	a, err := r.b.store.put(Manifest{ID: "a-x"}, map[string]string{"f": "clean"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.dir, "files", "f"), []byte("swapped"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadFile("f"); err == nil {
		t.Fatal("tampered file read without error")
	}
	if _, err := a.ReadFile("other"); !errors.Is(err, ErrNoArtifact) {
		t.Fatal(err)
	}
	if _, err := r.b.store.Get("../a-x"); !errors.Is(err, ErrNoArtifact) {
		t.Fatal("path escape in artifact ID")
	}
}

func TestStateIsBrokerOnly(t *testing.T) {
	r := newRig(t, nil)
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	for _, d := range []string{"", "queue", "sockets", "artifacts"} {
		fi, err := os.Stat(filepath.Join(r.cfg.Dir, d))
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", d, fi.Mode(), err)
		}
	}
	jobs, _ := r.b.queued()
	fi, _ := os.Stat(jobs[0].path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatal(fmt.Sprint("job file mode ", fi.Mode()))
	}
}

// R4: a Create error that is not about capacity spends an attempt, so a
// job that can never start leaves the queue.
func TestPermanentCreateErrorSpendsAttempts(t *testing.T) {
	r := newRig(t, nil)
	r.f.createErr = fmt.Errorf("vm: %w: image", vm.ErrUnknown)
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "outcome", func() bool { return len(r.outcomes()) == 1 })
	if o := r.outcomes()[0]; o.Result != "failed" {
		t.Fatalf("outcome %+v", o)
	}
}

// hint.Outbox: Send is idempotent by day; a resend of a day already taken
// queues nothing, even after the first batch was built and left the queue.
func TestSendIsIdempotentByDay(t *testing.T) {
	r := newRig(t, nil)
	batch := [][]byte{skillHint(t), vulnHint(t)}
	if err := r.b.Send("2026-10-04", batch); err != nil {
		t.Fatal(err)
	}
	if err := r.b.Send("2026-10-04", batch); err != nil {
		t.Fatal(err)
	}
	jobs, _ := r.b.queued()
	if len(jobs) != 2 || jobs[0].Day != "2026-10-04" {
		t.Fatalf("queued %+v", jobs)
	}
	for _, j := range jobs {
		os.Remove(j.path) // as if built
	}
	if err := r.b.Send("2026-10-04", batch); err != nil {
		t.Fatal(err)
	}
	// A restart keeps the record of days taken.
	b2, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := b2.Send("2026-10-04", batch); err != nil {
		t.Fatal(err)
	}
	if jobs, _ := b2.queued(); len(jobs) != 0 {
		t.Fatalf("resent day queued again: %d jobs", len(jobs))
	}
	for _, d := range []string{"", "2026-1-4", "2026-13-01", "../x", "2026-10-04T00:00"} {
		if err := r.b.Send(d, batch); !errors.Is(err, ErrHint) {
			t.Errorf("day %q: %v", d, err)
		}
	}
}

// Potency PR1: a hint identical to one queued or already built is not
// built again; the outcome log records it as coalesced.
func TestIdenticalHintsCoalesce(t *testing.T) {
	r := newRig(t, nil)
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.b.Send(nextDay(), [][]byte{skillHint(t), vulnHint(t)})
	jobs, _ := r.b.queued()
	if len(jobs) != 2 {
		t.Fatalf("%d jobs, want the repeat coalesced", len(jobs))
	}
	r.f.guest = func(id, dir string) { call(client(dir), "POST", "/cleanroom/result", goodResult()) }
	r.run()
	waitFor(t, "built", func() bool { return len(r.outcomes()) == 3 })
	r.f.wg.Wait()
	r.b.Send(nextDay(), [][]byte{vulnHint(t)})
	waitFor(t, "coalesced", func() bool { return len(r.outcomes()) == 4 })
	var coalesced, built int
	for _, o := range r.outcomes() {
		switch o.Result {
		case "coalesced":
			coalesced++
		case "built":
			built++
		}
	}
	if coalesced != 2 || built != 2 || len(r.f.creates()) != 2 {
		t.Fatalf("outcomes %+v, %d machines", r.outcomes(), len(r.f.creates()))
	}
}

// Potency PR2: a clean room that needs public material it cannot reach
// says so with a fixed reason; the job is parked, and Requeue runs it
// again on a fresh machine.
func TestNeedsPublicMaterialParksAndRequeues(t *testing.T) {
	r := newRig(t, nil)
	var codes []int
	var mu sync.Mutex
	first := true
	r.f.guest = func(id, dir string) {
		c := client(dir)
		mu.Lock()
		f := first
		first = false
		mu.Unlock()
		if !f {
			call(c, "POST", "/cleanroom/result", goodResult())
			return
		}
		bad, _ := call(c, "POST", "/cleanroom/unable", []byte(`{"reason":"my bank changed its login page"}`))
		good, _ := call(c, "POST", "/cleanroom/unable", []byte(`{"reason":"needs_public_material"}`))
		mu.Lock()
		codes = append(codes, bad, good)
		mu.Unlock()
	}
	r.b.Send(nextDay(), [][]byte{skillHint(t)})
	r.run()
	waitFor(t, "parked", func() bool { return len(r.outcomes()) == 1 })
	r.f.wg.Wait()
	if o := r.outcomes()[0]; o.Result != "parked" || len(codes) != 2 || codes[0] != 400 || codes[1] != 200 {
		t.Fatalf("outcome %+v codes %v", o, codes)
	}
	if jobs, _ := r.b.queued(); len(jobs) != 0 {
		t.Fatal("parked job still queued")
	}
	if n, err := r.b.Requeue(); n != 1 || err != nil {
		t.Fatalf("requeue %d %v", n, err)
	}
	waitFor(t, "built", func() bool { return len(r.outcomes()) == 2 })
	r.f.wg.Wait()
	if o := r.outcomes()[1]; o.Result != "built" {
		t.Fatalf("outcome %+v", o)
	}
}

// R1, OSS-3: a result stored while the job failed is removed, so the
// store never holds a publishable artifact from a failed job.
func TestResultStoredAfterFailureIsRemoved(t *testing.T) {
	r := newRig(t, nil)
	s := &session{b: r.b, id: "cr-x", job: &job{ID: "x", Hint: string(skillHint(t))}, kind: "skill_gap", done: make(chan struct{})}
	r.f.ms["cr-x"] = &vm.Machine{ID: "cr-x", Spec: vm.Spec{Image: "cleanroom"}}
	// The job fails between the clean check and storing the result.
	r.f.onGet = func(string) { s.fail("machine stopped being clean") }
	w := httptest.NewRecorder()
	s.result(w, httptest.NewRequest("POST", "/cleanroom/result", bytes.NewReader(goodResult())))
	pub, _ := r.b.Store().Publishable()
	if w.Code == 200 || len(pub) != 0 {
		t.Fatalf("code %d, %d publishable", w.Code, len(pub))
	}
}
