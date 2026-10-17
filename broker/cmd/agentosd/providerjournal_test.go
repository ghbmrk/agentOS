package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/provagent"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/workers"
)

// REQ: OP-8

// Synthetic canaries: neither may reach the journal.
const (
	canaryBrief  = "brief-canary-7f3e1c do the subtask"
	canaryResult = "result-canary-b52d90 the answer"
)

// notes is an egressRecorder that keeps what it is given.
type notes struct {
	mu sync.Mutex
	n  []journal.EgressNote
}

func (s *notes) RecordEgress(n journal.EgressNote) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n = append(s.n, n)
	return nil
}

// runHost is a provagent.Host whose CLI writes result: the first Exec is
// the CLI, the next reads the result file.
type runHost struct {
	mu      sync.Mutex
	result  string
	created []string
	execs   int
}

func (h *runHost) CreateProviderWorker(_ context.Context, id string, _ vm.Spec, _ map[string][]byte) (vm.Machine, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.created = append(h.created, id)
	return vm.Machine{}, nil
}

func (h *runHost) Exec(_ context.Context, _ string, c vm.Command, _ time.Duration) (vm.ExecResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.execs++
	if len(c.Argv) == 2 && c.Argv[0] == "cat" {
		return vm.ExecResult{Stdout: []byte(h.result)}, nil
	}
	return vm.ExecResult{Stdout: []byte("cli chatter " + canaryResult)}, nil
}

func (h *runHost) Destroy(context.Context, string) error { return nil }

type okSeeder struct{}

func (okSeeder) Seed(string, string) (map[string][]byte, error) { return map[string][]byte{}, nil }
func (okSeeder) Close(string)                                   {}

// meteredRunner is agentosd's runner with every gate open on Codex, a host
// that runs, and its Journal and Charge wired to rec and a meter allowing
// calls calls per machine.
func meteredRunner(t *testing.T, calls int64) (*provagent.Runner, *runHost, *notes, *meter.Meter) {
	t.Helper()
	mtr, err := meter.Open(meter.Config{
		Path:           filepath.Join(t.TempDir(), "meter.json"),
		MachineCap:     meter.Limits{Calls: calls, Tokens: 1000},
		OverallCap:     meter.Limits{Calls: 100, Tokens: 100000},
		DailyExtension: meter.Limits{Calls: 1, Tokens: 1},
		Notify:         func(meter.Exhausted) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	h, rec := &runHost{result: canaryResult}, &notes{}
	r := providerRunner(nil, nil, nil, nil)
	r.Host, r.Seeder = h, okSeeder{}
	q := r.Decls["codex"].Q.CLIVersion
	r.ImageVersion = func(string) string { return q }
	r.Granted = func(string) bool { return true }
	r.PrivateOK = func(string) bool { return true }
	r.Consent = func(string) bool { return true }
	r.Usage = func(string) (provagent.Usage, error) {
		return provagent.Usage{Readings: []provagent.Reading{{Pool: "primary", Left: 0.9, At: time.Now()}, {Pool: "secondary", Left: 0.9, At: time.Now()}}}, nil
	}
	r.Reserve = func(string, string) float64 { return 0.1 }
	r.PerPool = 1
	meterProviderRuns(r, rec, mtr)
	return r, h, rec, mtr
}

func codexReq(machine string) provagent.Request {
	return provagent.Request{Machine: machine, Provider: "codex", Brief: canaryBrief, TaskClass: "code", Label: vm.Public, Class: admission.Accepted, MemMB: 512}
}

func TestProviderRunnerHasJournal(t *testing.T) {
	r := providerRunner(nil, nil, nil, nil)
	if r.Journal == nil {
		t.Fatal("providerRunner leaves Journal nil")
	}
	meterProviderRuns(r, &notes{}, nil)
	if r.Journal == nil || r.Charge == nil {
		t.Fatal("meterProviderRuns leaves Journal or Charge nil")
	}
	// No meter: a run is refused, never charged to nobody.
	if _, err := r.Charge("wk-a"); err == nil {
		t.Fatal("charged with no meter")
	}
}

func TestProviderRunWritesOneEntryWithNoBrief(t *testing.T) {
	r, _, rec, _ := meteredRunner(t, 5)
	out, err := r.Run(context.Background(), codexReq("wk-a"))
	if err != nil || out != canaryResult {
		t.Fatalf("run: %q %v", out, err)
	}
	if len(rec.n) != 1 {
		t.Fatalf("%d journal entries", len(rec.n))
	}
	n := rec.n[0]
	all := fmt.Sprintf("%+v", n)
	for _, c := range []string{"brief-canary", "result-canary", "cli chatter"} {
		if strings.Contains(all, c) {
			t.Errorf("entry carries %q: %s", c, all)
		}
	}
	if n.Machine != "wk-a" || n.Adapter != "provider-codex" || n.Operation != "code" ||
		!strings.Contains(n.Reason, "ok") || !strings.Contains(n.Reason, fmt.Sprint(len(canaryResult))) {
		t.Errorf("entry %s", all)
	}
	// The engine takes the entry as written: its identifiers are tokens.
	eng, err := journal.Open(&journal.MemStore{}, allowAll{}, nil, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.RecordEgress(n); err != nil {
		t.Errorf("engine refused the entry: %v", err)
	}
}

func TestProviderRunChargesTheCallerMachine(t *testing.T) {
	r, _, rec, mtr := meteredRunner(t, 5)
	for i := 0; i < 2; i++ {
		if _, err := r.Run(context.Background(), codexReq("wk-a")); err != nil {
			t.Fatal(err)
		}
	}
	if u := mtr.Usage("wk-a"); u.Calls != 2 || u.Tokens != 0 {
		t.Errorf("wk-a usage %+v, want 2 calls and 0 tokens", u)
	}
	if u := mtr.Usage("wk-b"); u.Calls != 0 {
		t.Errorf("wk-b charged: %+v", u)
	}
	// The worker tool's caller machine is what agentosd's adapter charges.
	if _, err := (providerTool{r}).Run(context.Background(), workers.ProviderRequest{Machine: "wk-c", Provider: "codex", Brief: canaryBrief, TaskClass: "code", Label: vm.Public}); err != nil {
		t.Fatal(err)
	}
	if u := mtr.Usage("wk-c"); u.Calls != 1 {
		t.Errorf("providerTool charged wk-c %+v", u)
	}
	// No caller: journaled unattributed and refused, never charged.
	if _, err := r.Run(context.Background(), codexReq("")); err == nil {
		t.Fatal("an unattributed run ran")
	}
	if last := rec.n[len(rec.n)-1]; last.Machine != unattributed || !strings.Contains(last.Reason, "failed") {
		t.Errorf("unattributed entry %+v", last)
	}
}

func TestProviderRunRefusedAtMachineCap(t *testing.T) {
	r, h, rec, mtr := meteredRunner(t, 1)
	if _, err := r.Run(context.Background(), codexReq("wk-a")); err != nil {
		t.Fatal(err)
	}
	created := len(h.created)
	_, err := r.Run(context.Background(), codexReq("wk-a"))
	var ref *provagent.Refusal
	if !errors.As(err, &ref) || ref.Reason != provagent.UsedUp {
		t.Fatalf("at the cap: %v", err)
	}
	if len(h.created) != created {
		t.Errorf("a VM started at the cap: %v", h.created)
	}
	if u := mtr.Usage("wk-a"); u.Calls != 1 {
		t.Errorf("usage %+v after a refusal", u)
	}
	if last := rec.n[len(rec.n)-1]; !strings.Contains(last.Reason, string(provagent.UsedUp)) {
		t.Errorf("refusal entry %+v", last)
	}
	// The provider slot (PerPool 1) is free: another machine runs.
	if _, err := r.Run(context.Background(), codexReq("wk-b")); err != nil {
		t.Errorf("slot kept by the refused run: %v", err)
	}
}
