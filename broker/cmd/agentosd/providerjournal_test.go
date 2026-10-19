package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/journal"
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

func (okSeeder) Seed(string, string, bool) (map[string][]byte, error) {
	return map[string][]byte{}, nil
}
func (okSeeder) Close(string) {}

// journaledRunner is agentosd's runner with every gate open on Codex, a
// host that runs, and its Journal wired to rec.
func journaledRunner(t *testing.T) (*provagent.Runner, *runHost, *notes) {
	t.Helper()
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
	journalProviderRuns(r, rec)
	return r, h, rec
}

func codexReq(machine string) provagent.Request {
	return provagent.Request{Machine: machine, Provider: "codex", Brief: canaryBrief, TaskClass: "code", Label: vm.Public, Class: admission.Accepted, MemMB: 512}
}

func TestProviderRunnerHasJournal(t *testing.T) {
	r := providerRunner(nil, nil, nil, nil)
	if r.Journal == nil {
		t.Fatal("providerRunner leaves Journal nil")
	}
	journalProviderRuns(r, &notes{})
	if r.Journal == nil {
		t.Fatal("journalProviderRuns leaves Journal nil")
	}
}

func TestProviderRunWritesOneEntryWithNoBrief(t *testing.T) {
	r, _, rec := journaledRunner(t)
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

func TestProviderRunIsJournaledUnderTheCallerMachine(t *testing.T) {
	r, _, rec := journaledRunner(t)
	if _, err := r.Run(context.Background(), codexReq("wk-a")); err != nil {
		t.Fatal(err)
	}
	// The worker tool's caller machine is what agentosd's adapter journals.
	if _, err := (providerTool{r}).Run(context.Background(), workers.ProviderRequest{Machine: "wk-c", Provider: "codex", Brief: canaryBrief, TaskClass: "code", Label: vm.Public}); err != nil {
		t.Fatal(err)
	}
	// No caller: the run is journaled unattributed, not refused.
	if _, err := r.Run(context.Background(), codexReq("")); err != nil {
		t.Fatalf("an unattributed run: %v", err)
	}
	var got []string
	for _, n := range rec.n {
		got = append(got, n.Machine)
	}
	if strings.Join(got, ",") != "wk-a,wk-c,"+unattributed {
		t.Errorf("journaled machines %v", got)
	}
}

// A plan run is metered by its journal entry alone: it is never refused or
// counted by the spend meter, so many runs from one machine all run, each
// journaled once (OP-8 as #2291 wrote it: zero spend, bounded by plan
// quota and the reserve). journalProviderRuns takes no meter at all.
func TestPlanRunIsNeverRefusedOrCountedBySpendMeter(t *testing.T) {
	r, h, rec := journaledRunner(t)
	const runs = 8
	for i := 0; i < runs; i++ {
		if _, err := r.Run(context.Background(), codexReq("wk-a")); err != nil {
			t.Fatalf("run %d refused: %v", i, err)
		}
	}
	if len(h.created) != runs || len(rec.n) != runs {
		t.Errorf("%d VMs, %d journal entries, want %d each", len(h.created), len(rec.n), runs)
	}
	for _, n := range rec.n {
		if !strings.HasPrefix(n.Reason, "provider run ok") {
			t.Errorf("entry %+v", n)
		}
	}
}
