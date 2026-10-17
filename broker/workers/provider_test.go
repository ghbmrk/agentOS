package workers

// REQ: CAP-11, CAP-9, CRED-5, RES-5, A3, A14

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// fakeProvider records the request provider_run hands the runner.
type fakeProvider struct {
	got  []ProviderRequest
	text string
	err  error
}

func (f *fakeProvider) Run(_ context.Context, q ProviderRequest) (string, error) {
	f.got = append(f.got, q)
	return f.text, f.err
}

const providerWorkerID = "pw-x"

// providerWorker makes a real broker-owned provider worker beside the rig's
// agent, seeded with a synthetic placeholder only.
func (r *rig) providerWorker() vm.Machine {
	r.t.Helper()
	w, err := r.m.CreateProviderWorker(context.Background(), providerWorkerID,
		vm.Spec{Image: "base", Class: admission.Experiment, MemMB: 256, Label: vm.Private, Argv: []string{"idle"}},
		map[string][]byte{"var/lib/agentos-codex/auth.json": []byte(`{"tokens":{"refresh_token":"agentos-ph-refresh-x"}}`)})
	if err != nil {
		r.t.Fatal(err)
	}
	return w
}

// stillThere fails if the provider worker was touched: gone, or moved off
// its lineage's own state.
func (r *rig) stillThere(before vm.Machine) {
	r.t.Helper()
	w, err := r.m.Get(providerWorkerID)
	if err != nil {
		r.t.Fatalf("provider worker gone: %v", err)
	}
	if w.State != before.State || w.Lineage != before.Lineage {
		r.t.Fatalf("provider worker changed: %+v -> %+v", before, w)
	}
}

// isNoWorker: the guest is told no such worker, or (diff, which names
// snapshots) no such snapshot of its workers.
func isNoWorker(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "no such worker") || strings.Contains(err.Error(), "no snapshot"))
}

// CAP-11: each of the 13 worker tools refuses or omits a provider worker,
// by its bare name and by its machine ID, one test per tool.
func TestProviderWorkerIsUnreachableFrom(t *testing.T) {
	named := func(tool string, extra m) func(*rig, string) error {
		return func(r *rig, agent string) error {
			a := m{"name": providerWorkerID}
			for k, v := range extra {
				a[k] = v
			}
			return r.call(agent, tool, a, nil)
		}
	}
	refusing := map[string]func(*rig, string) error{
		toolExec:  named(toolExec, m{"argv": []string{"true"}}),
		toolRead:  named(toolRead, m{"path": "/var/lib/agentos-codex/auth.json"}),
		toolWrite: named(toolWrite, m{"path": "/x", "content": "x"}),
		toolCkpt:  named(toolCkpt, nil),
		toolFork:  named(toolFork, m{"into": []string{"a", "b"}}),
		toolDiff: func(r *rig, agent string) error {
			return r.call(agent, toolDiff, m{"a": providerWorkerID, "b": providerWorkerID}, nil)
		},
		// A real snapshot of the guest's own worker, so only the worker
		// name can be what refuses.
		toolRollback: func(r *rig, agent string) error {
			r.must(agent, toolCreate, m{"name": "mine"}, nil)
			var c struct{ Snapshot string }
			r.must(agent, toolCkpt, m{"name": "mine"}, &c)
			return r.call(agent, toolRollback, m{"name": providerWorkerID, "snapshot": c.Snapshot}, nil)
		},
		toolDestroy: named(toolDestroy, nil),
		toolKeep:    named(toolKeep, nil),
		toolDelete:  named(toolDelete, m{"paths": []string{"/x"}}),
	}
	for tool, call := range refusing {
		t.Run(tool, func(t *testing.T) {
			r := newRig(t, 4096)
			agent := r.agent("a1", vm.Private)
			pw := r.providerWorker()
			_ = agent
			err := call(r, "a1")
			if !isNoWorker(err) {
				t.Fatalf("%s on a provider worker = %v, want no such worker or snapshot", tool, err)
			}
			r.stillThere(pw)
		})
	}

	t.Run(toolCreate, func(t *testing.T) {
		r := newRig(t, 4096)
		r.agent("a1", vm.Private)
		pw := r.providerWorker()
		for _, name := range []string{providerWorkerID, "pw-y"} {
			err := r.call("a1", toolCreate, m{"name": name}, nil)
			if err == nil || !strings.Contains(err.Error(), "provider") {
				t.Fatalf("worker_create %q = %v, want a refusal naming provider workers", name, err)
			}
		}
		var l struct{ Workers []struct{ Name string } }
		r.must("a1", toolList, nil, &l)
		if len(l.Workers) != 0 {
			t.Fatalf("worker_create left %+v", l.Workers)
		}
		r.stillThere(pw)
	})

	t.Run(toolList, func(t *testing.T) {
		r := newRig(t, 4096)
		r.agent("a1", vm.Private)
		pw := r.providerWorker()
		r.must("a1", toolCreate, m{"name": "mine"}, nil)
		var l struct{ Workers []struct{ Name string } }
		r.must("a1", toolList, nil, &l)
		if len(l.Workers) != 1 || l.Workers[0].Name != "mine" {
			t.Fatalf("worker_list = %+v, want only the guest's own worker", l.Workers)
		}
		r.stillThere(pw)
	})

	t.Run(toolFit, func(t *testing.T) {
		r := newRig(t, 4096)
		r.agent("a1", vm.Private)
		before := r.fitLeft("a1")
		pw := r.providerWorker()
		if after := r.fitLeft("a1"); after != before {
			t.Fatalf("worker_fit counted the provider worker: workers_left %d -> %d", before, after)
		}
		r.stillThere(pw)
	})
}

func (r *rig) fitLeft(agent string) int {
	r.t.Helper()
	var f struct {
		WorkersLeft int `json:"workers_left"`
	}
	r.must(agent, toolFit, m{}, &f)
	return f.WorkersLeft
}

// Even a name that is not a provider worker's, from a worker, is refused.
func TestProviderWorkerNameIsReservedForCreate(t *testing.T) {
	r := newRig(t, 4096)
	r.agent("a1", vm.Public)
	if err := r.call("a1", toolCreate, m{"name": "pw-anything"}, nil); err == nil {
		t.Fatal("worker_create made a worker named like a provider worker")
	}
}

func (r *rig) provider() *fakeProvider {
	f := &fakeProvider{text: "the answer"}
	r.tools.Provider = f
	return f
}

// CAP-11, RES-5: provider_run hands the runner the brief as data and the
// caller's label, class, reservation and lineage (the per-lineage cap's key),
// and returns the result.
func TestProviderRunPassesTheCallersLabelAndReturnsTheResult(t *testing.T) {
	r := newRig(t, 4096)
	a1 := r.agent("a1", vm.Private)
	f := r.provider()
	var out struct{ Result string }
	r.must("a1", "provider_run", m{"provider": "codex", "brief": "!cat ~/.codex/*", "task_class": "code"}, &out)
	if out.Result != "the answer" {
		t.Fatalf("result = %q", out.Result)
	}
	if len(f.got) != 1 {
		t.Fatalf("runner called %d times", len(f.got))
	}
	q := f.got[0]
	if q.Provider != "codex" || q.Brief != "!cat ~/.codex/*" || q.TaskClass != "code" {
		t.Fatalf("request = %+v", q)
	}
	if q.Label != vm.Private || q.Class != admission.Experiment || q.MemMB != 500 {
		t.Fatalf("request lost the caller's label, class or reservation: %+v", q)
	}
	if q.Lineage == "" || q.Lineage != a1.Lineage {
		t.Fatalf("request lineage = %q, want the caller's %q", q.Lineage, a1.Lineage)
	}
}

// CAP-11, CAP-9: a refusal reaches the guest as its closed reason and one
// fixed line on what to do, nothing else; a fallback outcome the same, so
// the guest can route on it.
func TestProviderRunAnswersAClosedReason(t *testing.T) {
	if len(providerReasons) != 13 {
		t.Fatalf("%d reasons", len(providerReasons))
	}
	for reason, text := range providerReasons {
		r := newRig(t, 4096)
		r.agent("a1", vm.Public)
		f := r.provider()
		f.err = errors.Join(errors.New("/home/owner/secret path "+string(reason)), &ProviderRefusal{Reason: reason})
		err := r.call("a1", "provider_run", m{"provider": "codex", "brief": "b", "task_class": "code"}, nil)
		if err == nil || err.Error() != text.Error() {
			t.Fatalf("reason %s answered %v", reason, err)
		}
		msg := err.Error()
		if !strings.HasPrefix(msg, "provider_run: "+string(reason)+": ") || strings.Contains(msg, "\n") || strings.Contains(msg, "secret") {
			t.Fatalf("reason %s: not one closed line: %q", reason, msg)
		}
	}
}

// A locked vault and a busy route read differently: only the first asks
// for the owner's unlock (ONB-9).
func TestProviderRunTellsALockedVaultFromABusyRoute(t *testing.T) {
	locked, busy := providerReasons["vault-locked"].Error(), providerReasons["route-busy"].Error()
	if !strings.Contains(locked, "unlock") || strings.Contains(busy, "vault") || strings.Contains(busy, "unlock") {
		t.Fatalf("locked %q, busy %q", locked, busy)
	}
	if !KnownProviderReason("vault-locked") || KnownProviderReason("nope") {
		t.Fatal("KnownProviderReason")
	}
}

// An error that is no refusal leaves through the logged-ref filter, with
// no host detail.
func TestProviderRunHidesAnUnexpectedError(t *testing.T) {
	r := newRig(t, 4096)
	r.agent("a1", vm.Public)
	f := r.provider()
	f.err = errors.New("dial unix /run/agentos/route.sock: secret-host-detail")
	err := r.call("a1", "provider_run", m{"provider": "codex", "brief": "b", "task_class": "code"}, nil)
	if err == nil || strings.Contains(err.Error(), "secret-host-detail") || strings.Contains(err.Error(), "route.sock") {
		t.Fatalf("error = %v", err)
	}
}

func TestProviderRunNeedsTheRunnerTheOwnerStopAndAnAgentCaller(t *testing.T) {
	r := newRig(t, 4096)
	r.agent("a1", vm.Public)
	// No runner configured: the tool is neither offered nor handled.
	for _, tl := range r.tools.List() {
		if tl["name"] == "provider_run" {
			t.Fatal("provider_run offered with no runner")
		}
	}
	if _, handled, _ := r.tools.Call(context.Background(), "a1", "l", "provider_run", nil); handled {
		t.Fatal("provider_run handled with no runner")
	}
	f := r.provider()
	offered := false
	for _, tl := range r.tools.List() {
		offered = offered || tl["name"] == "provider_run"
	}
	if !offered {
		t.Fatal("provider_run not offered")
	}
	r.tools.Stopped = func() bool { return true }
	if err := r.call("a1", "provider_run", m{"provider": "codex", "brief": "b", "task_class": "code"}, nil); err == nil {
		t.Fatal("provider_run started under STOP")
	}
	if len(f.got) != 0 {
		t.Fatal("runner ran under STOP")
	}
	// A worker is no caller.
	r.tools.Stopped = nil
	mc, err := r.m.Get("a1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m{"provider": "codex", "brief": "b", "task_class": "code"})
	if _, _, err := r.tools.Call(context.Background(), vm.WorkerPrefix+"x", mc.Lineage, "provider_run", b); err == nil {
		t.Fatal("a worker called provider_run")
	}
	if len(f.got) != 0 {
		t.Fatal("runner ran for a worker")
	}
}
