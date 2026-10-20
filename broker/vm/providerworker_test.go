package vm

// REQ: CRED-1, CRED-5, A14, CAP-8, OP-6

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
)

// placeholderAuth stands for the seed the vault process hands vm: a
// placeholder auth file, never a real credential.
const placeholderAuth = `{"tokens":{"refresh_token":"agentos-ph-refresh-x"}}`

func (e *env) providerWorker(id string) Machine {
	e.t.Helper()
	w, err := e.m.CreateProviderWorker(bg, id, workerSpec(Private),
		map[string][]byte{"var/lib/agentos-codex/auth.json": []byte(placeholderAuth)})
	must(e.t, err)
	return w
}

// CRED-5: the placeholder file lands in the worker's own layer, and the
// worker is private, with no guest services and its own lineage.
func TestProviderWorkerIsSeededWithThePlaceholderFile(t *testing.T) {
	e := newEnv(t, 4096)
	svc := &recServices{root: t.TempDir(), open: map[string]bool{}}
	e.cfg.Services = svc
	e.open()
	w := e.providerWorker("pw-a1")
	if w.Label != Private {
		t.Fatalf("label = %v", w.Label)
	}
	if got := e.guestRead("pw-a1", "var/lib/agentos-codex/auth.json"); got != placeholderAuth {
		t.Fatalf("auth.json = %q", got)
	}
	if svc.open["pw-a1"] {
		t.Fatal("a provider worker got guest services")
	}
	r, err := e.m.Exec(bg, "pw-a1", Command{As: Private, Argv: []string{"cat", "var/lib/agentos-codex/auth.json"}}, time.Second)
	must(t, err)
	if !bytes.Equal(r.Stdout, []byte(placeholderAuth)) {
		t.Fatalf("exec read %q", r.Stdout)
	}
}

func TestProviderWorkerNeedsPrivateAndItsPrefix(t *testing.T) {
	e := newEnv(t, 4096)
	e.open()
	seed := map[string][]byte{"auth.json": []byte(placeholderAuth)}
	if _, err := e.m.CreateProviderWorker(bg, "pw-x", workerSpec(Public), seed); !errors.Is(err, ErrSeedLabel) {
		t.Fatalf("public provider worker = %v, want ErrSeedLabel", err)
	}
	if _, err := e.m.CreateProviderWorker(bg, "wk-x", workerSpec(Private), seed); err == nil {
		t.Fatal("CreateProviderWorker made a non-pw- machine")
	}
	if _, err := e.m.Create(bg, "pw-y", workerSpec(Private)); err == nil || !strings.Contains(err.Error(), "provider workers") {
		t.Fatalf("Create made a pw- machine: %v", err)
	}
	if _, err := e.m.CreateSeeded(bg, "pw-z", workerSpec(Private), seed); err == nil {
		t.Fatal("CreateSeeded made a pw- machine")
	}
}

// Provider workers are broker-owned: no lineage lists them.
func TestWorkersOmitsAProviderWorker(t *testing.T) {
	e := newEnv(t, 4096)
	e.open()
	agent := e.create("agent", admission.Experiment, 500)
	w := e.providerWorker("pw-a1")
	_, err := e.m.CreateWorker(bg, "wk-a1", agent.Lineage, workerSpec(Private))
	must(t, err)
	for _, lin := range []string{agent.Lineage, w.Lineage} {
		for _, id := range e.m.Workers(lin) {
			if strings.HasPrefix(id, ProviderPrefix) {
				t.Fatalf("Workers(%s) lists %s", lin, id)
			}
		}
	}
	if got := e.m.Workers(agent.Lineage); len(got) != 1 || got[0] != "wk-a1" {
		t.Fatalf("Workers = %v", got)
	}
}

// Snapshot, checkpoint, sleep, fork (as source or target), rollback and
// merge all refuse a provider worker, and none changes it.
func TestProviderWorkerTakesNoSnapshotForkRollbackOrMerge(t *testing.T) {
	e := newEnv(t, 4096)
	e.open()
	e.create("agent", admission.Experiment, 500)
	e.providerWorker("pw-a1")
	snap, err := e.m.Step(bg, "agent")
	must(t, err)
	before := len(e.m.Snapshots("pw-a1")) + len(e.m.Snapshots("agent"))

	refused := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, ErrProviderWorker) {
			t.Fatalf("%s = %v, want ErrProviderWorker", name, err)
		}
	}
	_, err = e.m.Step(bg, "pw-a1")
	refused("Step", err)
	_, err = e.m.Checkpoint(bg, "pw-a1")
	refused("Checkpoint", err)
	_, err = e.m.CheckpointAndStop(bg, "pw-a1")
	refused("CheckpointAndStop", err)
	_, err = e.m.Fork(bg, "pw-a1", []string{"pw-a2"})
	refused("Fork source", err)
	_, err = e.m.Fork(bg, "agent", []string{"pw-a3"})
	refused("Fork target", err)
	refused("Rollback", e.m.Rollback(bg, "pw-a1", snap.ID))
	_, err = e.m.Merge(bg, "agent", "pw-a1")
	refused("Merge src", err)
	_, err = e.m.Merge(bg, "pw-a1", "agent")
	refused("Merge dst", err)
	_, err = e.m.Park(bg, "pw-a1")
	if err == nil {
		t.Fatal("Park took a provider worker")
	}
	if got := len(e.m.Snapshots("pw-a1")) + len(e.m.Snapshots("agent")); got != before {
		t.Fatalf("snapshots %d -> %d", before, got)
	}
	if m, err := e.m.Get("pw-a1"); err != nil || m.State != Running {
		t.Fatalf("provider worker = %+v, %v after refusals", m, err)
	}
}

// OP-6 (#2481): STOP ends a provider run in flight. The reaper calls
// EndCommands while STOP holds; it reaches pw- commands as well as wk-
// ones, and the worker stays up for the runner to destroy.
func TestEndCommandsEndsAProviderRunInFlight(t *testing.T) {
	e := newEnv(t, 4096)
	e.open()
	e.providerWorker("pw-a1")
	done := make(chan error, 1)
	go func() {
		_, err := e.m.Exec(bg, "pw-a1", Command{As: Private, Argv: []string{"sleep"}}, 10*time.Minute)
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for e.m.EndCommands() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("EndCommands found no provider command in flight")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an ended provider command reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("EndCommands did not end the provider command")
	}
	w, err := e.m.Get("pw-a1")
	must(t, err)
	if w.State != Running {
		t.Fatalf("provider worker is %s after its command ended", w.State)
	}
}
