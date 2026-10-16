package vm

// REQ: A14, A3, CRED-5, CRED-1, CAP-8

import (
	"github.com/ghbmrk/agentos/broker/admission"
	"path/filepath"
	"strings"
	"testing"
)

// launchOf returns the latest launch of machine id.
func launchOf(t *testing.T, e *env, id string) Launch {
	t.Helper()
	e.rt.mu.Lock()
	defer e.rt.mu.Unlock()
	for i := len(e.rt.launches) - 1; i >= 0; i-- {
		if e.rt.launches[i].ID == id {
			return e.rt.launches[i]
		}
	}
	t.Fatalf("%s never launched", id)
	return Launch{}
}

// A provider worker is launched with its own route directory from
// Config.ProviderRoutes and nothing from Config.Services; no other machine
// gets a route directory (#1755: the socket exists only for a broker-held
// provider's worker).
func TestProviderWorkerGetsOnlyItsRouteDirectory(t *testing.T) {
	e := newEnv(t, 8192)
	svc := &recServices{root: t.TempDir(), open: map[string]bool{}}
	routes := &recServices{root: t.TempDir(), open: map[string]bool{}}
	e.cfg.Services, e.cfg.ProviderRoutes = svc, routes
	e.open()
	agent := e.create("agent", admission.Experiment, 256)
	_, err := e.m.CreateWorker(bg, "wk-a1", agent.Lineage, workerSpec(Private))
	must(t, err)
	e.providerWorker("pw-a1")

	if got, want := launchOf(t, e, "pw-a1").Services, filepath.Join(routes.root, "pw-a1"); got != want {
		t.Fatalf("pw-a1 launched with services %q, want its route directory %q", got, want)
	}
	if got := launchOf(t, e, "wk-a1").Services; got != "" {
		t.Fatalf("a plain worker got %q", got)
	}
	if got := launchOf(t, e, "agent").Services; !strings.HasPrefix(got, svc.root) {
		t.Fatalf("the agent machine lost its guest services: %q", got)
	}
	if strings.Join(routes.opened, ",") != "pw-a1" {
		t.Fatalf("route directories opened for %v; want pw-a1 only", routes.opened)
	}
	for _, id := range svc.opened {
		if strings.HasPrefix(id, ProviderPrefix) || strings.HasPrefix(id, WorkerPrefix) {
			t.Fatalf("guest services opened for %s", id)
		}
	}

	must(t, e.m.Destroy(bg, "pw-a1"))
	if routes.open["pw-a1"] || len(routes.closed) == 0 {
		t.Fatal("destroying the provider worker left its route open")
	}
}

// A provider worker whose route cannot be opened does not start: it would
// otherwise run with no way out, or be given another machine's.
func TestProviderWorkerNeedsItsRoute(t *testing.T) {
	e := newEnv(t, 4096)
	routes := &recServices{root: t.TempDir(), open: map[string]bool{}, fail: true}
	e.cfg.ProviderRoutes = routes
	e.open()
	_, err := e.m.CreateProviderWorker(bg, "pw-a1", workerSpec(Private), map[string][]byte{"var/lib/agentos-codex/auth.json": []byte(placeholderAuth)})
	if err == nil {
		t.Fatal("provider worker started without its route")
	}
	if len(e.rt.launches) != 0 {
		t.Fatal("the runtime was started")
	}
}

// Without a ProviderRoutes the worker runs with no services at all, as
// before (the route is wired only when the vault process serves it).
func TestProviderWorkerWithoutRoutesHasNoServices(t *testing.T) {
	e := newEnv(t, 4096)
	e.cfg.Services = &recServices{root: t.TempDir(), open: map[string]bool{}}
	e.open()
	e.providerWorker("pw-a1")
	if got := launchOf(t, e, "pw-a1").Services; got != "" {
		t.Fatalf("got %q", got)
	}
}
