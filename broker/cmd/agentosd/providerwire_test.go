package main

// REQ: CAP-11, CRED-5, RES-5

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/provagent"
	"github.com/ghbmrk/agentos/broker/vm"
	"github.com/ghbmrk/agentos/broker/workers"
)

// The wired runner starts nothing until the rows that fill its inputs land:
// Codex's qualification record is empty (#809), Claude is an opt-in (#1380).
func TestProviderRunnerIsClosedByDefault(t *testing.T) {
	r := providerRunner(nil, nil, nil, nil)
	for provider, want := range map[string]provagent.Reason{"codex": provagent.Unqualified, "claude": provagent.OptInRequired} {
		_, err := r.Run(context.Background(), provagent.Request{Provider: provider, Brief: "b", TaskClass: "code",
			Label: vm.Public, Class: admission.Experiment, MemMB: 256})
		var ref *provagent.Refusal
		if !errors.As(err, &ref) || ref.Reason != want {
			t.Fatalf("%s = %v, want %s", provider, err, want)
		}
	}
	if r.Granted("codex") || r.PrivateOK("codex") || r.Consent("codex") {
		t.Fatal("an owner-side input is open before its row landed")
	}
}

// filledRunner is the wired runner once #809 fills the record and the
// owner grants the plan.
func filledRunner() *provagent.Runner {
	r := providerRunner(nil, nil, nil, nil)
	d := r.Decls["codex"]
	d.Q = provagent.Qualification{CLIVersion: "1", Evidence: "e", TermsURL: "https://t.test", TermsRead: "2026-10-01", Verdict: provagent.Allowed}
	r.Decls["codex"] = d
	r.ImageVersion = func(string) string { return "1" }
	r.Granted = func(string) bool { return true }
	return r
}

func runCodex(r *provagent.Runner) provagent.Reason {
	_, err := r.Run(context.Background(), provagent.Request{Provider: "codex", Brief: "b", TaskClass: "code",
		Label: vm.Public, Class: admission.Experiment, MemMB: 256})
	var ref *provagent.Refusal
	if !errors.As(err, &ref) {
		return ""
	}
	return ref.Reason
}

// RES-5 fails closed: a runner without plan usage wired refuses admission
// even once the record is filled; wirePlanUsage gives it the vault
// process's readings, and an unreachable control socket is a busy route.
func TestProviderRunnerRefusesWithoutPlanUsage(t *testing.T) {
	if got := runCodex(filledRunner()); got != provagent.PoolAtReserve {
		t.Fatalf("unwired = %s, want pool-at-reserve", got)
	}
	r := filledRunner()
	wirePlanUsage(r, modelroute.NewRouteControl(filepath.Join(t.TempDir(), "none.sock")))
	if got := runCodex(r); got != provagent.RouteBusy {
		t.Fatalf("unreachable = %s, want route-busy", got)
	}
	// A pool the provider reported exhausted, until its reset, refuses
	// before anything is seeded.
	var closed []string
	reset := time.Now().Add(time.Hour).Unix()
	body := fmt.Sprintf(`{"Pools":[{"At":%q,"Pool":"primary","UsedPercent":100,"ResetAt":%d}]}`, time.Now().Format(time.RFC3339Nano), reset)
	r = filledRunner()
	wirePlanUsage(r, controlServer(t, http.StatusOK, body, &closed))
	if got := runCodex(r); got != provagent.PoolAtReserve {
		t.Fatalf("used up = %s, want pool-at-reserve", got)
	}
}

// The usage adapter turns the vault process's percentages into shares
// left, an exhaustion into none, and unix reset times into times.
func TestPlanUsageAdapterMapsReadings(t *testing.T) {
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	refused := at.Add(time.Minute)
	body := fmt.Sprintf(`{"Pools":[
		{"At":%[1]q,"Pool":"primary","UsedPercent":25,"ResetAt":1760536800},
		{"At":%[1]q,"Pool":"secondary","UsedPercent":140},
		{"At":%[1]q,"Pool":"credits","UsedPercent":3,"Exhausted":true}],
		"LoginRefused":%[2]q}`, at.Format(time.RFC3339), refused.Format(time.RFC3339))
	var closed []string
	u, err := planUsage{controlServer(t, http.StatusOK, body, &closed)}.Usage("codex")
	if err != nil {
		t.Fatal(err)
	}
	want := []provagent.Reading{
		{Pool: "primary", Left: 0.75, At: at, ResetAt: time.Unix(1760536800, 0)},
		{Pool: "secondary", Left: 0, At: at},
		{Pool: "credits", Left: 0, At: at, Exhausted: true},
	}
	if len(u.Readings) != len(want) || !u.LoginRefused.Equal(refused) {
		t.Fatalf("%+v", u)
	}
	for i, w := range want {
		g := u.Readings[i]
		if g.Pool != w.Pool || g.Left != w.Left || !g.At.Equal(w.At) || !g.ResetAt.Equal(w.ResetAt) || g.Exhausted != w.Exhausted {
			t.Errorf("reading %d = %+v, want %+v", i, g, w)
		}
	}
	if _, err := (planUsage{}).Usage("codex"); err == nil {
		t.Error("no route control read as usage")
	}
	if ownerReserve("codex", "primary") != 0 {
		t.Error("the default reserve is not 0% (ONB-9)")
	}
}

// Every runner reason has a guest text in workers: the two lists are one.
func TestEveryProviderReasonHasAGuestText(t *testing.T) {
	for _, r := range provagent.Reasons() {
		if !workers.KnownProviderReason(workers.ProviderReason(r)) {
			t.Errorf("workers has no text for %s", r)
		}
	}
}

// The adapter hands the worker tools the closed reason only, never the
// runner's error.
func TestProviderToolPassesTheClosedReasonOnly(t *testing.T) {
	_, err := providerTool{providerRunner(nil, nil, nil, nil)}.Run(context.Background(), workers.ProviderRequest{Provider: "claude", Brief: "b", TaskClass: "code", Label: vm.Public})
	var ref *workers.ProviderRefusal
	if !errors.As(err, &ref) || ref.Reason != "opt-in-required" {
		t.Fatalf("= %v", err)
	}
	var pref *provagent.Refusal
	if errors.As(err, &pref) {
		t.Fatal("the runner's error crossed")
	}
}

// controlServer answers /seed with status and body, and records /close.
func controlServer(t *testing.T, status int, body string, closed *[]string) *modelroute.RouteControl {
	t.Helper()
	dir, err := os.MkdirTemp("", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/close" {
			*closed = append(*closed, r.URL.Query().Get("machine"))
			return
		}
		if status == http.StatusOK {
			w.Write([]byte(body))
			return
		}
		http.Error(w, body, status)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return modelroute.NewRouteControl(sock)
}

func TestPlanSeederMapsTheRouteControlsErrors(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   error
	}{
		{http.StatusInternalServerError, "no plan login stored", provagent.ErrNoLogin},
		{http.StatusServiceUnavailable, "the vault is locked; no provider route can open", provagent.ErrVaultLocked},
		{http.StatusServiceUnavailable, "egress busy: too many provider calls", provagent.ErrRouteBusy},
	} {
		var closed []string
		_, err := planSeeder{controlServer(t, c.status, c.body, &closed)}.Seed("codex", "pw-a")
		if !errors.Is(err, c.want) {
			t.Errorf("%d %q = %v, want %v", c.status, c.body, err, c.want)
		}
		for _, other := range []error{provagent.ErrNoLogin, provagent.ErrVaultLocked, provagent.ErrRouteBusy} {
			if other != c.want && errors.Is(err, other) {
				t.Errorf("%q also reads as %v", c.body, other)
			}
		}
	}
	var closed []string
	s := planSeeder{controlServer(t, http.StatusOK, `{"auth.json":"e30="}`, &closed)}
	if seed, err := s.Seed("codex", "pw-a"); err != nil || string(seed["auth.json"]) != "{}" {
		t.Fatalf("seed %v %v", seed, err)
	}
	s.Close("pw-a")
	if len(closed) != 1 || closed[0] != "pw-a" {
		t.Fatalf("closed %v", closed)
	}
}

// The control socket mints Codex placeholders only: another provider is
// never asked for one.
func TestPlanSeederSeedsCodexOnly(t *testing.T) {
	var closed []string
	s := planSeeder{controlServer(t, http.StatusOK, `{"auth.json":"e30="}`, &closed)}
	for _, p := range []string{"claude", "grok", ""} {
		if _, err := s.Seed(p, "pw-a"); err == nil || !strings.Contains(err.Error(), "no plan seed") {
			t.Errorf("%q: %v", p, err)
		}
	}
}
