package modelroute

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// REQ: A14, CRED-5, RES-5

// authFile stands in for egress.CodexAuthFile, the one path a Codex seed
// carries.
const authFile = "var/lib/agentos-codex/auth.json"

// The broker opens and closes a provider worker's route over the vault
// process's control socket; a refusal is an error, so the machine does not
// start without its route (A14, RES-5).
func TestA14RouteControlOpensAndClosesOverTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls []string
	refuse := false
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if refuse {
			http.Error(w, "locked", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/open" {
			io.WriteString(w, `{"dir":"/run/x/pw-a"}`)
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	c := NewRouteControl(sock)
	got, err := c.Open("pw-a")
	if err != nil || got != "/run/x/pw-a" {
		t.Fatalf("open: %q, %v", got, err)
	}
	c.Close("pw-a")
	mu.Lock()
	want := []string{"POST /open?machine=pw-a", "POST /close?machine=pw-a"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls %v, want %v", calls, want)
	}
	refuse = true
	mu.Unlock()
	if _, err := c.Open("pw-a"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("a locked open returned %v, want ErrVaultLocked", err)
	} else if strings.Contains(err.Error(), "\n") {
		t.Fatalf("a locked open's error spans lines: %q", err)
	}
	if _, err := c.Seed("pw-a"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("a locked seed returned %v, want ErrVaultLocked", err)
	}
	if _, err := NewRouteControl(filepath.Join(dir, "none.sock")).Open("pw-a"); err == nil {
		t.Fatal("an unreachable control socket returned no error")
	}
}

// controlStub serves reply on a unix socket in place of agentos-egress.
func controlStub(t *testing.T, h http.HandlerFunc) *RouteControl {
	t.Helper()
	dir, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return NewRouteControl(sock)
}

// Open hands the machine only an absolute, clean directory named for the
// worker it asked for, whatever the vault process replies (A14).
func TestA14RouteControlChecksTheDirectory(t *testing.T) {
	for _, dir := range []string{"run/x/pw-a", "/run/x/pw-b", "/run/x/../y/pw-a", "/run/x/pw-a/", "/run/x//pw-a", "/"} {
		c := controlStub(t, func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"dir": dir})
		})
		if got, err := c.Open("pw-a"); err == nil {
			t.Errorf("reply %q: opened %q", dir, got)
		}
	}
}

// Seed returns the placeholder files the vault process minted for the
// worker, for agentosd to put in the machine before it starts (#1015).
func TestCRED5RouteControlSeedsTheWorker(t *testing.T) {
	var path string
	c := controlStub(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string][]byte{authFile: []byte(`{"tokens":{}}`)})
	})
	got, err := c.Seed("pw-a")
	if err != nil {
		t.Fatal(err)
	}
	if path != "POST /seed?machine=pw-a" {
		t.Fatalf("called %q", path)
	}
	if len(got) != 1 || string(got[authFile]) != `{"tokens":{}}` {
		t.Fatalf("seed %q", got)
	}
}

// RES-5: the broker reads a provider's pools over the control socket; the
// reply is decoded into this package's own types, and a refusal or an
// unreadable reply is an error, never an empty pool list that reads as
// "nothing used".
func TestRES5RouteControlReadsUsage(t *testing.T) {
	dir, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	reply := `{"Pools":[{"At":"2026-10-15T10:00:00Z","Provider":"codex","Worker":"pw-a","Pool":"primary","UsedPercent":42.5,"WindowMinutes":300,"ResetAt":1792000000,"Exhausted":false}],"LoginRefused":"2026-10-15T09:00:00Z"}`
	var path string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
		io.WriteString(w, reply)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	c := NewRouteControl(sock)
	u, err := c.Usage("codex")
	if err != nil {
		t.Fatal(err)
	}
	if path != "POST /usage?provider=codex" {
		t.Fatalf("called %q", path)
	}
	if len(u.Pools) != 1 || u.Pools[0].Pool != "primary" || u.Pools[0].UsedPercent != 42.5 || u.Pools[0].ResetAt != 1792000000 ||
		u.Pools[0].At.IsZero() || u.LoginRefused.IsZero() {
		t.Fatalf("usage %+v", u)
	}
	for _, bad := range []string{`not json`, `{"Pools":[{"Pool":""}]}`} {
		reply = bad
		if _, err := c.Usage("codex"); err == nil {
			t.Fatalf("reply %q read as usage", bad)
		}
	}
}
