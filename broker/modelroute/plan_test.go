package modelroute

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REQ: CAP-9, CRED-5, RES-5

// seedServer answers /seed with status and body on a unix socket.
func seedServer(t *testing.T, status int, body string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ps")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, body, status)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// CRED-5: a seed asked of a vault with no plan login is the no-login
// sentinel (#1858), apart from a vault that is locked or other failures.
func TestSeedWithNoLoginIsTheNoLoginSentinel(t *testing.T) {
	_, err := NewRouteControl(seedServer(t, http.StatusInternalServerError, "no plan login stored")).Seed("pw-a")
	if !errors.Is(err, ErrNoPlanLogin) {
		t.Fatalf("no login stored = %v, want ErrNoPlanLogin", err)
	}
	if errors.Is(err, ErrVaultLocked) {
		t.Fatal("no login read as a locked vault")
	}
	_, err = NewRouteControl(seedServer(t, http.StatusInternalServerError, "disk on fire")).Seed("pw-a")
	if err == nil || errors.Is(err, ErrNoPlanLogin) || errors.Is(err, ErrVaultLocked) {
		t.Fatalf("another failure = %v", err)
	}
}

// CAP-9: any 503 from the route (locked, stalled or contended) is a
// fallback condition, not a refusal (#1857). Only the locked vault's own
// text is a locked vault; any other 503 is a busy route.
func TestA503FromTheRouteFallsBack(t *testing.T) {
	for body, busy := range map[string]bool{
		"the vault is locked; no provider route can open": false, // agentos-egress errRouteLocked
		"egress busy: too many provider calls":            true,
		"":                                                true,
	} {
		_, err := NewRouteControl(seedServer(t, http.StatusServiceUnavailable, body)).Seed("pw-a")
		if !errors.Is(err, ErrVaultLocked) || !FallsBack(err) {
			t.Fatalf("503 %q = %v, fallsBack=%v", body, err, FallsBack(err))
		}
		if errors.Is(err, ErrRouteBusy) != busy {
			t.Fatalf("503 %q = %v, want busy %v", body, err, busy)
		}
	}
	if FallsBack(ErrNoPlanLogin) || FallsBack(nil) {
		t.Fatal("a missing login or no error falls back")
	}
}

func TestPlanIsARouteKind(t *testing.T) {
	if KindPlan != "plan" {
		t.Fatalf("KindPlan = %q", KindPlan)
	}
}

// The locked vault's 503 text is agentos-egress's errRouteLocked; if that
// text drifts, a locked vault would read as a busy route.
func TestLockedTextIsTheVaultProcesssOwn(t *testing.T) {
	src, err := os.ReadFile("../cmd/agentos-egress/workerroute.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(line, "var errRouteLocked = ") {
			if !strings.Contains(line, lockedText) {
				t.Fatalf("errRouteLocked %q lacks %q", line, lockedText)
			}
			return
		}
	}
	t.Fatal("agentos-egress has no errRouteLocked")
}
