package modelroute

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
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
// fallback condition, not a refusal (#1857).
func TestA503FromTheRouteFallsBack(t *testing.T) {
	for _, body := range []string{"vault-locked", "egress busy: too many provider calls"} {
		_, err := NewRouteControl(seedServer(t, http.StatusServiceUnavailable, body)).Seed("pw-a")
		if !errors.Is(err, ErrVaultLocked) || !FallsBack(err) {
			t.Fatalf("503 %q = %v, fallsBack=%v", body, err, FallsBack(err))
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
