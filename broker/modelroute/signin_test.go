package modelroute

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// REQ: CRED-5, ONB-3, CAP-9

// #1264 c4e2: a worker marked SignInFor opens its route with /signin (the
// sign-in endpoints) until Close, then a new open is a run route again.
func TestCRED5SignInWorkerOpensTheSignInRoute(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	c := controlStub(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		io.WriteString(w, `{"dir":"/run/x/`+r.URL.Query().Get("machine")+`"}`)
	})
	c.SignInFor("pw-s")
	for _, id := range []string{"pw-s", "pw-r", "pw-s"} {
		if _, err := c.Open(id); err != nil {
			t.Fatal(err)
		}
	}
	c.Close("pw-s")
	if _, err := c.Open("pw-s"); err != nil {
		t.Fatal(err)
	}
	want := "/signin?machine=pw-s|/open?machine=pw-r|/signin?machine=pw-s|/close?machine=pw-s|/open?machine=pw-s"
	if got := strings.Join(calls, "|"); got != want {
		t.Fatalf("calls %s, want %s", got, want)
	}
}

// Plan reads the plan's state; a locked vault is ErrVaultLocked and an
// unreadable reply an error, never a grant.
func TestCRED5RouteControlReadsThePlanState(t *testing.T) {
	var path string
	reply := `{"granted":true,"private_ok":false}`
	status := http.StatusOK
	c := controlStub(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
		if status != http.StatusOK {
			http.Error(w, reply, status)
			return
		}
		io.WriteString(w, reply)
	})
	s, err := c.Plan("codex")
	if err != nil || !s.Granted || s.PrivateOK || path != "POST /plan?provider=codex" {
		t.Fatalf("plan %+v %v via %q", s, err, path)
	}
	reply = `{"granted":false,"private_ok":true}`
	if s, err := c.Plan("codex"); err != nil || s.Granted || !s.PrivateOK {
		t.Fatalf("plan %+v %v", s, err)
	}
	reply = `not json`
	if s, err := c.Plan("codex"); err == nil || s.Granted || s.PrivateOK {
		t.Fatalf("unreadable: %+v %v", s, err)
	}
	reply, status = "the vault is locked; no provider route can open", http.StatusServiceUnavailable
	if s, err := c.Plan("codex"); !errors.Is(err, ErrVaultLocked) || s.Granted {
		t.Fatalf("locked: %+v %v", s, err)
	}
}
