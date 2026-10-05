package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: ADP-10, ARC-6, CRED-5

type plainMachines struct{}

func (plainMachines) Step(context.Context, string) error { return nil }
func (plainMachines) RaisePrivate(string) error          { return nil }
func (plainMachines) Lineage(id string) (string, error)  { return id, nil }

type noGrants struct{}

func (noGrants) Check(context.Context, journal.Phase, journal.Intent) error {
	return journal.ErrInvalid
}

// TestA14RouterDenialsAreJournaled is A14's "denied and journaled" row on
// the box's model path, which the e2e rig cannot compose (callAudit is
// this process's): guest socket -> guest plane -> OP-8 meter -> broker
// forwarder -> model socket -> model router -> egress proxy. Every request
// the router itself refuses (an undeclared or unclean path, an unknown
// class, a body it does not accept, an ungranted provider) reaches no
// provider, and each distinct refusal is journaled through the broker's
// wiring (modelroute.Journal) with the method the guest used.
func TestA14RouterDenialsAreJournaled(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	sock := openModelSocket(t, testRouter(t), func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"hi"}}]}`)
	})

	work := t.TempDir()
	jstore, err := journal.OpenFile(filepath.Join(work, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer jstore.Close()
	eng, err := journal.Open(jstore, noGrants{}, map[string]journal.Executor{}, func(s string) string { return s })
	if err != nil {
		t.Fatal(err)
	}
	fwd := modelroute.Forward(modelroute.Config{
		Socket: sock,
		Label:  func(string) string { return "private" },
		Denied: modelroute.Journal(eng, t.Logf),
	})
	mtr, err := meter.Open(meter.Config{Path: filepath.Join(work, "meter.json"),
		MachineCap: meter.Limits{Calls: 100, Tokens: 1 << 30}, OverallCap: meter.Limits{Calls: 100, Tokens: 1 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	plane, err := guest.New(guest.Config{Dir: filepath.Join(work, "guests"), Machines: plainMachines{}, Effects: eng, Model: fwd, Meter: mtr})
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Shutdown()
	dir, err := plane.Open("agent")
	if err != nil {
		t.Fatal(err)
	}
	gsock := filepath.Join(dir, guest.Socket)
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", gsock)
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	ok := `{"model":"default","messages":[{"role":"user","content":"hi"}]}`
	for _, a := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/model/v1/chat/completions", ok, 200},
		{"GET", "/model/v1/models", "", 404},
		{"POST", "/model/v1/files", "{}", 404},
		{"POST", "/model/v1/chat%2Fcompletions", ok, 404},
		{"POST", "/model/v1/./chat/completions", ok, 404},
		{"POST", "/model/v1/chat/completions?x=1", ok, 404},
		{"POST", "/model/v1/chat/completions", `{"model":"nope","messages":[{"role":"user","content":"hi"}]}`, 404},
		{"POST", "/model/v1/chat/completions", `{"model":"default","messages":[{"role":"wizard","content":"hi"}]}`, 400},
		{"POST", "/model/v1/chat/completions", `{"model":"claude","messages":[{"role":"user","content":"hi"}]}`, 403},
	} {
		req, _ := http.NewRequest(a.method, "http://broker"+a.path, strings.NewReader(a.body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != a.status {
			t.Errorf("%s %s: %d, want %d", a.method, a.path, resp.StatusCode, a.status)
		}
	}
	mu.Lock()
	if calls != 1 {
		t.Errorf("provider called %d times, want 1 (only the clean request)", calls)
	}
	mu.Unlock()

	type key struct {
		method string
		status int
		reason string
	}
	got := map[key]int{}
	for _, r := range eng.Trail() {
		if r.Type != journal.RecEgress {
			continue
		}
		if r.Egress.Machine != "agent" || r.Egress.Adapter != "router" {
			t.Errorf("journaled %+v, want the router's denial for agent", *r.Egress)
		}
		got[key{r.Egress.Method, r.Egress.Status, r.Egress.Reason}]++
	}
	const path = "only POST /v1/chat/completions is served"
	for _, k := range []key{
		{"GET", 404, path},
		{"POST", 404, "no such model class"},
		{"POST", 400, `request not accepted: "message role \"wizard\" is not accepted"`},
		{"POST", 403, "no route for this class is granted and allowed for this machine's data label"},
	} {
		if got[k] != 1 {
			t.Errorf("journal holds %d of %+v, want 1; all: %v", got[k], k, got)
		}
	}
	// The five path refusals share one reason class: one record now, the
	// rest folded into the next (egress E6), so a looping guest cannot
	// fill the journal.
	if n := got[key{"POST", 404, path}]; n != 0 {
		t.Errorf("POST path refusals journaled %d times after the GET opened the window", n)
	}
}
