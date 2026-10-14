package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modelroute"
)

// REQ: CRED-5, CAP-9, ONB-3, CRED-1

// providerSock serves the verify socket's setup provider routes with one
// fixed status, and keeps every request body it was sent.
type providerSock struct {
	mu     sync.Mutex
	status int
	bodies []string
}

func serveProviderSock(t *testing.T) (*providerSock, enroller) {
	t.Helper()
	f := &providerSock{status: 200}
	path := filepath.Join(shortDir(t), "v.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, r.URL.Path+" "+string(b))
		status := f.status
		f.mu.Unlock()
		w.WriteHeader(status)
		if status == 200 && r.URL.Path == "/setup/providers" {
			io.WriteString(w, `{"providers":[{"id":"openai","name":"OpenAI","connected":true,"private_ok":true},{"id":"anthropic","name":"Anthropic"}]}`)
			return
		}
		io.WriteString(w, `{}`)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f, enroller{modelroute.NewVerifier(path)}
}

// agentosd's enroller serves setup's providers over the verify socket: each
// takes an API key, none offers device code until c4e2, and the vault
// process's refusals reach localsrv as the refusals it maps.
func TestTheEnrollerServesSetupsProvidersThroughTheVault(t *testing.T) {
	f, e := serveProviderSock(t)
	if providersOf(e) == nil {
		t.Fatal("the vault enroller does not serve providers")
	}
	if providersOf(&setupVault{}) != nil {
		t.Fatal("an enroller without providers served them")
	}

	ps, err := e.Providers()
	if err != nil {
		t.Fatal(err)
	}
	want := []localapi.SetupProvider{
		{ID: "openai", Name: "OpenAI", APIKey: true, Connected: true, PrivateOK: true},
		{ID: "anthropic", Name: "Anthropic", APIKey: true},
	}
	if len(ps) != len(want) || ps[0] != want[0] || ps[1] != want[1] {
		t.Fatalf("providers: %+v", ps)
	}

	const canary = "sk-CANARY-agentosd-key-3c1"
	if err := e.PutAPIKey("openai", canary); err != nil {
		t.Fatal(err)
	}
	if err := e.SetPrivateOK("anthropic", true); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	got := strings.Join(f.bodies, "\n")
	f.mu.Unlock()
	if !strings.Contains(got, "/setup/providers/key ") || !strings.Contains(got, canary) || !strings.Contains(got, "/setup/providers/private ") {
		t.Fatalf("requests: %s", got)
	}

	for status, want := range map[int]error{
		400: localsrv.ProviderRefused,
		403: localsrv.KeyRefused, // REQ: ONB-3
		502: localsrv.KeyUnchecked,
		410: localsrv.EnrollClosed,
		412: localsrv.EnrollNotOpen,
	} {
		f.mu.Lock()
		f.status = status
		f.mu.Unlock()
		if err := e.PutAPIKey("openai", canary); !errors.Is(err, want) {
			t.Fatalf("%d: key put answered %v, want %v", status, err, want)
		}
		if _, err := e.Providers(); !errors.Is(err, want) && status != 400 {
			t.Fatalf("%d: list answered %v, want %v", status, err, want)
		}
		if err := e.PutAPIKey("openai", canary); err != nil && strings.Contains(err.Error(), canary) {
			t.Fatalf("%d: the refusal carries the key: %v", status, err)
		}
	}
}

// The key check's waits nest (Security L8.4): the vault process gives the
// provider the least time, agentosd waits longer for the vault, and the
// page waits longest for agentosd. REQ: ONB-3
func TestSetupKeyWaitsNest(t *testing.T) {
	if !(modelroute.SetupKeyCheckWait < modelroute.SetupAPIKeyTimeout && modelroute.SetupAPIKeyTimeout < localapi.APIKeyTimeout) {
		t.Fatalf("waits %v, %v, %v do not nest", modelroute.SetupKeyCheckWait, modelroute.SetupAPIKeyTimeout, localapi.APIKeyTimeout)
	}
}
