package modelroute

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// REQ: CRED-5, CAP-9, CRED-1

// fakeVault serves the verify socket with one fixed status and body, and
// keeps the last request it was sent.
func fakeVault(t *testing.T, status *atomic.Int32, body *atomic.Value, last *atomic.Value) *Verifier {
	t.Helper()
	path := filepath.Join(t.TempDir(), "verify.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		last.Store(r.Method + " " + r.URL.Path + " " + string(b))
		w.WriteHeader(int(status.Load()))
		io.WriteString(w, body.Load().(string))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return NewVerifier(path)
}

// Setup's provider calls send what the page asked for and map the vault
// process's refusals as enrollment's are mapped, so agentosd tells a
// locked vault, a sealed one and one never opened for setup apart.
func TestSetupProviderCallsMapTheVaultProcessAnswers(t *testing.T) {
	var status atomic.Int32
	var body, last atomic.Value
	status.Store(200)
	body.Store(`{"providers":[{"id":"openai","name":"OpenAI","connected":true,"private_ok":false},{"id":"anthropic","name":"Anthropic"}]}`)
	v := fakeVault(t, &status, &body, &last)

	ps, err := v.SetupProviders()
	if err != nil {
		t.Fatal(err)
	}
	want := []SetupProvider{{ID: "openai", Name: "OpenAI", Connected: true}, {ID: "anthropic", Name: "Anthropic"}}
	if fmt.Sprint(ps) != fmt.Sprint(want) {
		t.Fatalf("providers: %v", ps)
	}
	if got := last.Load().(string); !strings.HasPrefix(got, "GET /setup/providers ") {
		t.Fatalf("list request: %q", got)
	}

	body.Store(`{}`)
	if err := v.SetupAPIKey("openai", "sk-synthetic-canary"); err != nil {
		t.Fatal(err)
	}
	var kr SetupKeyRequest
	got := last.Load().(string)
	if !strings.HasPrefix(got, "POST /setup/providers/key ") || json.Unmarshal([]byte(strings.SplitN(got, " ", 3)[2]), &kr) != nil ||
		kr.Provider != "openai" || kr.Key != "sk-synthetic-canary" {
		t.Fatalf("key request: %q", got)
	}
	if err := v.SetupPrivateOK("anthropic", true); err != nil {
		t.Fatal(err)
	}
	if got := last.Load().(string); got != `POST /setup/providers/private {"provider":"anthropic","ok":true}` {
		t.Fatalf("private request: %q", got)
	}

	for st, want := range map[int32]error{503: ErrVaultLocked, 410: ErrEnrolled, 412: ErrEnrollNotOpen, 400: ErrSetupRefused} {
		status.Store(st)
		if _, err := v.SetupProviders(); err != want {
			t.Fatalf("list %d: %v", st, err)
		}
		if err := v.SetupAPIKey("openai", "sk-synthetic-canary"); err != want {
			t.Fatalf("key %d: %v", st, err)
		}
		if err := v.SetupPrivateOK("openai", false); err != want {
			t.Fatalf("private %d: %v", st, err)
		}
	}
	status.Store(500)
	if err := v.SetupAPIKey("openai", "sk-synthetic-canary"); err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatalf("500: %v", err)
	}
}

// The list is what the page shows, so a vault process that answers a
// provider with no ID or name is refused rather than shown.
func TestSetupProvidersRefusesAMalformedList(t *testing.T) {
	var status atomic.Int32
	var body, last atomic.Value
	status.Store(200)
	v := fakeVault(t, &status, &body, &last)
	for _, b := range []string{`{"providers":[{"id":"","name":"X"}]}`, `{"providers":[{"id":"x","name":""}]}`, `not json`} {
		body.Store(b)
		if ps, err := v.SetupProviders(); err == nil {
			t.Fatalf("%s: %v", b, ps)
		}
	}
}

// The key request never prints its key (CRED-1).
func TestSetupKeyRequestRedacts(t *testing.T) {
	r := SetupKeyRequest{Provider: "openai", Key: "sk-synthetic-canary"}
	for _, s := range []string{fmt.Sprint(r), fmt.Sprintf("%v %+v %#v %s", r, r, r, r)} {
		if strings.Contains(s, "canary") {
			t.Fatalf("printed: %s", s)
		}
	}
}
