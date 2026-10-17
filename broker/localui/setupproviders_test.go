package localui

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: CRED-5, CAP-9, ONB-3, CRED-1

// vaultProviders is agentosd's provider setup over the fake's vault: an
// API key per provider, no device code until c4e2.
type vaultProviders struct{ f *fakeHooks }

func (v vaultProviders) Providers() ([]localapi.SetupProvider, error) {
	var out []localapi.SetupProvider
	for _, p := range v.f.Providers() {
		out = append(out, localapi.SetupProvider{ID: p.ID, Name: p.Name, APIKey: true, Connected: p.Connected, PrivateOK: p.PrivateOK})
	}
	return out, nil
}
func (v vaultProviders) PutAPIKey(id, key string) error        { return v.f.ConnectAPIKey(id, key) }
func (v vaultProviders) SetPrivateOK(id string, ok bool) error { return v.f.SetPrivateOK(id, ok) }

// viaProviders also takes the provider hooks from agentosd.
type viaProviders struct{ viaAgentosd }

func (v viaProviders) Providers() []Provider                 { return v.a.Providers() }
func (v viaProviders) ConnectAPIKey(id, key string) error    { return v.a.ConnectAPIKey(id, key) }
func (v viaProviders) SetPrivateOK(id string, ok bool) error { return v.a.SetPrivateOK(id, ok) }
func (v viaProviders) StartDeviceCode(id string) (string, string, string, error) {
	return v.a.StartDeviceCode(id)
}

// CRED-5, CAP-9, ONB-3 (P2-2w c4e): over localui.sock, the page lists
// agentosd's providers, its API key and private-data answer reach the
// vault, and the connected provider lets setup finish. The key is never
// shown back, plan sign-in is not offered, and once setup is finished the
// provider ops are closed.
func TestTheAIStepConnectsAProviderThroughAgentosd(t *testing.T) {
	r := newRig(t)
	dir := filepath.Join(t.TempDir(), "run")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uid := os.Getuid()
	srv := &sockets.Server{Dir: dir}
	s := localsrv.NewSetup(localsrv.SetupConfig{Record: localsrv.FileRecord{Path: filepath.Join(t.TempDir(), "setup.json")},
		Enroll:    vaultEnroller{r.hooks},
		Providers: vaultProviders{r.hooks},
		Progress:  func() localapi.SetupProgress { p := r.hooks.Progress(); return localapi.SetupProgress(p) },
		Finished:  func(string) {}, Now: r.clock})
	if err := srv.Start(ctx, sockets.Endpoint{Name: localapi.Socket, Peer: sockets.Peer{Kind: "localui"}, PeerUID: &uid, Ops: s.Ops()}); err != nil {
		t.Fatal(err)
	}
	defer srv.Wait()
	defer cancel()
	a := AgentosdSetup{Owner: Socket{Path: filepath.Join(dir, localapi.Socket)}}
	r.via = viaProviders{viaAgentosd{r.hooks, a}}
	r.srv = r.open(&MemStore{})

	ps := a.Providers()
	if len(ps) != 2 || ps[0].ID != "anthropic" || !ps[0].APIKey || ps[0].DeviceCode || ps[0].Connected {
		t.Fatalf("providers: %+v", ps)
	}
	r.runSetupToAI()
	page := r.get("/setup")
	if strings.Contains(page, `action="/setup/ai-device"`) {
		t.Fatalf("plan sign-in offered before c4e2: %s", page)
	}
	if r.hooks.finished != "" {
		t.Fatal("finished with no provider connected")
	}
	w := r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
	if strings.Contains(w.Body.String(), apiCanary) || strings.Contains(r.do("GET", "/setup", nil).Body.String(), apiCanary) {
		t.Fatal("the page showed the key back")
	}
	if r.hooks.keys["anthropic"] != apiCanary || !r.hooks.private["anthropic"] {
		t.Fatalf("vault got keys=%d private=%v", len(r.hooks.keys), r.hooks.private)
	}
	if r.hooks.finished != ownerNum || !r.srv.setup.done() {
		t.Fatalf("setup did not finish: %q", r.hooks.finished)
	}
	if a.Providers() != nil {
		t.Fatal("providers listed after finish")
	}
	if err := a.ConnectAPIKey("openai", apiCanary); !refused(err, localapi.ErrSetupClosed) {
		t.Fatalf("key after finish: %v", err)
	}
	if err := a.SetPrivateOK("openai", true); !refused(err, localapi.ErrSetupClosed) {
		t.Fatalf("private answer after finish: %v", err)
	}
	if _, _, _, err := a.StartDeviceCode("anthropic"); !refused(err, localapi.ErrSetupClosed) {
		t.Fatalf("device code after finish: %v", err)
	}
}
