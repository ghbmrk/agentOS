package localui

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ONB-3, CRED-5, CAP-9, UX3-F1, UX3-F2, UX3-F3

// planProviders is agentosd's provider setup with the first provider
// signing in by device code (c4e2b).
type planProviders struct{ vaultProviders }

func (v planProviders) Providers() ([]localapi.SetupProvider, error) {
	ps, err := v.vaultProviders.Providers()
	if len(ps) > 0 {
		ps[0].APIKey, ps[0].DeviceCode = false, true
	}
	return ps, err
}

// planSignIn is agentosd's setup sign-in: it answers the provider's page,
// a code and the issuer, or busy. signing is the runner's SigningIn: set
// by a start, cleared when the sign-in ends.
type planSignIn struct {
	mu      sync.Mutex
	busy    bool
	starts  int
	signing bool
}

func (s *planSignIn) Ready(string) bool { return true }
func (s *planSignIn) Start(context.Context, string) (string, string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.starts++
	if s.busy {
		return "", "", "", localsrv.SignInBusy
	}
	s.signing = true
	return "https://auth.openai.com/codex/device", "ABCD-1234", "OpenAI", nil
}

func (s *planSignIn) SigningIn(string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signing
}

func (s *planSignIn) set(signing bool) { s.mu.Lock(); s.signing = signing; s.mu.Unlock() }

// devicePrompt is the line the G1 driver reads the link and code from
// (PR #1867's planSignIn).
var devicePrompt = regexp.MustCompile(`<p>Open <a href="([^"]*)">[^<]*</a> and enter <span class="mono">([^<]*)</span>\.</p>`)

// agentosdSignInRig runs setup to the AI step with the page reaching
// providers and sign-in through agentosd's own setup ops, as on the box.
func agentosdSignInRig(t *testing.T) (*rig, *planSignIn) {
	t.Helper()
	r := newRig(t)
	dir := filepath.Join(t.TempDir(), "run")
	ctx, cancel := context.WithCancel(context.Background())
	uid := os.Getuid()
	srv := &sockets.Server{Dir: dir}
	si := &planSignIn{}
	s := localsrv.NewSetup(localsrv.SetupConfig{Record: localsrv.FileRecord{Path: filepath.Join(t.TempDir(), "setup.json")},
		Enroll:    vaultEnroller{r.hooks},
		Providers: planProviders{vaultProviders{r.hooks}},
		SignIn:    si,
		Progress:  func() localapi.SetupProgress { p := r.hooks.Progress(); return localapi.SetupProgress(p) },
		Finished:  func(string) {}, Now: r.clock})
	if err := srv.Start(ctx, sockets.Endpoint{Name: localapi.Socket, Peer: sockets.Peer{Kind: "localui"}, PeerUID: &uid, Ops: s.Ops()}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); srv.Wait() })
	a := AgentosdSetup{Owner: Socket{Path: filepath.Join(dir, localapi.Socket)}}
	r.via = viaProviders{viaAgentosd{r.hooks, a}}
	r.srv = r.open(&MemStore{})
	r.runSetupToAI()
	return r, si
}

// ONB-3, CRED-5, CAP-9 (#1264 c4e2b): over localui.sock, "Sign in" on a
// plan route shows the provider's own page and code, and says who sent
// the code (§8.1 step 6), with the owner's private answer recorded; a
// sign-in still waiting is named as such, not as a failure.
func TestThePlanSignInShowsThePageCodeAndIssuer(t *testing.T) {
	r, si := agentosdSignInRig(t)

	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	page := r.get("/setup")
	m := devicePrompt.FindStringSubmatch(page)
	if m == nil || m[1] != "https://auth.openai.com/codex/device" || m[2] != "ABCD-1234" {
		t.Fatalf("no device prompt with the provider's page and code: %v\n%s", m, page)
	}
	if !strings.Contains(page, "<p>This code is from OpenAI, not from your code generator.</p>") {
		t.Fatalf("the page does not say who sent the code:\n%s", page)
	}
	if !r.hooks.private["anthropic"] {
		t.Fatal("the private answer was not recorded")
	}

	// A second sign-in while the first waits is named as waiting.
	si.mu.Lock()
	si.busy = true
	si.mu.Unlock()
	r.srv.setup.device = map[string][3]string{}
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if page := r.get("/setup"); !strings.Contains(page, "still waiting") || devicePrompt.MatchString(page) {
		t.Fatalf("busy sign-in:\n%s", page)
	}
}

// A sign-in answer that names no issuer shows no code: the page never
// shows a code without saying who sent it (§8.1 step 6).
func TestAPlanSignInWithNoIssuerShowsNoCode(t *testing.T) {
	r := newRig(t)
	r.via = noIssuer{r.hooks}
	r.srv = r.open(&MemStore{})
	r.runSetupToAI()
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if page := r.get("/setup"); devicePrompt.MatchString(page) || strings.Contains(page, "WXYZ-1234") {
		t.Fatalf("a code with no issuer shown:\n%s", page)
	}
}

type noIssuer struct{ *fakeHooks }

func (n noIssuer) StartDeviceCode(id string) (string, string, string, error) {
	l, c, _, err := n.fakeHooks.StartDeviceCode(id)
	return l, c, "", err
}

// endedSignIn is the line the page shows for a sign-in that ended.
var endedSignIn = regexp.MustCompile(`<p>Your sign-in with Anthropic ended`)

// UX3-F2 (#2328): once the provider's sign-in ends unapproved, the next
// load of the page shows it ended, with the control for a new code and
// without the old code, before the owner clicks anything; the control
// then shows a new code.
func TestEndedSignInShowsWithoutAClick(t *testing.T) {
	r, si := agentosdSignInRig(t)
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if page := r.get("/setup"); shownCode(page) != "ABCD-1234" {
		t.Fatalf("no code shown:\n%s", page)
	}
	si.set(false) // the code expired, was declined, or the sign-in failed
	page := r.get("/setup")
	if !endedSignIn.MatchString(page) || devicePrompt.MatchString(page) || strings.Contains(page, "ABCD-1234") {
		t.Fatalf("an ended sign-in is not shown as ended:\n%s", page)
	}
	if _, ok := setupForms(t, page)["ai-retry anthropic"]; !ok {
		t.Fatalf("no new-code control beside the ended sign-in:\n%s", page)
	}
	submit(r, page, "ai-retry anthropic")
	if page := r.get("/setup"); shownCode(page) != "ABCD-1234" || endedSignIn.MatchString(page) {
		t.Fatalf("a new code is not shown after the retry:\n%s", page)
	}
}

// UX3-F3 (#2328): a sign-in that still waits keeps showing its code on
// every load, and is never called ended.
func TestLiveSignInStillShowsCode(t *testing.T) {
	r, _ := agentosdSignInRig(t)
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	for i := 0; i < 2; i++ {
		if page := r.get("/setup"); shownCode(page) != "ABCD-1234" || endedSignIn.MatchString(page) {
			t.Fatalf("load %d: a waiting sign-in is not shown with its code:\n%s", i, page)
		}
	}
}

// UX3-F3 (#2328): a provider this page never started a sign-in for shows
// neither a code nor an ended sign-in, whether or not a sign-in started
// elsewhere still waits, only its Sign in button.
func TestIdleProviderShowsNoSignInBlock(t *testing.T) {
	r, si := agentosdSignInRig(t)
	for _, signing := range []bool{false, true} {
		si.set(signing)
		page := r.get("/setup")
		if devicePrompt.MatchString(page) || endedSignIn.MatchString(page) {
			t.Fatalf("signing %v: an idle provider shows a sign-in:\n%s", signing, page)
		}
		forms := setupForms(t, page)
		if _, ok := forms["ai-retry anthropic"]; ok {
			t.Fatalf("signing %v: an idle provider offers a new code:\n%s", signing, page)
		}
		if _, ok := forms["ai-device anthropic"]; !ok {
			t.Fatalf("signing %v: no Sign in button:\n%s", signing, page)
		}
	}
}
