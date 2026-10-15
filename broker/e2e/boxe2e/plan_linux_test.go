package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/e2e/boxe2e/codexstub"
)

// REQ: HW-10, CRED-5

// fakeBox is the setup page at step 7 as #1264 is expected to serve it,
// with the vault's device-code sign-in played against the stub: the
// sign-in starts on the owner's post and completes on a reload once the
// owner approved the code at the provider.
type fakeBox struct {
	stub  *codexstub.Stub
	offer bool   // step 7 offers the codex sign-in
	host  string // the link's host
	leak  bool   // the status page shows an issued token
	mu    sync.Mutex
	dev   map[string]string
	done  bool
}

func (f *fakeBox) provider(method, path, ctype string, body string) (int, map[string]string) {
	r := httptest.NewRequest(method, "https://auth.openai.com"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", ctype)
	w := httptest.NewRecorder()
	f.stub.ServeHTTP(w, r)
	var out map[string]string
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (f *fakeBox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == "POST" && r.URL.Path == "/setup/ai-device":
		if r.PostFormValue("provider") != "codex" || r.PostFormValue("private") != "1" {
			http.Error(w, "bad form", 400)
			return
		}
		_, f.dev = f.provider("POST", "/api/accounts/deviceauth/usercode", "application/json", `{"client_id":"app_synthetic"}`)
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
	case r.URL.Path == "/setup" && f.done:
		http.Redirect(w, r, "/status", http.StatusSeeOther)
	case r.URL.Path == "/setup" && f.dev != nil:
		b, _ := json.Marshal(map[string]string{"device_auth_id": f.dev["device_auth_id"], "user_code": f.dev["user_code"]})
		if st, ct := f.provider("POST", "/api/accounts/deviceauth/token", "application/json", string(b)); st == 200 {
			form := url.Values{"grant_type": {"authorization_code"}, "code": {ct["authorization_code"]},
				"code_verifier": {ct["code_verifier"]}, "redirect_uri": {"https://auth.openai.com/deviceauth/callback"}}
			if st, _ := f.provider("POST", "/oauth/token", "application/x-www-form-urlencoded", form.Encode()); st == 200 {
				f.done = true
				http.Redirect(w, r, "/status", http.StatusSeeOther)
				return
			}
		}
		link := "https://" + f.host + "/codex/device"
		w.Write([]byte(`<h2>7. Connect AI</h2><p class="muted">One is enough. You can add more later.</p><h3>ChatGPT</h3>` +
			`<p>Open <a href="` + link + `">` + link + `</a> and enter <span class="mono">` + f.dev["user_code"] + `</span>.</p>` +
			`<p>This code is from OpenAI.</p><p><a href="/setup">I signed in</a></p>`))
	case r.URL.Path == "/setup":
		page := `<h2>7. Connect AI</h2><p class="muted">One is enough. You can add more later.</p><h3>ChatGPT</h3>`
		if f.offer {
			page += `<form method="post" action="/setup/ai-device"><input type="hidden" name="provider" value="codex"><button>Sign in with ChatGPT</button></form>`
		}
		w.Write([]byte(page))
	case r.URL.Path == "/status":
		page := `<h1>Status</h1>`
		if f.leak {
			page += f.stub.Tokens()[0]
		}
		w.Write([]byte(page))
	default:
		http.NotFound(w, r)
	}
}

type handlerRT struct{ h http.Handler }

func (t handlerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	t.h.ServeHTTP(w, r)
	return w.Result(), nil
}

func fakeDriver(f *fakeBox) *driver {
	return &driver{stub: f.stub, phone: &http.Client{
		Transport:     handlerRT{f},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// The step-7 driver signs in as #1264's page is expected to offer it: the
// link on the provider's own host, the code approved at the stub, setup
// finished, and no issued token on any page. Until the page offers the
// sign-in, and until a worker runs the task (#1314), guest-task fails with
// the not-driven text, so it reads XFAIL; any other failure reads FAIL.
func TestGuestTaskSignsInToThePlan(t *testing.T) {
	ok := func(f *fakeBox) error { return fakeDriver(f).guestTask() }
	want := xfail["guest-task"].want

	f := &fakeBox{stub: codexstub.New(), host: "auth.openai.com"}
	if err := ok(f); err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "#1264") {
		t.Fatalf("no offer: %v", err)
	}

	f = &fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com"}
	err := ok(f)
	if err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "#1314") {
		t.Fatalf("signed in: %v", err)
	}
	if !f.done || f.stub.Hits()["code"] != 1 || f.stub.Refused() != 0 {
		t.Fatalf("sign-in did not reach the provider: done %v hits %v refused %d", f.done, f.stub.Hits(), f.stub.Refused())
	}

	for name, f := range map[string]*fakeBox{
		"link off the auth host": {stub: codexstub.New(), offer: true, host: "auth.openai.com.evil.example"},
		"token on a page":        {stub: codexstub.New(), offer: true, host: "auth.openai.com", leak: true},
	} {
		if err := ok(f); err == nil || strings.HasPrefix(err.Error(), notDriven) {
			t.Errorf("%s: %v reads XFAIL", name, err)
		}
	}
}
