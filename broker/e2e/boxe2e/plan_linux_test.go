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
	stray bool   // the box makes a call the provider refuses
	noRun bool   // the sign-in cannot start: the page shows localui's error
	mu    sync.Mutex
	dev   map[string]string
	tok   map[string]string // the exchange's tokens, for a fake worker's model call
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
		if f.noRun {
			http.Redirect(w, r, "/setup?err=start", http.StatusSeeOther)
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
			if st, tok := f.provider("POST", "/oauth/token", "application/x-www-form-urlencoded", form.Encode()); st == 200 {
				f.done, f.tok = true, tok
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
		if f.noRun {
			page += `<p class="err">Could not start sign-in with that provider. Try again.</p>`
		}
		if f.offer {
			page += `<form method="post" action="/setup/ai-device"><input type="hidden" name="provider" value="codex"><button>Sign in with ChatGPT</button></form>`
		}
		w.Write([]byte(page))
	case r.URL.Path == "/status":
		if f.stray {
			f.provider("GET", "/backend-api/undeclared", "application/json", "")
		}
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
// sign-in, and until the agent machine is offered provider_run (#1721),
// guest-task fails with the not-driven text, so it reads XFAIL; any other
// failure reads FAIL.
func TestGuestTaskSignsInToThePlan(t *testing.T) {
	ok := func(f *fakeBox) error { return fakeDriver(f).guestTask() }
	want := xfail["guest-task"].want

	f := &fakeBox{stub: codexstub.New(), host: "auth.openai.com"}
	if err := ok(f); err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "#1264") {
		t.Fatalf("no offer: %v", err)
	}

	f = &fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com"}
	d := fakeDriver(f)
	d.guestSock = guestSock(t, &fakeGuest{f: f, mode: "absent"})
	err := d.guestTask()
	if err == nil || !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "#1721") {
		t.Fatalf("signed in: %v", err)
	}
	if !f.done || f.stub.Hits()["code"] != 1 || f.stub.Refused() != 0 {
		t.Fatalf("sign-in did not reach the provider: done %v hits %v refused %d", f.done, f.stub.Hits(), f.stub.Refused())
	}

	// A sign-in that cannot start reads XFAIL #1721 only while agentosd
	// registers no codex image; with the image it is a product failure.
	for _, c := range []struct {
		argv  []string
		xfail bool
	}{
		{[]string{"/usr/lib/agentos/agentosd", "-image", "openclaw=/usr/lib/agentos/images/openclaw"}, true},
		{[]string{"/usr/lib/agentos/agentosd", "-image", "codex=/usr/lib/agentos/images/codex"}, false},
	} {
		d := fakeDriver(&fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com", noRun: true})
		argv := c.argv
		d.agentosdArgv = func() ([]string, error) { return argv, nil }
		err := d.guestTask()
		switch {
		case err == nil:
			t.Errorf("no start %v: passed", argv)
		case c.xfail && (!strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "#1721")):
			t.Errorf("no start, no codex image: %v does not read XFAIL #1721", err)
		case !c.xfail && (strings.HasPrefix(err.Error(), notDriven) || !strings.Contains(err.Error(), "no sign-in link")):
			t.Errorf("no start, codex image: %v does not read FAIL", err)
		}
	}

	// A FAIL with the image quotes agentosd's setup and provagent lines,
	// the refusal's cause, with the stub's canary cut out (#1701).
	d = fakeDriver(&fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com", noRun: true})
	d.agentosdArgv = func() ([]string, error) {
		return []string{"/usr/lib/agentos/agentosd", "-image", "codex=/usr/lib/agentos/images/codex"}, nil
	}
	d.agentosdLog = func() string {
		return "agentosd: listening\n" +
			"setup: sign-in machines: cgroup: no room\n" +
			"provagent: codex sign-in: create provider worker pw-1: vm: " + codexstub.Canary + "\n" +
			"localsrv: unrelated\n"
	}
	err = d.guestTask()
	switch {
	case err == nil:
		t.Fatal("no start: passed")
	case !strings.Contains(err.Error(), "setup: sign-in machines: cgroup: no room") || !strings.Contains(err.Error(), "provagent: codex sign-in: create provider worker"):
		t.Errorf("no start: %v quotes no setup or provagent line", err)
	case strings.Contains(err.Error(), codexstub.Canary) || strings.Contains(err.Error(), "unrelated") || strings.Contains(err.Error(), "listening"):
		t.Errorf("no start: %v quotes the canary or an unrelated line", err)
	}

	// Each failure reads FAIL and names what went wrong: the host the page
	// showed, the refused calls, the request whose page showed a token.
	for name, c := range map[string]struct {
		f    *fakeBox
		says string
	}{
		"link off the auth host": {&fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com.evil.example"}, `host "auth.openai.com.evil.example"`},
		"token on a page":        {&fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com", leak: true}, "provider token: GET /status"},
		"a refused call":         {&fakeBox{stub: codexstub.New(), offer: true, host: "auth.openai.com", stray: true}, "the provider refused 1 calls"},
	} {
		err := ok(c.f)
		if err == nil || strings.HasPrefix(err.Error(), notDriven) {
			t.Errorf("%s: %v reads XFAIL", name, err)
		} else if !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: %v does not say %q", name, err, c.says)
		}
	}
}
