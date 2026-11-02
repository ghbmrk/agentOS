package plan_test

// REQ: CLK-1, CLK-7

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/plan"
)

// The fake's device-step secrets: the device id that polls for the code,
// and the code and PKCE verifier that redeem the sign-in.
var deviceSecrets = []string{"real-device-1", "real-code-1", "real-verifier-1"}

func jsonReq(path, body string) *http.Request {
	return req("POST", path, body, map[string]string{"Content-Type": "application/json"})
}

func formReq(body string) *http.Request {
	return req("POST", "/oauth/token", body, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

// No sign-in secret reaches the guest (#3111, CLK-1): the device id, the
// authorization code and the PKCE verifier come back to the sign-in guest
// as its own placeholders, and the clerk sends the real values in their
// place, so the provider sees exactly what it issued and the guest holds
// nothing that redeems the sign-in.
func TestPlanSignInSecretsNeverReachTheGuest(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	resp, d := p.Do(context.Background(), "s", jsonReq("/api/accounts/deviceauth/usercode", `{"client_id":"app_x"}`), nil)
	if d != "" {
		t.Fatalf("usercode: %s", d)
	}
	var uc map[string]string
	got := read(t, resp)
	if err := json.Unmarshal([]byte(got), &uc); err != nil || uc["user_code"] != "ABCD-1234" || uc["device_auth_id"] == "" {
		t.Fatalf("usercode answer %q", got)
	}
	answers := []string{got}
	poll, _ := json.Marshal(map[string]string{"device_auth_id": uc["device_auth_id"], "user_code": uc["user_code"]})
	resp, d = p.Do(context.Background(), "s", jsonReq("/api/accounts/deviceauth/token", string(poll)), nil)
	if d != "" {
		t.Fatalf("devicetoken: %s", d)
	}
	got = read(t, resp)
	answers = append(answers, got)
	if _, sent := f.last(); !strings.Contains(sent, `"device_auth_id":"real-device-1"`) {
		t.Fatalf("the poll sent %q", sent)
	}
	var ct map[string]string
	if err := json.Unmarshal([]byte(got), &ct); err != nil || ct["authorization_code"] == "" || ct["code_verifier"] == "" || ct["code_challenge"] != "challenge-1" {
		t.Fatalf("devicetoken answer %q", got)
	}
	resp, d = p.Do(context.Background(), "s", formReq(codeForm(ct["authorization_code"], ct["code_verifier"])), nil)
	if d != "" || !p.SignedIn("s") {
		t.Fatalf("code exchange: %q", d)
	}
	answers = append(answers, read(t, resp))
	if _, sent := f.last(); !strings.Contains(sent, "code=real-code-1") || !strings.Contains(sent, "code_verifier=real-verifier-1") {
		t.Fatalf("the exchange sent %q", sent)
	}
	for _, a := range answers {
		for _, s := range deviceSecrets {
			if strings.Contains(a, s) {
				t.Fatalf("the guest got %s in %q", s, a)
			}
		}
	}
	// The code is spent: its placeholders no longer redeem anything.
	before := f.hits()
	if resp, d := p.Do(context.Background(), "s", formReq(codeForm(ct["authorization_code"], ct["code_verifier"])), nil); resp != nil || d != plan.DPlaceholder {
		t.Fatalf("a replayed code exchange: %v %q", resp, d)
	}
	if f.hits() != before {
		t.Fatal("a replayed code exchange reached the provider")
	}
}

// A sign-in step that takes a secret is refused, before anything is sent,
// unless it carries this guest's own placeholder for it: a made-up or real
// value, another sign-in guest's placeholder, the code's placeholder in the
// verifier's key, or one held by a guest since forgotten.
func TestPlanSignInTakesOnlyTheGuestsOwnPlaceholders(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	for _, g := range []string{"s", "t"} {
		if err := p.BeginSignIn(g); err != nil {
			t.Fatal(err)
		}
	}
	other := deviceSteps(t, p, "t")
	own := deviceSteps(t, p, "s")
	ph := func(form, key string) string {
		i := strings.Index(form, key+"=")
		v := form[i+len(key)+1:]
		if j := strings.IndexByte(v, '&'); j >= 0 {
			v = v[:j]
		}
		return v
	}
	before := f.hits()
	for name, r := range map[string]*http.Request{
		"a real device id":          jsonReq("/api/accounts/deviceauth/token", `{"device_auth_id":"real-device-1","user_code":"ABCD-1234"}`),
		"no device id":              jsonReq("/api/accounts/deviceauth/token", `{"user_code":"ABCD-1234"}`),
		"the real code":             formReq(codeForm("real-code-1", "real-verifier-1")),
		"another guest's":           formReq(other),
		"code and verifier swapped": formReq(codeForm(ph(own, "code_verifier"), ph(own, "code"))),
		"half another guest's":      formReq(codeForm(ph(own, "code"), ph(other, "code_verifier"))),
	} {
		if resp, d := p.Do(context.Background(), "s", r, nil); resp != nil || d != plan.DPlaceholder {
			t.Errorf("%s: %v %q", name, resp, d)
		}
	}
	if f.hits() != before || p.Signed() {
		t.Fatal("a refused sign-in step reached the provider")
	}
	p.Forget("s")
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	if resp, d := p.Do(context.Background(), "s", formReq(own), nil); resp != nil || d != plan.DPlaceholder {
		t.Fatalf("a forgotten guest's placeholders: %v %q", resp, d)
	}
	if resp, d := p.Do(context.Background(), "t", formReq(other), nil); d != "" || resp == nil || !p.SignedIn("t") {
		t.Fatalf("the other guest's own exchange: %q", d)
	}
}

// A step that answers a secret passes an error answer's status only, and
// drops an answer that lacks a declared secret or carries one's value
// anywhere else, in its body or a passed header (DSecret).
func TestPlanSignInDropsAnAnswerThatWouldLeakASecret(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	var answer func(w http.ResponseWriter)
	f.device = func(w http.ResponseWriter, _ *http.Request, _ string) bool { answer(w); return true }
	poll := func() (*http.Response, string) {
		uc := deviceStepsUserCode(t, p, "s")
		return p.Do(context.Background(), "s", jsonReq("/api/accounts/deviceauth/token", uc), nil)
	}
	answer = func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		w.Write([]byte(`{"authorization_code":"real-code-1","error":"pending"}`))
	}
	resp, d := poll()
	if d != "" || resp.StatusCode != 403 {
		t.Fatalf("a pending poll: %v %q", resp, d)
	}
	if b := read(t, resp); b != "" {
		t.Fatalf("a pending poll passed its body %q", b)
	}
	for name, a := range map[string]func(w http.ResponseWriter){
		"no verifier": func(w http.ResponseWriter) { w.Write([]byte(`{"authorization_code":"real-code-1"}`)) },
		"a number":    func(w http.ResponseWriter) { w.Write([]byte(`{"authorization_code":"real-code-1","code_verifier":7}`)) },
		"not JSON":    func(w http.ResponseWriter) { w.Write([]byte(`code=real-code-1`)) },
		"echoed": func(w http.ResponseWriter) {
			w.Write([]byte(`{"authorization_code":"real-code-1","code_verifier":"real-verifier-1","code_challenge":"real-code-1"}`))
		},
		"the device id echoed": func(w http.ResponseWriter) {
			w.Write([]byte(`{"authorization_code":"real-code-1","code_verifier":"real-verifier-1","code_challenge":"real-device-1"}`))
		},
		"an escaped echo": func(w http.ResponseWriter) {
			w.Write([]byte(`{"authorization_code":"real\"code","code_verifier":"real-verifier-1","code_challenge":"x real\u0022code"}`))
		},
		"in a header": func(w http.ResponseWriter) {
			w.Header().Set("X-Request-Id", "real-verifier-1")
			w.Write([]byte(`{"authorization_code":"real-code-1","code_verifier":"real-verifier-1"}`))
		},
	} {
		answer = a
		if resp, d := poll(); resp != nil || d != plan.DSecret {
			t.Errorf("%s: %v %q", name, resp, d)
		}
	}
}

// deviceStepsUserCode runs guest's usercode step and returns its poll body.
func deviceStepsUserCode(t *testing.T, p *plan.Login, guest string) string {
	t.Helper()
	resp, d := p.Do(context.Background(), guest, jsonReq("/api/accounts/deviceauth/usercode", `{"client_id":"app_x"}`), nil)
	if d != "" {
		t.Fatalf("usercode: %s", d)
	}
	var uc map[string]string
	json.Unmarshal([]byte(read(t, resp)), &uc)
	b, _ := json.Marshal(map[string]string{"device_auth_id": uc["device_auth_id"], "user_code": uc["user_code"]})
	return string(b)
}

// A declaration cannot leave a sign-in secret with the guest: a code
// exchange that does not take its code and verifier from a device step, a
// secret off a device step, or a taken key no step answers is refused at New.
func TestPlanDeclarationKeepsSignInSecrets(t *testing.T) {
	f := newPlanFix(t)
	for name, change := range map[string]func(e *plan.Endpoint){
		"code takes nothing": func(e *plan.Endpoint) {
			if e.Kind == plan.Code {
				e.Takes = nil
			}
		},
		"code keeps its verifier": func(e *plan.Endpoint) {
			if e.Kind == plan.Code {
				delete(e.Takes, "code_verifier")
			}
		},
		"code takes its redirect": func(e *plan.Endpoint) {
			if e.Kind == plan.Code {
				e.Takes["redirect_uri"] = "code_verifier"
			}
		},
		"undeclared secret": func(e *plan.Endpoint) {
			if e.Name == "devicetoken" {
				e.Secret = []string{"authorization_code"}
			}
		},
		"secret off a device step": func(e *plan.Endpoint) {
			if e.Kind == plan.Model {
				e.Secret = []string{"x"}
			}
		},
		"run step takes": func(e *plan.Endpoint) {
			if e.Kind == plan.Read {
				e.Takes = map[string]string{"x": "authorization_code"}
			}
		},
		"user code as secret": func(e *plan.Endpoint) {
			if e.Name == "usercode" {
				e.Secret = append(e.Secret, "user_code")
			}
		},
	} {
		d := f.decl(t)
		for i := range d.Endpoints {
			e := &d.Endpoints[i]
			if e.Takes != nil {
				m := map[string]string{}
				for k, v := range e.Takes {
					m[k] = v
				}
				e.Takes = m
			}
			change(e)
		}
		if _, err := plan.New(d, f.sec, f.roots); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}

// A device step that answers after its guest was forgotten is dropped and
// leaves nothing held for it (DEnded).
func TestPlanSignInDropsADeviceAnswerAfterForget(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	poll := deviceStepsUserCode(t, p, "s")
	reached, open := make(chan struct{}), make(chan struct{})
	f.device = func(w http.ResponseWriter, _ *http.Request, _ string) bool {
		close(reached)
		<-open
		w.Write([]byte(`{"authorization_code":"real-code-1","code_verifier":"real-verifier-1"}`))
		return true
	}
	type done struct {
		resp *http.Response
		d    string
	}
	out := make(chan done, 1)
	go func() {
		resp, d := p.Do(context.Background(), "s", jsonReq("/api/accounts/deviceauth/token", poll), nil)
		out <- done{resp, d}
	}()
	<-reached
	p.Forget("s")
	close(open)
	if got := <-out; got.resp != nil || got.d != plan.DEnded {
		t.Fatalf("a late device answer: %v %q", got.resp, got.d)
	}
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	if resp, d := p.Do(context.Background(), "s", jsonReq("/api/accounts/deviceauth/token", poll), nil); resp != nil || d != plan.DPlaceholder {
		t.Fatalf("the forgotten guest's device id: %v %q", resp, d)
	}
}

// A code exchange whose answer carries a device-step secret in a field it
// passes is dropped before the login is stored (DSecret).
func TestPlanSignInDropsATokenAnswerEchoingASecret(t *testing.T) {
	f := newPlanFix(t)
	d := f.decl(t)
	for i := range d.Token {
		if d.Token[i].Name == "scope" {
			d.Token[i].Pattern = `[a-z0-9-]{1,40}`
		}
	}
	p, err := plan.New(d, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	form := deviceSteps(t, p, "s")
	f.answer = func(w http.ResponseWriter, _ *http.Request, _ string) bool {
		tok := f.tokens()
		tok["scope"] = "real-verifier-1"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tok)
		return true
	}
	if resp, d := p.Do(context.Background(), "s", formReq(form), nil); resp != nil || d != plan.DSecret {
		t.Fatalf("an echoing token answer: %v %q", resp, d)
	}
	if p.Signed() || p.SignedIn("s") {
		t.Fatal("an echoing token answer was stored")
	}
}
