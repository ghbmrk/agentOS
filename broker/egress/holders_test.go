package egress

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, CRED-5, CRED-7, ADP-10

// A proxy whose adapters each have a holder (SIM-split) never reads a
// secret: it hands the holder the checked request, with no credential, and
// redacts every vault value from what comes back with a redactor that
// holds only keyed hashes.

// fakeHolder stands in for an account's holder process.
type fakeHolder struct {
	mu    sync.Mutex
	seen  []*http.Request
	reply func(r *http.Request) *http.Response
}

func (f *fakeHolder) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.seen = append(f.seen, r)
	f.mu.Unlock()
	if r.Body != nil {
		io.ReadAll(r.Body)
	}
	return f.reply(r), nil
}

func holderReply(status int, h http.Header, body string) func(*http.Request) *http.Response {
	return func(r *http.Request) *http.Response {
		if h == nil {
			h = http.Header{}
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), Request: r}
	}
}

func hashed(t *testing.T, values ...string) func() (Redactor, error) {
	t.Helper()
	var vs [][]byte
	for _, v := range values {
		vs = append(vs, []byte(v))
	}
	r, err := vault.NewHashRedactor(vs)
	if err != nil {
		t.Fatal(err)
	}
	return func() (Redactor, error) { return r, nil }
}

func TestHolderRouteHoldsNoSecret(t *testing.T) {
	keyA, keyB := synthetic(t, "sk-canary-a-"), synthetic(t, "sk-canary-b-")
	fh := &fakeHolder{reply: holderReply(200, http.Header{"Content-Type": {"application/json"}, "X-Request-Id": {keyB}},
		`{"echo":"`+keyB+`"}`)}
	audit := &auditLog{}
	p, err := New(Config{
		Adapters:  []Adapter{OpenAI("openai-key")},
		Grants:    map[string][]string{"m1": {"openai"}},
		Redaction: hashed(t, keyA, keyB),
		Holders:   map[string]http.RoundTripper{"openai-key": fh},
		Audit:     audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	p.Handler("m1").ServeHTTP(w, chat("/openai/v1/chat/completions"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if len(fh.seen) != 1 {
		t.Fatalf("holder saw %d requests", len(fh.seen))
	}
	up := fh.seen[0]
	if up.URL.Path != "/v1/chat/completions" || up.Method != "POST" {
		t.Fatalf("holder got %s %s", up.Method, up.URL)
	}
	if up.Header.Get("Authorization") != "" {
		t.Fatalf("egress sent a credential header to the holder: %q", up.Header.Get("Authorization"))
	}
	if leaked(w, keyB) || !strings.Contains(w.Body.String(), vault.Placeholder) {
		t.Fatalf("account B's key reached the guest: %s %v", w.Body, w.Header())
	}

	// A journaled path carrying a vault value is redacted too.
	req := chat("/openai/v1/" + keyA)
	p.Handler("m1").ServeHTTP(httptest.NewRecorder(), req)
	if ev := audit.last(t); strings.Contains(ev.Path, keyA) || !strings.Contains(ev.Path, vault.Placeholder) {
		t.Fatalf("journaled path %q", ev.Path)
	}
}

// A holder's drop of an exchange response stops the route exactly as the
// proxy's own swap failure would (CRED-5t); its refusal status does too.
func TestHolderDropStopsTheRoute(t *testing.T) {
	for _, tc := range []struct {
		status int
		drop   string
		reason string
		stops  bool
	}{
		{http.StatusBadGateway, DropUnswappable, ReasonUnswappable, true},
		{http.StatusBadGateway, DropExchangeError, "credential exchange answered with an error; dropped", false},
		{http.StatusUnauthorized, "", ReasonLoginRefused, true},
	} {
		h := http.Header{}
		if tc.drop != "" {
			h.Set(HolderDropHeader, tc.drop)
		}
		fh := &fakeHolder{reply: holderReply(tc.status, h, "")}
		fails := &failures{}
		audit := &auditLog{}
		p, err := New(Config{
			Adapters:    []Adapter{planAdapter()},
			Grants:      map[string][]string{"w1": {"plan"}},
			Redaction:   hashed(t),
			Holders:     map[string]http.RoundTripper{"openai-key": fh},
			Audit:       audit,
			RouteFailed: fails.told,
		})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		p.Handler("w1").ServeHTTP(w, refresh())
		if w.Code < 400 || audit.last(t).Reason != tc.reason {
			t.Fatalf("%+v: status %d reason %q", tc, w.Code, audit.last(t).Reason)
		}
		_, stopped := p.stopped("plan")
		if stopped != tc.stops {
			t.Fatalf("%+v: stopped %v", tc, stopped)
		}
	}
}

// A swapped exchange response from the holder reaches the guest as is.
func TestHolderSwappedExchangeIsForwarded(t *testing.T) {
	body := `{"access_token":"placeholder-a","refresh_token":"placeholder-r","expires_in":3600,"token_type":"Bearer"}`
	fh := &fakeHolder{reply: holderReply(200, http.Header{"Content-Type": {"application/json"}}, body)}
	p, err := New(Config{
		Adapters:    []Adapter{planAdapter()},
		Grants:      map[string][]string{"w1": {"plan"}},
		Redaction:   hashed(t),
		Holders:     map[string]http.RoundTripper{"openai-key": fh},
		Audit:       &auditLog{},
		RouteFailed: (&failures{}).told,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	p.Handler("w1").ServeHTTP(w, refresh())
	if w.Code != 200 || !bytes.Equal(bytes.TrimSpace(w.Body.Bytes()), []byte(body)) {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
}

// Holders are all or nothing: a proxy given only hashes cannot serve an
// adapter whose credential it would have to read.
func TestNewRequiresAHolderForEveryAdapterWithoutTheVault(t *testing.T) {
	if _, err := New(Config{Adapters: []Adapter{OpenAI("k")}, Redaction: hashed(t), Audit: &auditLog{}}); err == nil {
		t.Fatal("adapter without a holder accepted")
	}
	if _, err := New(Config{Adapters: []Adapter{OpenAI("k")}, Audit: &auditLog{}}); err == nil {
		t.Fatal("no vault and no redaction accepted")
	}
	if _, err := New(Config{Adapters: []Adapter{OpenAI("k")}, Holders: map[string]http.RoundTripper{"k": &fakeHolder{}}, Vault: emptyVault{}, Redaction: hashed(t), Audit: &auditLog{}}); err == nil {
		t.Fatal("vault beside holders accepted")
	}
}

// The proxy tells a holder the calling machine's label, so the holder can
// hold the body to the same rule (ADP-10). Only "public" is said; a guest's
// own claim never reaches the holder, and a private machine's request
// carries no label.
func TestProxyTellsTheHolderTheLabel(t *testing.T) {
	fh := &fakeHolder{reply: holderReply(200, http.Header{"Content-Type": {"application/json"}}, `{}`)}
	labels := map[string]string{"pub": LabelPublic, "priv": "private"}
	p, err := New(Config{
		Adapters:  []Adapter{OpenAI("openai-key")},
		Grants:    map[string][]string{"pub": {"openai"}, "priv": {"openai"}},
		Label:     func(m string) string { return labels[m] },
		Redaction: hashed(t, synthetic(t, "sk-canary-")),
		Holders:   map[string]http.RoundTripper{"openai-key": fh},
		Audit:     &auditLog{},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"pub", "priv"} {
		r := chat("/openai/v1/chat/completions")
		r.Header.Set(LabelHeader, LabelPublic)
		w := httptest.NewRecorder()
		p.Handler(m).ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", m, w.Code, w.Body)
		}
	}
	if got := fh.seen[0].Header.Values(LabelHeader); len(got) != 1 || got[0] != LabelPublic {
		t.Fatalf("public machine's label: %q", got)
	}
	if got := fh.seen[1].Header.Values(LabelHeader); len(got) != 0 {
		t.Fatalf("private machine's request carried a label: %q", got)
	}
}
