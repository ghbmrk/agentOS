package egress

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// REQ: ONB-3, CRED-5, CRED-1

// rtFunc is a RoundTripper from a function.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func answer(status int) rtFunc {
	return func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	}
}

// Setup checks a pasted key with one cheap authenticated call before the
// vault stores it (ONB-3, #1265): GET the adapter's declared key-check
// path on its own host, the key written as the adapter injects it, and
// nothing else of the guest's.
func TestCheckKeySendsOneDeclaredCall(t *testing.T) {
	const key = "sk-canary-keycheck-0001"
	for _, tc := range []struct {
		a      Adapter
		url    string
		header string
		want   string
		extra  map[string]string
	}{
		{OpenAI("openai"), "https://api.openai.com/v1/models", "Authorization", "Bearer " + key, nil},
		{Anthropic("anthropic"), "https://api.anthropic.com/v1/models", "X-Api-Key", key, map[string]string{"Anthropic-Version": "2023-06-01"}},
	} {
		var got []*http.Request
		rt := rtFunc(func(r *http.Request) (*http.Response, error) {
			got = append(got, r)
			return answer(http.StatusOK)(r)
		})
		if err := tc.a.CheckKey(context.Background(), rt, []byte(key)); err != nil {
			t.Fatalf("%s: accepted key: %v", tc.a.Name, err)
		}
		if len(got) != 1 {
			t.Fatalf("%s: %d calls, want 1", tc.a.Name, len(got))
		}
		r := got[0]
		if r.Method != http.MethodGet || r.URL.String() != tc.url || r.Body != nil && r.ContentLength != 0 {
			t.Fatalf("%s: sent %s %s", tc.a.Name, r.Method, r.URL)
		}
		if v := r.Header.Get(tc.header); v != tc.want {
			t.Fatalf("%s: %s = %q", tc.a.Name, tc.header, v)
		}
		if v := r.Header.Get("Accept-Encoding"); v != "identity" {
			t.Fatalf("%s: Accept-Encoding %q", tc.a.Name, v)
		}
		for h, v := range tc.extra {
			if r.Header.Get(h) != v {
				t.Fatalf("%s: %s = %q", tc.a.Name, h, r.Header.Get(h))
			}
		}
		want := 2 + len(tc.extra) // the key and Accept-Encoding
		if len(r.Header) != want {
			t.Fatalf("%s: sent headers %v", tc.a.Name, keys(r.Header))
		}
	}
}

func keys(h http.Header) []string {
	var out []string
	for k := range h {
		out = append(out, k)
	}
	return out
}

// The provider's answer decides: 2xx accepts the key, 401 and 403 refuse
// it, and anything else, an unreachable provider included, leaves it
// unchecked, so setup says so instead of blaming the key. Neither error
// carries the key (CRED-1).
func TestCheckKeyAnswers(t *testing.T) {
	const key = "sk-canary-keycheck-0002"
	a := OpenAI("openai")
	for _, tc := range []struct {
		rt   http.RoundTripper
		want error
	}{
		{answer(200), nil},
		{answer(204), nil},
		{answer(401), ErrKeyRefused},
		{answer(403), ErrKeyRefused},
		{answer(429), ErrKeyUnchecked},
		{answer(500), ErrKeyUnchecked},
		{answer(503), ErrKeyUnchecked},
		{answer(302), ErrKeyUnchecked},
		{answer(404), ErrKeyUnchecked},
		{rtFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial " + key) }), ErrKeyUnchecked},
	} {
		err := a.CheckKey(context.Background(), tc.rt, []byte(key))
		if err != tc.want {
			t.Fatalf("got %v, want %v", err, tc.want)
		}
		if err != nil && strings.Contains(err.Error(), key) {
			t.Fatalf("error carries the key: %v", err)
		}
	}
}

// An adapter without a key check cannot have a key checked: setup stores
// no key it could not check.
func TestCheckKeyNeedsADeclaration(t *testing.T) {
	a := OpenAI("openai")
	a.KeyCheck = nil
	called := false
	rt := rtFunc(func(r *http.Request) (*http.Response, error) { called = true; return answer(200)(r) })
	if err := a.CheckKey(context.Background(), rt, []byte("sk-canary-keycheck-0003")); err != ErrKeyUnchecked || called {
		t.Fatalf("no declaration: %v, called %v", err, called)
	}
}

// The declaration is checked as operations are: a literal path, and no
// header that could carry a credential or the injection header itself.
func TestKeyCheckDeclarationValidated(t *testing.T) {
	for _, kc := range []*KeyCheck{
		{Path: ""},
		{Path: "/v1/{id}"},
		{Path: "/v1/../models"},
		{Path: "/v1/models?x=1"},
		{Path: "/v1/models", Headers: map[string]string{"Authorization": "x"}},
		{Path: "/v1/models", Headers: map[string]string{"X-Session-Id": "x"}},
		{Path: "/v1/models", Headers: map[string]string{"Accept-Encoding": "gzip"}},
	} {
		a := OpenAI("openai")
		a.KeyCheck = kc
		if a.Validate() == nil {
			t.Fatalf("accepted key check %+v", kc)
		}
	}
	for _, a := range []Adapter{OpenAI("openai"), Anthropic("anthropic")} {
		if err := a.Validate(); err != nil {
			t.Fatalf("%s: %v", a.Name, err)
		}
	}
}

// A guest cannot reach the key-check path through the proxy: it is not an
// operation (E2).
func TestKeyCheckIsNotAnOperation(t *testing.T) {
	for _, a := range []Adapter{OpenAI("openai"), Anthropic("anthropic")} {
		if _, ok := a.Match(http.MethodGet, a.KeyCheck.Path); ok {
			t.Fatalf("%s: key check path is an operation", a.Name)
		}
	}
}
