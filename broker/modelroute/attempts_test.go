package modelroute

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: OP-8, ARC-7 (SR3-7-f1b, SR3-7-f1c)

const attemptsBody = `{"model":"default","max_tokens":100}`

// attemptWorst is one attempt's worst charge for attemptsBody.
var attemptWorst = meter.Tokens(int64(len(attemptsBody))) + 100

func attemptsMeter(t *testing.T, tokens int64) *meter.Meter {
	t.Helper()
	m, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "meter.json"),
		MachineCap: meter.Limits{Calls: 10, Tokens: tokens}, OverallCap: meter.Limits{Calls: 10, Tokens: 1 << 30}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestSR3_7f1bAllowanceIsTheBrokers: the vault process is told how many
// attempts past the first the call's meter holds, never more than
// MaxRetries; a guest's own allowance header is dropped, and an unmetered
// call is allowed none.
func TestSR3_7f1bAllowanceIsTheBrokers(t *testing.T) {
	for _, c := range []struct {
		name    string
		metered bool
		tokens  int64 // the machine's cap
		want    string
	}{
		{"unmetered", false, 0, "0"},
		{"room for one attempt", true, attemptWorst, "0"},
		{"room for two", true, 2*attemptWorst + 1, "1"},
		{"room for many", true, 1 << 30, "3"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
				got = r.Header.Values(HeaderAttempts)
				io.WriteString(w, "{}")
			}}
			fwd := Forward(Config{Socket: serveUnix(t, fe), Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
			h := fwd("m1")
			if c.metered {
				h = attemptsMeter(t, c.tokens).Wrap("m1", h)
			}
			req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(attemptsBody))
			req.Header.Set(HeaderAttempts, "1000")
			h.ServeHTTP(httptest.NewRecorder(), req)
			if len(got) != 1 || got[0] != c.want {
				t.Errorf("vault process saw allowance %q, want %q", got, c.want)
			}
		})
	}
}

// TestSR3_7f1cTrailerCarriesFailedAttempts: the usage trailer's failed
// attempts reach the meter with the served usage, and so does a trailer
// for a call no route served; a trailer saying nothing was sent upstream
// leaves the meter its own count; the allowance not spent is refunded.
func TestSR3_7f1cTrailerCarriesFailedAttempts(t *testing.T) {
	in := meter.Tokens(int64(len(attemptsBody)))
	const page = `{"error":{"message":"x"}}`
	for _, c := range []struct {
		name, trailer string
		want          int64
	}{
		{"504 then served", `{"provider":"openai","input":19,"output":6,"reported":true,"complete":true,"failed":[{"provider":"anthropic","status":504,"full":true}]}`, 25 + attemptWorst},
		{"429 then served", `{"provider":"openai","input":19,"output":6,"reported":true,"complete":true,"failed":[{"provider":"anthropic","status":429}]}`, 25 + in},
		{"none served", `{"provider":"","input":0,"output":0,"reported":false,"complete":false,"unserved":true,"failed":[{"provider":"anthropic","status":503,"full":true},{"provider":"openai","status":503,"full":true}]}`, 2 * attemptWorst},
		// The meter's own count: the page is an error, no content.
		{"nothing sent", `{"none":true}`, in},
		{"too many attempts", `{"provider":"","unserved":true,"failed":[` + strings.Repeat(`{"provider":"a","status":503,"full":true},`, MaxRetries+1) + `{"provider":"a","status":503,"full":true}]}`, (MaxRetries + 1) * attemptWorst},
		{"a bad attempt", `{"provider":"","unserved":true,"failed":[{"provider":"a","status":503,"input":-5}]}`, (MaxRetries + 1) * attemptWorst},
	} {
		t.Run(c.name, func(t *testing.T) {
			fe := &fakeEgress{h: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", HeaderUsage)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				io.WriteString(w, page)
				w.Header().Set(HeaderUsage, c.trailer)
			}}
			fwd := Forward(Config{Socket: serveUnix(t, fe), Label: func(string) string { return "public" }, Denied: func(string, Denial) {}})
			m := attemptsMeter(t, 1<<30)
			m.Wrap("m1", fwd("m1")).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(attemptsBody)))
			if u := m.Usage("m1"); u.Tokens != c.want || u.Calls != 1 {
				t.Errorf("charged %d tokens and %d calls, want %d and 1", u.Tokens, u.Calls, c.want)
			}
		})
	}
}
