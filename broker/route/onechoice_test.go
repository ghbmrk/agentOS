package route

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: OP-8, ARC-7

// metered composes the real meter, the router (through Routed, as the
// guest plane mounts it) and the providers' serializers in front of the
// rig's recording upstream. It returns the guest-facing handler and the
// meter, and records, for every call that reaches upstream, the tokens
// the meter held for it at that moment: in + reservation.
type metered struct {
	h    http.Handler
	m    *meter.Meter
	held []int64
}

func newMetered(t *testing.T, r *rig, maxOut int64) *metered {
	t.Helper()
	m, err := meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "meter.json"),
		MachineCap: meter.Limits{Calls: 1000, Tokens: 1 << 40},
		OverallCap: meter.Limits{Calls: 1000, Tokens: 1 << 40},
		MaxReserve: maxOut, DefaultReserve: 700,
		Now: func() time.Time { return r.clock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &metered{h: m.Wrap("m1", Routed(r.router)("m1")), m: m}
}

func (c *metered) do(t *testing.T, r *rig, host, fixtureName, body string) *httptest.ResponseRecorder {
	t.Helper()
	ctype := "application/json"
	r.up.set(host, func(w http.ResponseWriter, req *http.Request) {
		c.held = append(c.held, c.m.Usage("m1").Tokens)
		w.Header().Set("Content-Type", ctype)
		w.Write(fixture(t, fixtureName))
	})
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	return w
}

// providers is each supported provider with the route rule that sends a
// call only to it, its upstream host, and a fixture answer.
var providers = []struct {
	name, host, fixture string
	rule                Rule
}{
	{"openai", hostOpenAI, "openai_completion.json", Rule{"default": {{Provider: "openai", Model: "gpt-fixture"}}}},
	{"anthropic", hostAnthropic, "anthropic_message.json", Rule{"default": {{Provider: "anthropic", Model: "claude-fixture"}}}},
}

// TestSR3_7AmbiguousChoiceCountNeverReachesUpstream composes meter,
// router and provider serializer. A choice count or output limit spelled
// so the meter's exact-key view and the router's case-insensitive struct
// decode could read different values (case variants, duplicate keys,
// case-colliding keys, Unicode case folds) is refused before any
// upstream dispatch, and every request that does go out asks for one
// choice.
func TestSR3_7AmbiguousChoiceCountNeverReachesUpstream(t *testing.T) {
	const msgs = `"model":"default","messages":[{"role":"user","content":"x"}]`
	refused := []string{
		`{` + msgs + `,"n":2}`,
		`{` + msgs + `,"N":2}`,
		`{` + msgs + `,"n":1,"N":3}`,
		`{` + msgs + `,"N":3,"n":1}`,
		`{` + msgs + `,"n":3,"n":1}`,
		`{` + msgs + `,"n":1,"n":1}`,
		`{` + msgs + `,"MAX_TOKENS":999999}`,
		`{` + msgs + `,"max_tokens":10,"Max_Tokens":999999}`,
		`{` + msgs + `,"max_toKens":999999}`, // KELVIN SIGN folds to k
		`{` + msgs + `,"max_tokens":10,"max_tokens":10}`,
		`{` + msgs + `,"Model":"other"}`,
		`{` + msgs + `,"ſtream":true}`, // LONG S folds to s
	}
	for _, p := range providers {
		r := newRig(t, rigOpts{rule: p.rule, maxOut: 6000})
		c := newMetered(t, r, 6000)
		for _, body := range refused {
			before := r.up.count(p.host)
			w := c.do(t, r, p.host, p.fixture, body)
			if w.Code != http.StatusBadRequest || r.up.count(p.host) != before {
				t.Errorf("%s %s: status %d, upstream calls %d -> %d; want 400 and none", p.name, body, w.Code, before, r.up.count(p.host))
			}
		}
		for _, body := range []string{`{` + msgs + `}`, `{` + msgs + `,"n":1}`} {
			before := r.up.count(p.host)
			if w := c.do(t, r, p.host, p.fixture, body); w.Code != http.StatusOK || r.up.count(p.host) != before+1 {
				t.Fatalf("%s %s: status %d: %s", p.name, body, w.Code, w.Body)
			}
			if n := choices(t, r.up.lastBody(p.host)); n != 1 {
				t.Errorf("%s %s: upstream asked for %d choices", p.name, body, n)
			}
		}
	}
}

// choices is the number of choices a provider request asks for: n when
// present (OpenAI), else one (the Messages API has no such field).
func choices(t *testing.T, body []byte) int {
	t.Helper()
	var v struct{ N *int }
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("upstream body %s: %v", body, err)
	}
	if v.N == nil {
		return 1
	}
	return *v.N
}

// TestSR3_7RouterRefusesSeveralChoicesForEveryProvider: the router's
// final typed request enforces one choice itself, for every provider,
// whatever reached it (a meter misconfigured or bypassed, a body from
// another forwarder). Absent n and n=1 stay usable.
func TestSR3_7RouterRefusesSeveralChoicesForEveryProvider(t *testing.T) {
	const msgs = `"model":"default","messages":[{"role":"user","content":"x"}]`
	for _, p := range providers {
		r := newRig(t, rigOpts{rule: p.rule})
		r.up.set(p.host, serveFixture(200, "application/json", fixture(t, p.fixture)))
		for _, body := range []string{`{` + msgs + `,"n":2}`, `{` + msgs + `,"N":2}`, `{` + msgs + `,"n":0}`, `{` + msgs + `,"n":1,"N":2}`, `{` + msgs + `,"n":2,"n":1}`} {
			if w := r.do(t, "m1", body); w.Code != http.StatusBadRequest || r.up.count(p.host) != 0 {
				t.Errorf("%s %s: status %d, upstream calls %d", p.name, body, w.Code, r.up.count(p.host))
			}
		}
		for _, body := range []string{`{` + msgs + `}`, `{` + msgs + `,"n":1}`} {
			if w := r.do(t, "m1", body); w.Code != http.StatusOK {
				t.Fatalf("%s %s: status %d: %s", p.name, body, w.Code, w.Body)
			}
			if n := choices(t, r.up.lastBody(p.host)); n != 1 {
				t.Errorf("%s %s: %d choices", p.name, body, n)
			}
		}
	}
}

// TestSR3_7ReservationCoversForwardedLimit: the output limit each
// provider receives is no more than what the meter reserved for the
// call, for every supported output-limit alias: max_tokens,
// max_completion_tokens, both, none, and max_output_tokens (a Responses
// key the chat router does not read, so it must not stand in for a limit
// the router would otherwise set at its own ceiling). Unknown fields
// never reach a provider.
func TestSR3_7ReservationCoversForwardedLimit(t *testing.T) {
	const msgs = `"model":"default","messages":[{"role":"user","content":"x"}]`
	for _, p := range providers {
		r := newRig(t, rigOpts{rule: p.rule, maxOut: 6000})
		c := newMetered(t, r, 6000)
		for _, body := range []string{
			`{` + msgs + `}`,
			`{` + msgs + `,"max_tokens":300}`,
			`{` + msgs + `,"max_completion_tokens":300}`,
			`{` + msgs + `,"max_completion_tokens":300,"max_tokens":5000}`,
			`{` + msgs + `,"max_tokens":999999}`,
			`{` + msgs + `,"max_output_tokens":100}`,
			`{` + msgs + `,"max_output_tokens":100,"max_tokens":200}`,
			`{` + msgs + `,"agentos_extra":{"n":9},"logit_bias":{"1":5}}`,
		} {
			before := c.m.Usage("m1").Tokens
			c.held = nil
			w := c.do(t, r, p.host, p.fixture, body)
			if w.Code != http.StatusOK || len(c.held) != 1 {
				t.Fatalf("%s %s: status %d, %d upstream calls: %s", p.name, body, w.Code, len(c.held), w.Body)
			}
			reserved := c.held[0] - before - meter.Tokens(int64(len(body)))
			sent := r.up.lastBody(p.host)
			if lim := forwardedLimit(t, sent); lim <= 0 || lim > reserved {
				t.Errorf("%s %s: forwarded limit %d, reserved %d: %s", p.name, body, lim, reserved, sent)
			}
			for _, k := range []string{"max_output_tokens", "agentos_extra", "logit_bias"} {
				if strings.Contains(string(sent), `"`+k+`"`) {
					t.Errorf("%s %s: unknown field %s forwarded: %s", p.name, body, k, sent)
				}
			}
		}
	}
}

// forwardedLimit is the largest output limit a provider request carries.
func forwardedLimit(t *testing.T, body []byte) int64 {
	t.Helper()
	var v map[string]json.RawMessage
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	var lim int64
	for _, k := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
		var n int64
		if raw, ok := v[k]; ok && json.Unmarshal(raw, &n) == nil {
			lim = max(lim, n)
		}
	}
	return lim
}

// TestSR3_7SyntheticUsageSettlesTheCall: through the composed path, a
// served call holds its reservation while upstream runs and then settles
// at the provider's synthetic reported usage (no live call; what a real
// provider bills is not measured here).
func TestSR3_7SyntheticUsageSettlesTheCall(t *testing.T) {
	const body = `{"model":"default","messages":[{"role":"user","content":"x"}],"n":1,"max_tokens":3000}`
	for _, p := range []struct {
		name, host, fixture string
		rule                Rule
		want                int64 // the fixture's usage, as the meter weighs it
	}{
		{"openai", hostOpenAI, "openai_completion.json", providers[0].rule, 19 + 6},
		// 412 in, 3000 cache read at 0.1, 200 cache write at 1.25, 57 out.
		{"anthropic", hostAnthropic, "anthropic_message.json", providers[1].rule, 412 + 300 + 250 + 57},
	} {
		r := newRig(t, rigOpts{rule: p.rule, maxOut: 6000})
		c := newMetered(t, r, 6000)
		if w := c.do(t, r, p.host, p.fixture, body); w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", p.name, w.Code, w.Body)
		}
		if got := c.m.Usage("m1"); got.Calls != 1 || got.Tokens != p.want {
			t.Errorf("%s: settled %+v, want 1 call, %d tokens", p.name, got, p.want)
		}
		if c.held[0] < 3000 {
			t.Errorf("%s: held %d during the call, below the 3000 reserved", p.name, c.held[0])
		}
	}
}
