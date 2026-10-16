package egress

import (
	"io"
	"net/http"
	"testing"
	"time"
)

// REQ: RES-5, CRED-5

// RES-5: a pool's reading is the provider's, whichever worker's call
// carried it: readings aggregate per provider and pool, the newest wins, and
// one provider's readings never answer for another's.
func TestPlanUsageAggregatesPerProvider(t *testing.T) {
	var u PlanUsage
	t0 := time.Unix(1_800_000_000, 0)
	u.Quota(QuotaReading{At: t0, Provider: "codex", Worker: "pw-a", Pool: "primary", UsedPercent: 10})
	u.Quota(QuotaReading{At: t0.Add(time.Minute), Provider: "codex", Worker: "pw-b", Pool: "primary", UsedPercent: 30})
	u.Quota(QuotaReading{At: t0.Add(30 * time.Second), Provider: "codex", Worker: "pw-c", Pool: "primary", UsedPercent: 99}) // late, older
	u.Quota(QuotaReading{At: t0, Provider: "codex", Worker: "pw-a", Pool: "secondary", UsedPercent: 5})
	u.Quota(QuotaReading{At: t0, Provider: "other", Worker: "pw-z", Pool: "primary", UsedPercent: 100, Exhausted: true})

	s := u.Snapshot("codex")
	if len(s.Pools) != 2 || s.Pools[0].Pool != "primary" || s.Pools[1].Pool != "secondary" {
		t.Fatalf("pools %+v", s.Pools)
	}
	if s.Pools[0].UsedPercent != 30 || s.Pools[0].Worker != "pw-b" {
		t.Fatalf("primary is not the newest reading: %+v", s.Pools[0])
	}
	if len(u.Snapshot("nobody").Pools) != 0 {
		t.Fatal("an unread provider has readings")
	}
}

// A used-up signal with no pool headers is the "plan" pool; a later reading
// with pool headers supersedes it.
func TestPlanUsageLaterPoolReadingSupersedesPlanSignal(t *testing.T) {
	var u PlanUsage
	t0 := time.Unix(1_800_000_000, 0)
	u.Quota(QuotaReading{At: t0, Provider: "codex", Pool: "plan", Exhausted: true})
	if s := u.Snapshot("codex"); len(s.Pools) != 1 || !s.Pools[0].Exhausted {
		t.Fatalf("plan signal lost: %+v", s.Pools)
	}
	u.Quota(QuotaReading{At: t0.Add(time.Second), Provider: "codex", Pool: "primary", UsedPercent: 20})
	if s := u.Snapshot("codex"); len(s.Pools) != 1 || s.Pools[0].Pool != "primary" {
		t.Fatalf("plan signal outlived a later reading: %+v", s.Pools)
	}
}

// CRED-5: a refresh the provider refuses with a refused-login code is a
// signal on the broker's own connection, recorded per provider; any other
// error (a wrong client, a server fault) is not.
func TestWorkerRouteRefusedRefreshSignals(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"expired, object", 401, `{"error":{"code":"refresh_token_expired","message":"x"}}`, true},
		{"reused, string", 400, `{"error":"refresh_token_reused"}`, true},
		{"invalidated", 401, `{"error":{"code":"refresh_token_invalidated"}}`, true},
		{"other code", 400, `{"error":"invalid_client"}`, false},
		{"invalid grant", 400, `{"error":"invalid_grant"}`, false},
		{"server fault", 500, `{"error":"refresh_token_expired"}`, false},
		{"not JSON", 401, `refresh_token_expired`, false},
	}
	for _, c := range cases {
		r := newWorkerRig(t, false)
		r.up.reply = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(c.status)
			io.WriteString(w, c.body)
		}
		if w := r.do(refreshReq("ph-refresh-w1")); w.Code < 400 {
			t.Fatalf("%s: refused refresh answered %d", c.name, w.Code)
		}
		if got := len(r.signal) == 1; got != c.want {
			t.Fatalf("%s: signals %+v, want one: %v", c.name, r.signal, c.want)
		}
		if c.want && (r.signal[0].Provider != "codex" || r.signal[0].Worker != "w1" || r.signal[0].Kind != SignalLoginRefused || r.signal[0].At.IsZero()) {
			t.Fatalf("%s: signal %+v", c.name, r.signal[0])
		}
	}

	var u PlanUsage
	at := time.Unix(1_800_000_000, 0)
	u.Signal(PlanSignal{At: at, Provider: "codex", Worker: "w1", Kind: SignalLoginRefused})
	if s := u.Snapshot("codex"); !s.LoginRefused.Equal(at) {
		t.Fatalf("snapshot %+v", s)
	}
	if !u.Snapshot("other").LoginRefused.IsZero() {
		t.Fatal("one provider's refusal answers for another")
	}
}

// A pool whose used share the provider did not state is not a reading: a
// window alone must not read as an empty pool.
func TestWorkerRouteUnstatedUseIsNoReading(t *testing.T) {
	r := newWorkerRig(t, false)
	r.up.reply = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Codex-Primary-Window-Minutes", "300")
		w.Header().Set("X-Codex-Secondary-Used-Percent", "n/a")
		w.Header().Set("Content-Type", "text/event-stream")
	}
	r.do(responses(codexBody(clientTools)))
	if len(r.quota) != 0 {
		t.Fatalf("readings from unstated use: %+v", r.quota)
	}
}
