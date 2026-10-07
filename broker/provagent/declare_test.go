package provagent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/planquota"
)

// REQ: CAP-11, CAP-12

func sample() Declaration {
	return Declaration{
		ID: "claude-code", CLI: "claude", Versions: []string{"2.1.289"},
		Command: []string{"claude", "-p", "{{brief}}", "--output-format", "stream-json"},
		Custody: WorkerHeld, TermsNote: "Anthropic requires provider sign-in",
		Hosts: []string{"api.anthropic.com"},
		Pools: []PoolDecl{{ID: "five_hour", Source: "cli-events"}, {ID: "seven_day", Source: "cli-events"}},
		UsedUpSignal: "rate_limit_event rejected",
		TaskClasses:  []string{"code", "review"},
		PrivateOK:    false,
	}
}

func TestCAP11DeclarationSchemaRejectsSecrets(t *testing.T) {
	d := sample()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	d.TermsNote = "token sk-ant-oat01-secret"
	if err := d.Validate(); err == nil {
		t.Fatal("accepted a declaration carrying a token shape")
	}
}

func TestCAP12ResourcesOmitsSecretsAndHonoursPreference(t *testing.T) {
	g := planquota.New()
	g.Set(planquota.Pool{ID: "five_hour", Used: 0.1, Reserve: 0, Reset: time.Unix(2e9, 0)})
	g.Set(planquota.Pool{ID: "seven_day", Used: 0.1, Reserve: 0, Reset: time.Unix(2e9, 0)})
	r := &Registry{Decls: []Declaration{sample()}, Gate: g}
	views := r.Resources(false)
	if len(views) != 1 || views[0].Kind != "plan_agent" || views[0].MarginalCost != "0" {
		t.Fatalf("views %+v", views)
	}
	b, err := ToolJSON(views)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "PrivateOK") || strings.Contains(string(b), "sk-") {
		t.Fatalf("secrets in tool JSON: %s", b)
	}
	var check []map[string]any
	if err := json.Unmarshal(b, &check); err != nil {
		t.Fatal(err)
	}
	use, why := r.Honour("claude-code", false)
	if use != "claude-code" || why != "" {
		t.Fatalf("honour: %q %q", use, why)
	}
	use, why = r.Honour("claude-code", true)
	if use != "" || why != LabelNotAllowed {
		t.Fatalf("label deny: %q %q", use, why)
	}
	use, why = r.Honour("missing", false)
	if use != "" || why != NotGranted {
		t.Fatalf("missing: %q %q", use, why)
	}
	_ = g.Admit([]string{"five_hour", "seven_day"}, false)
	_ = g.Admit([]string{"five_hour", "seven_day"}, false)
	use, why = r.Honour("claude-code", false)
	if use != "" || why != ConcurrencyFull {
		t.Fatalf("concurrency: %q %q", use, why)
	}
}
