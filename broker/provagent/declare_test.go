package provagent

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// REQ: CAP-11, CRED-5

const canaryToken = "sk-canary-0123456789abcdefABCDEF"

func good() Declaration {
	return Declaration{
		ID: "stub", CLI: "stubcli", Version: "1.0.0", Image: "stub-image",
		Wrap: []string{"/usr/local/bin/fwd", "--"}, Argv: []string{"stubcli", "run", "-"},
		Cwd: "/work", ResultPath: "/work/.result", Env: []string{"PATH=/usr/bin"},
		Custody: BrokerHeld, Endpoints: []string{"api.example.test"}, Placeholder: "auth.json",
		Pools:  []Pool{{Name: "5h", ReadFrom: "x-stub-primary-used-percent"}},
		UsedUp: []string{"usage_limit_reached"}, LoginRefused: []string{"login_refused"},
		TaskClasses: []string{"code"},
	}
}

func TestValidateRefusesMalformedDeclarations(t *testing.T) {
	cases := map[string]func(d *Declaration){
		"missing id":          func(d *Declaration) { d.ID = "" },
		"missing cli":         func(d *Declaration) { d.CLI = "" },
		"missing version":     func(d *Declaration) { d.Version = "" },
		"missing argv":        func(d *Declaration) { d.Argv = nil },
		"relative cwd":        func(d *Declaration) { d.Cwd = "work" },
		"relative result":     func(d *Declaration) { d.ResultPath = "result" },
		"no task class":       func(d *Declaration) { d.TaskClasses = nil },
		"no used-up signal":   func(d *Declaration) { d.UsedUp = nil },
		"no pool":             func(d *Declaration) { d.Pools = nil },
		"unknown custody":     func(d *Declaration) { d.Custody = "guest-held" },
		"broker-held no host": func(d *Declaration) { d.Endpoints = nil },
		"credential in env":   func(d *Declaration) { d.Env = append(d.Env, "X="+canaryToken) },
		"credential in argv":  func(d *Declaration) { d.Argv = append(d.Argv, canaryToken) },
		"token-named env":     func(d *Declaration) { d.Env = append(d.Env, "CODEX_REFRESH_TOKEN_URL_OVERRIDE=http://x") },
		"bad verdict": func(d *Declaration) {
			d.Q = Qualification{CLIVersion: "1", Evidence: "e", TermsURL: "https://t.test", TermsRead: "2026-10-01", Verdict: "maybe"}
		},
		"bad date": func(d *Declaration) {
			d.Q = Qualification{CLIVersion: "1", Evidence: "e", TermsURL: "https://t.test", TermsRead: "yesterday", Verdict: Allowed}
		},
		"insecure terms url": func(d *Declaration) {
			d.Q = Qualification{CLIVersion: "1", Evidence: "e", TermsURL: "http://t.test", TermsRead: "2026-10-01", Verdict: Allowed}
		},
		"version without rest": func(d *Declaration) { d.Q = Qualification{CLIVersion: "1", Verdict: Allowed} },
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("good declaration refused: %v", err)
	}
	for name, mut := range cases {
		d := good()
		mut(&d)
		if err := d.Validate(); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
}

func TestBuiltinsLoad(t *testing.T) {
	bs := Builtins()
	if len(bs) != 2 {
		t.Fatalf("builtins: %d", len(bs))
	}
	for _, d := range bs {
		if err := d.Validate(); err != nil {
			t.Errorf("%s: %v", d.ID, err)
		}
	}
	c, ok := bs["codex"]
	if !ok || c.Custody != BrokerHeld || c.Q.Verdict != Allowed {
		t.Errorf("codex: %+v", c)
	}
	cl, ok := bs["claude"]
	if !ok || cl.Custody != WorkerHeld || cl.Q.Verdict != Unclear {
		t.Errorf("claude: %+v", cl)
	}
}

// The built-in Codex launch is the file the image ships, so the two cannot
// drift (C18: wrap then argv with exactly env).
func TestCodexBuiltinMatchesLaunchJSON(t *testing.T) {
	raw, err := os.ReadFile("../../guest/codex/launch.json")
	if err != nil {
		t.Fatal(err)
	}
	var l struct {
		Wrap, Argv, Env []string
		Cwd             string
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	c := Builtins()["codex"]
	if !reflect.DeepEqual(c.Wrap, l.Wrap) || !reflect.DeepEqual(c.Argv, l.Argv) || !reflect.DeepEqual(c.Env, l.Env) || c.Cwd != l.Cwd {
		t.Errorf("builtin codex differs from guest/codex/launch.json:\n%+v\n%+v", c, l)
	}
	for _, e := range c.Env {
		if strings.Contains(strings.ToUpper(strings.SplitN(e, "=", 2)[0]), "TOKEN") {
			t.Errorf("env carries a token-named variable: %s", e)
		}
	}
}

func qualified() Qualification {
	return Qualification{CLIVersion: "1.0.0", Evidence: "spikes/x", TermsURL: "https://t.test", TermsRead: "2026-10-01", Verdict: Allowed}
}

func TestGateCodexIsUnqualifiedWhileItsRecordIsEmpty(t *testing.T) {
	g := Gate{ImageVersion: "0.162.1"}
	if r := reasonOf(g.Check(Builtins()["codex"])); r != Unqualified {
		t.Errorf("empty record: %q", r)
	}
}

func TestGateRefusals(t *testing.T) {
	d := good()
	d.Q = qualified()
	if err := (Gate{ImageVersion: "1.0.0"}).Check(d); err != nil {
		t.Fatalf("qualified refused: %v", err)
	}
	mism := (Gate{ImageVersion: "1.0.1"}).Check(d)
	if reasonOf(mism) != Unqualified {
		t.Errorf("version mismatch: %v", mism)
	}
	d.Q.Verdict = NotAllowed
	if r := reasonOf((Gate{ImageVersion: "1.0.0"}).Check(d)); r != Unqualified {
		t.Errorf("not-allowed: %q", r)
	}
	d.Q.Verdict = Unconfirmed
	if r := reasonOf((Gate{ImageVersion: "1.0.0"}).Check(d)); r != Unqualified {
		t.Errorf("unconfirmed without consent: %q", r)
	}
	if err := (Gate{ImageVersion: "1.0.0", Consent: true}).Check(d); err != nil {
		t.Errorf("unconfirmed with consent: %v", err)
	}
}

func TestGateClaudeNeedsAnOptIn(t *testing.T) {
	d := Builtins()["claude"]
	for _, g := range []Gate{{ImageVersion: ""}, {ImageVersion: "1", Consent: true}} {
		if r := reasonOf(g.Check(d)); r != OptInRequired {
			t.Errorf("claude: %q", r)
		}
	}
	d.Q = qualified()
	d.Q.Verdict = Unclear
	if r := reasonOf((Gate{ImageVersion: "1.0.0", Consent: true}).Check(d)); r != OptInRequired {
		t.Errorf("claude with a full unclear record: %q", r)
	}
}

func TestLooksLikeCredential(t *testing.T) {
	for _, s := range []string{canaryToken, `{"access_token":"abcdefgh12345678"}`, "Authorization: Bearer abcdefghijklmnop", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIx.sig"} {
		if !LooksLikeCredential(s) {
			t.Errorf("missed %q", s)
		}
	}
	if LooksLikeCredential("ordinary result text with sk- nothing") {
		t.Error("flagged plain text")
	}
}
