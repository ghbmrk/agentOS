package provagent

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
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
		Idle:    []string{"sleep", "infinity"},
		Custody: BrokerHeld, Endpoints: []string{"api.example.test"}, Placeholder: "auth.json",
		Pools:       []Pool{{Name: "5h", ReadFrom: "x-stub-primary-used-percent"}},
		ErrorEvents: []string{"error"},
		UsedUp:      []string{"usage_limit_reached"},
		TaskClasses: []string{"code"},
	}
}

func TestValidateRefusesMalformedDeclarations(t *testing.T) {
	cases := map[string]func(d *Declaration){
		"missing id":          func(d *Declaration) { d.ID = "" },
		"missing cli":         func(d *Declaration) { d.CLI = "" },
		"missing version":     func(d *Declaration) { d.Version = "" },
		"missing argv":        func(d *Declaration) { d.Argv = nil },
		"no idle argv":        func(d *Declaration) { d.Idle = nil },
		"relative cwd":        func(d *Declaration) { d.Cwd = "work" },
		"relative result":     func(d *Declaration) { d.ResultPath = "result" },
		"no task class":       func(d *Declaration) { d.TaskClasses = nil },
		"no used-up signal":   func(d *Declaration) { d.UsedUp = nil },
		"no error events":     func(d *Declaration) { d.ErrorEvents = nil },
		"no pool":             func(d *Declaration) { d.Pools = nil },
		"unknown custody":     func(d *Declaration) { d.Custody = "guest-held" },
		"broker-held no host": func(d *Declaration) { d.Endpoints = nil },
		"credential in env":   func(d *Declaration) { d.Env = append(d.Env, "X="+canaryToken) },
		"credential in argv":  func(d *Declaration) { d.Argv = append(d.Argv, canaryToken) },
		"token-named env":     func(d *Declaration) { d.Env = append(d.Env, "CODEX_REFRESH_TOKEN_URL_OVERRIDE=http://x") },
		"bad verdict": func(d *Declaration) {
			d.Q = Qualification{CLIVersion: "1.0.0", Evidence: "e", TermsURL: "https://t.test", TermsRead: "2026-10-01", Verdict: "maybe"}
		},
		"bad date": func(d *Declaration) {
			d.Q = Qualification{CLIVersion: "1.0.0", Evidence: "e", TermsURL: "https://t.test", TermsRead: "yesterday", Verdict: Allowed}
		},
		"insecure terms url": func(d *Declaration) {
			d.Q = Qualification{CLIVersion: "1.0.0", Evidence: "e", TermsURL: "http://t.test", TermsRead: "2026-10-01", Verdict: Allowed}
		},
		"version without rest": func(d *Declaration) { d.Q = Qualification{CLIVersion: "1.0.0", Verdict: Allowed} },
		"record for another version": func(d *Declaration) {
			d.Q = qualified()
			d.Q.CLIVersion = "1.0.1"
		},
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
		Wrap, Argv, Env, Idle []string
		Cwd                   string
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	c := Builtins()["codex"]
	if !reflect.DeepEqual(c.Wrap, l.Wrap) || !reflect.DeepEqual(c.Argv, l.Argv) || !reflect.DeepEqual(c.Env, l.Env) || !reflect.DeepEqual(c.Idle, l.Idle) || c.Cwd != l.Cwd {
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

// pinnedCodex is CODEX_VERSION in guest/codex/build-rootfs.sh, the version
// the image pins (and agentosd reads back as the gate's ImageVersion, #1877).
func pinnedCodex(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../guest/codex/build-rootfs.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^CODEX_VERSION=([0-9][0-9A-Za-z.+-]*)$`).FindAllSubmatch(raw, -1)
	if len(m) != 1 {
		t.Fatalf("build-rootfs.sh: %d CODEX_VERSION lines", len(m))
	}
	return string(m[0][1])
}

// filledCodex is the Codex builtin with a synthetic complete record at the
// pinned version, the shape #809's finish gives it.
func filledCodex(t *testing.T) Declaration {
	d := Builtins()["codex"]
	d.Q.CLIVersion = pinnedCodex(t)
	d.Q.Evidence = "spikes/x"
	d.Q.TermsURL = "https://t.test"
	d.Q.TermsRead = "2026-10-01"
	return d
}

// The shipped Codex record keeps the gate closed until it is complete; once
// complete at the pinned version it opens. #809's finish is then only data.
func TestGateCodexOpensOnlyOnACompleteRecord(t *testing.T) {
	g := Gate{ImageVersion: pinnedCodex(t)}
	c := Builtins()["codex"]
	if c.Q.Complete() {
		if err := g.Check(c); err != nil {
			t.Errorf("complete record at the pinned version refused: %v", err)
		}
	} else if r := reasonOf(g.Check(c)); r != Unqualified {
		t.Errorf("incomplete record: %q", r)
	}
	d := filledCodex(t)
	if err := d.Validate(); err != nil {
		t.Fatalf("filled record refused: %v", err)
	}
	if err := g.Check(d); err != nil {
		t.Errorf("filled record at the pinned version refused: %v", err)
	}
}

// Any one field missing keeps the gate closed, and a record pinned but not
// complete does not load (CAP-11).
func TestGateCodexIncompleteRecordStaysUnqualified(t *testing.T) {
	g := Gate{ImageVersion: pinnedCodex(t)}
	cases := map[string]func(q *Qualification){
		"cli version": func(q *Qualification) { q.CLIVersion = "" },
		"evidence":    func(q *Qualification) { q.Evidence = "" },
		"terms url":   func(q *Qualification) { q.TermsURL = "" },
		"terms read":  func(q *Qualification) { q.TermsRead = "" },
		"verdict":     func(q *Qualification) { q.Verdict = "" },
	}
	for name, clear := range cases {
		d := filledCodex(t)
		clear(&d.Q)
		if d.Q.Complete() {
			t.Errorf("no %s: complete", name)
		}
		if r := reasonOf(g.Check(d)); r != Unqualified {
			t.Errorf("no %s: gate %q", name, r)
		}
		if err := d.Validate(); err == nil {
			t.Errorf("no %s: a partly filled record loaded", name)
		}
	}
}

// A record whose CLI version is not the pinned one stays unqualified: at the
// gate when the image pins another version, and at load when the record
// names a version the declaration was not written for (CAP-11).
func TestGateCodexOnAnotherCLIVersionStaysUnqualified(t *testing.T) {
	pin := pinnedCodex(t)
	d := filledCodex(t)
	for _, img := range []string{"", "0.162.0", pin + ".1"} {
		if r := reasonOf((Gate{ImageVersion: img}).Check(d)); r != Unqualified {
			t.Errorf("image pins %q: gate %q", img, r)
		}
	}
	d.Q.CLIVersion = "0.162.0"
	if r := reasonOf((Gate{ImageVersion: pin}).Check(d)); r != Unqualified {
		t.Errorf("record for 0.162.0, image %s: gate %q", pin, r)
	}
	if err := d.Validate(); err == nil {
		t.Error("record for another CLI version loaded")
	}
}

// The Codex builtin is written for the version the image pins, and its
// record, once filled, names that version and evidence that exists.
func TestCodexBuiltinMatchesThePinnedImageVersion(t *testing.T) {
	pin := pinnedCodex(t)
	c := Builtins()["codex"]
	if c.Version != pin {
		t.Errorf("codex declaration is for %s, the image pins %s", c.Version, pin)
	}
	if c.Q.CLIVersion != "" && c.Q.CLIVersion != pin {
		t.Errorf("codex record is for %s, the image pins %s", c.Q.CLIVersion, pin)
	}
	if c.Q.Evidence != "" {
		if _, err := os.Stat("../../" + c.Q.Evidence); err != nil || strings.Contains(c.Q.Evidence, "..") || strings.HasPrefix(c.Q.Evidence, "/") {
			t.Errorf("codex evidence %q is not a file in the repo: %v", c.Q.Evidence, err)
		}
	}
	if c.Q.Verdict != Allowed { // D-117's terms read (#1377)
		t.Errorf("codex verdict: %q", c.Q.Verdict)
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
