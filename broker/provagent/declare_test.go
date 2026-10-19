package provagent

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/vault"
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
		CloudOff:    []string{"telemetry.enabled = false"},
		Pools:       []Pool{{Name: "5h", ReadFrom: "x-stub-primary-used-percent"}},
		ErrorEvents: []string{"error"},
		UsedUp:      []string{"usage_limit_reached"},
		TaskClasses: []string{"code"},
		CredFormats: []string{`(?i)\bstubtok_[a-z0-9]{16,}`},
	}
}

// REQ: CRED-7
func TestDeclarationNeedsCredentialFormats(t *testing.T) {
	cases := map[string][]string{
		"missing":             nil,
		"empty list":          {},
		"matches empty":       {`\bstubtok_[a-z0-9]{16,}`, `x*`},
		"empty format":        {""},
		"does not compile":    {`(?i)\bstubtok_[a-z0-9{16,}`},
		"one of two compiles": {`\bstubtok_[a-z0-9]{16,}`, `(unclosed`},
	}
	for name, f := range cases {
		d := good()
		d.CredFormats = f
		if err := d.Validate(); err == nil {
			t.Errorf("%s: loaded", name)
		}
		if _, err := d.Formats(); err == nil {
			t.Errorf("%s: formats compiled", name)
		}
	}
	for id, d := range Builtins() {
		if len(d.CredFormats) == 0 {
			t.Errorf("builtin %s states no credential format", id)
		}
	}
}

// canaryRefresh is a synthetic Codex refresh token in the shape measured on a
// live sign-in (#2313, spikes/S8-live/RESULTS.md): 196 characters over
// [A-Za-z0-9._], dot segments 2.1.191, no prefix.
var canaryRefresh = "Zq.C." + strings.Repeat("CANARYcanary_0123456789", 9)[:191]

// rt40 and rtDotted are synthetic tokens in the public rt_ shape: the
// shortest body it matches, and a body with a dot in it.
var (
	rt40     = "rt_" + strings.Repeat("a", 40)
	rtDotted = "rt_" + strings.Repeat("SYNTHqz_0", 5) + "." + strings.Repeat("SYNTHqz-0", 5)
)

// The Codex declaration matches a refresh token in the measured shape whole,
// wherever it sits, and none of its formats matches ordinary text.
// REQ: CRED-7
func TestCodexFormatsMatchMeasuredRefreshShape(t *testing.T) {
	fs, err := Builtins()["codex"].Formats()
	if err != nil {
		t.Fatal(err)
	}
	match := func(s string) string {
		for _, re := range fs {
			if m := re.FindString(s); m != "" {
				return m
			}
		}
		return ""
	}
	if len(canaryRefresh) != 196 {
		t.Fatalf("canary is %d characters, want 196", len(canaryRefresh))
	}
	for _, s := range []string{
		canaryRefresh,
		`{"tokens":{"refresh_token":"` + canaryRefresh + `"}}`,
		"token " + canaryRefresh + ". Done",
		"refresh=" + canaryRefresh + "\n",
		// Escaped, percent-encoded or joined prefixes leave no word
		// boundary before the token, so the format must not need one.
		`line1\n` + canaryRefresh,
		`a:\t` + canaryRefresh,
		`\u0022` + canaryRefresh,
		"%22" + canaryRefresh,
		"refresh_token%3D" + canaryRefresh,
		"_" + canaryRefresh,
		"x" + canaryRefresh,
	} {
		if m := match(s); m != canaryRefresh {
			t.Errorf("refresh canary in %.40q...: matched %q", s, m)
		}
	}
	// The tail looks like base64url, and one sample fixes neither its
	// alphabet nor its length: a '-' anywhere, or a shorter tail, is still
	// matched whole.
	dash := func(i int) string {
		b := []byte(canaryRefresh)
		b[5+i] = '-'
		return string(b)
	}
	for _, tok := range []string{
		dash(0), dash(100), dash(190),
		"Z-.-." + canaryRefresh[5:],
		canaryRefresh[:5+160],
		"ab.c." + strings.Repeat("a-", 100),
		// The public rt_ shape stays declared (case-sensitive), from a
		// 40-character body up, dots allowed.
		"rt_" + strings.Repeat("CANARYcanary-0123456789_", 3),
		rt40,
		rtDotted,
	} {
		for _, s := range []string{tok, `{"refresh_token":"` + tok + `"}`, "x " + tok + "\n"} {
			if m := match(s); m != tok {
				t.Errorf("token %.12q... in %.40q...: matched %q", tok, s, m)
			}
		}
	}
	// An rt_ token after a JSON escape or a percent-encoded byte has no
	// word boundary before it; the format consumes the escape instead, so
	// the match is the escape and the whole token.
	for _, tok := range []string{rt40, rtDotted} {
		for _, esc := range []string{`\n`, `\t`, `\u0022`, `"`, "%22", "%3D"} {
			for _, pre := range []string{"line1", "a:", "refresh_token", `{"t":`} {
				s := pre + esc + tok + `"}`
				want := tok
				if esc != `"` {
					want = esc + tok
				}
				if m := match(s); m != want {
					t.Errorf("token %.12q... in %.40q...: matched %q, want %q", tok, s, m, want)
				}
			}
		}
	}
	tail := strings.Repeat("a", 191)
	// With no word boundary, a longer first segment is matched from its
	// last two characters on.
	if m := match("abc.d." + tail); m != "bc.d."+tail {
		t.Errorf("long segment one: matched %q", m)
	}
	for name, s := range map[string]string{
		"prose":             "The run finished. See v1.2.3 and https://example.com/a.b.c for details.",
		"version":           "codex-cli 0.162.1 (rustc 1.90.0) build ab.c.d",
		"sha256 hex":        "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"uuid":              "account 3f2c1a9e-4b7d-4c1e-9a2f-0d6b8e5c7a31",
		"short tail":        "ab.c." + tail[:159],
		"no segments":       "abc" + tail,
		"short segment one": "a.b." + tail,
		"long segment two":  "ab.cd." + tail,
		"code identifier":   "rt_sigprocmask_handler_wrapper(); rt_tables_lookup_function",
		"short rt_":         "rt_" + strings.Repeat("a", 39),
		"upper-case RT_":    "RT_" + strings.Repeat("a", 40),
		"rt_ inside word":   "start_" + strings.Repeat("a", 40),
		"spaced":            "ab . c . " + tail,
	} {
		if m := match(s); m != "" {
			t.Errorf("%s: matched %q", name, m)
		}
	}
}

// An rt_ token after an escape whose backslash is itself escaped (JSON nested
// in JSON) is redacted with the whole backslash run, so the output stays valid
// JSON and holds no 6-byte run of the token body (#2375).
// REQ: CRED-7
func TestCodexRtFormatRedactsNestedJSONToValidJSON(t *testing.T) {
	r, err := vault.NewRedactor(nil).WithFormats(Builtins()["codex"].CredFormats...)
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{rt40, rtDotted} {
		body := tok[3:]
		for _, esc := range []string{`\n`, `\\n`, `\u0022`, `\\u0022`, "\n"} {
			doc := "pre " + esc + tok + " post"
			for level := 1; level <= 3; level++ {
				b, err := json.Marshal(map[string]string{"log": doc})
				if err != nil {
					t.Fatal(err)
				}
				doc = string(b)
				got := r.Redact(b)
				if !json.Valid(got) {
					t.Errorf("escape %q level %d: invalid JSON %q", esc, level, got)
				}
				for i := 0; i+6 <= len(body); i++ {
					if strings.Contains(string(got), body[i:i+6]) {
						t.Errorf("escape %q level %d: leaked %q", esc, level, got)
						break
					}
				}
			}
		}
	}
}

func TestValidateRefusesMalformedDeclarations(t *testing.T) {
	cases := map[string]func(d *Declaration){
		"missing id":             func(d *Declaration) { d.ID = "" },
		"missing cli":            func(d *Declaration) { d.CLI = "" },
		"missing version":        func(d *Declaration) { d.Version = "" },
		"missing argv":           func(d *Declaration) { d.Argv = nil },
		"no idle argv":           func(d *Declaration) { d.Idle = nil },
		"relative cwd":           func(d *Declaration) { d.Cwd = "work" },
		"relative result":        func(d *Declaration) { d.ResultPath = "result" },
		"no task class":          func(d *Declaration) { d.TaskClasses = nil },
		"no used-up signal":      func(d *Declaration) { d.UsedUp = nil },
		"no error events":        func(d *Declaration) { d.ErrorEvents = nil },
		"half-filled pool":       func(d *Declaration) { d.Pools = []Pool{{Name: "5h"}} },
		"no pool, not unmetered": func(d *Declaration) { d.Pools = nil },
		"unmetered with a pool":  func(d *Declaration) { d.Unmetered = true },
		"unknown custody":        func(d *Declaration) { d.Custody = "guest-held" },
		"broker-held no host":    func(d *Declaration) { d.Endpoints = nil },
		"credential in env":      func(d *Declaration) { d.Env = append(d.Env, "X="+canaryToken) },
		"credential in argv":     func(d *Declaration) { d.Argv = append(d.Argv, canaryToken) },
		"token-named env":        func(d *Declaration) { d.Env = append(d.Env, "CODEX_REFRESH_TOKEN_URL_OVERRIDE=http://x") },
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
	if len(bs) != 3 {
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
	g, ok := bs["grok"]
	if !ok || g.Custody != BrokerHeld || g.Q.Verdict != Allowed || g.Q.Complete() {
		t.Errorf("grok: %+v", g)
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

// REQ: ARC3-C3
// A CLI guest (a broker-held declaration) names the switches that turn its
// provider's cloud and remote features off; without them it is refused, and
// a flag it names must be in the argv that runs the CLI (ARC-3).
func TestCLIGuestDeclarationNeedsCloudOff(t *testing.T) {
	d := good()
	d.CloudOff = nil
	if err := d.Validate(); err == nil {
		t.Fatal("a CLI guest with no cloud-off list validated")
	}
	d.CloudOff = []string{""}
	if err := d.Validate(); err == nil {
		t.Fatal("an empty cloud-off entry validated")
	}
	d.CloudOff = []string{"--no-cloud"}
	if err := d.Validate(); err == nil {
		t.Fatal("a cloud-off flag missing from argv validated")
	}
	d.Argv = append(d.Argv, "--no-cloud")
	if err := d.Validate(); err != nil {
		t.Fatalf("a cloud-off flag in argv: %v", err)
	}
	// A worker-held provider agent switches its cloud features off under
	// CRED-5 W4, not here.
	w := good()
	w.Custody, w.Endpoints, w.Placeholder, w.CloudOff = WorkerHeld, nil, "", nil
	if err := w.Validate(); err != nil {
		t.Fatalf("worker-held without a cloud-off list: %v", err)
	}
	for id, b := range Builtins() {
		if b.Custody == BrokerHeld && len(b.CloudOff) == 0 {
			t.Errorf("%s: no cloud-off list", id)
		}
	}
}

// REQ: ARC3-C1
// Each codex cloud-off entry is a `table.key = value` line the managed
// config pins, so the declaration and the file the image ships cannot drift.
func TestCodexCloudOffIsPinnedInManagedConfig(t *testing.T) {
	b, err := os.ReadFile("../../guest/codex/managed_config.toml")
	if err != nil {
		t.Fatal(err)
	}
	pinned := map[string]bool{}
	table := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			table = strings.Trim(line, "[]") + "."
		default:
			pinned[table+line] = true
		}
	}
	c := Builtins()["codex"]
	if len(c.CloudOff) == 0 {
		t.Fatal("codex: no cloud-off list")
	}
	for _, e := range c.CloudOff {
		if !pinned[e] {
			t.Errorf("codex cloud-off %q is not pinned in managed_config.toml", e)
		}
	}
}

// REQ: ARC3-C2
// The codex declaration's hosts are exactly the egress route's, so an
// endpoint on a host the declaration does not name (or the reverse) fails.
func TestCodexEndpointsMatchTheEgressRoute(t *testing.T) {
	route := egress.Codex()
	if route.Provider != "codex" {
		t.Fatalf("route provider %q", route.Provider)
	}
	hosts := map[string]bool{}
	for _, e := range route.Endpoints {
		hosts[e.Host] = true
	}
	var got []string
	for h := range hosts {
		got = append(got, h)
	}
	want := append([]string(nil), Builtins()["codex"].Endpoints...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("route hosts %v, declared %v", got, want)
	}
}
