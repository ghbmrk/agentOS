// Package provagent declares provider-agent plan routes (CAP-11): a
// provider's official agent CLI, run headless in a broker-owned worker, as a
// route type added by declaration. A declaration is data: it carries no
// credential, is validated at load, and holds a qualification record that
// keeps the route off until S8-live (#809) has filled it.
package provagent

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Custody is who holds the login (CRED-5).
type Custody string

const (
	// BrokerHeld: the CLI holds placeholders and the vault process injects
	// the login at the declared endpoints (#1014, #1015).
	BrokerHeld Custody = "broker-held"
	// WorkerHeld: the worker holds the login. Only the Claude opt-in uses
	// it (D-114, #1380).
	WorkerHeld Custody = "worker-held"
)

// Verdict is the owner's reading of the provider's terms.
type Verdict string

const (
	Allowed    Verdict = "allowed"
	NotAllowed Verdict = "not-allowed"
	Unclear    Verdict = "unclear"
	// Unconfirmed is a broker-held route the terms do not plainly allow
	// (D-061): it runs only with the owner's recorded consent (CRED-5c).
	Unconfirmed Verdict = "unconfirmed"
)

func (v Verdict) known() bool {
	switch v {
	case Allowed, NotAllowed, Unclear, Unconfirmed:
		return true
	}
	return false
}

// Qualification is the record #809 fills: the pinned CLI version, a pointer
// to the W1-W5 evidence, and the terms URL, date read and verdict.
type Qualification struct {
	CLIVersion string
	Evidence   string
	TermsURL   string
	TermsRead  string // YYYY-MM-DD
	Verdict    Verdict
}

// Complete is whether every field is filled.
func (q Qualification) Complete() bool {
	return q.CLIVersion != "" && q.Evidence != "" && q.TermsURL != "" && q.TermsRead != "" && q.Verdict != ""
}

func (q Qualification) empty() bool { return q == Qualification{} }

func (q Qualification) validate() error {
	if q.empty() {
		return nil
	}
	// #809 fills the CLI version and the evidence pointer; #1377 the terms
	// reading. A record may carry the verdict before either, but a pinned
	// version without everything else is malformed.
	if (q.CLIVersion != "" || q.Evidence != "") && !q.Complete() {
		return errors.New("qualification record is partly filled")
	}
	if q.Verdict != "" && !q.Verdict.known() {
		return fmt.Errorf("qualification verdict %q", q.Verdict)
	}
	if q.TermsURL != "" && !strings.HasPrefix(q.TermsURL, "https://") {
		return errors.New("qualification terms URL is not https")
	}
	if q.TermsRead != "" {
		if _, err := time.Parse("2006-01-02", q.TermsRead); err != nil {
			return fmt.Errorf("qualification date: %w", err)
		}
	}
	return nil
}

// Pool is a usage pool and where the broker reads it (RES-5).
type Pool struct{ Name, ReadFrom string }

// Declaration is one provider-agent route.
type Declaration struct {
	ID      string
	CLI     string
	Version string // the CLI version this declaration was written for
	Image   string // the provider image the worker is created from

	// Wrap then Argv is the headless command; Env is exactly its
	// environment. The brief is not here: it arrives on stdin.
	Wrap, Argv, Env []string
	Cwd             string
	ResultPath      string // the declared result file; the CLI's stdout is written to it
	// Idle is what the worker runs from start until it is destroyed: runsc
	// refuses a container with no process args, and the CLI runs by Exec,
	// so the worker needs a process that waits and does nothing (#1721).
	Idle []string

	Custody     Custody
	Endpoints   []string // hosts the vault process injects at (feeds #1014)
	Placeholder string   // the placeholder file the worker is seeded with (feeds #1015)
	Pools       []Pool
	TaskClasses []string

	// ErrorEvents are the "type" values of the CLI's own JSON error events
	// in the result stream. The signals below are substrings matched only
	// in those events, never in the agent's messages, which a brief steers.
	ErrorEvents []string
	// UsedUp are substrings matched in the error events. A refused login
	// and a credit draw are not read here: the agent can write the result,
	// so the broker reads both on its own upstream connection (#1856).
	UsedUp []string

	// SignInArgv is the device-code sign-in command (ONB-3, #1264), run
	// like Argv under Wrap and Env; empty is a route with no sign-in here.
	// The CLI prints its verification link and code: only a link in
	// SignInLinks is read, and SignInPage, the provider's own page, is what
	// the owner is shown (egress PlanRoute.SignInLink checks the same).
	// SignInFrom names who issues the code, for the page's "This code is
	// from <provider>" line (SPEC §8.1 step 6).
	SignInArgv  []string
	SignInLinks []string
	SignInPage  string
	SignInFrom  string

	// CredFormats are regular expressions for this provider's credential
	// shapes (access token, refresh token, API key), in Go syntax with any
	// flags inline, such as (?i). A result is scanned for them as well as
	// LooksLikeCredential, and the vault redactor scrubs them (CRED-7).
	CredFormats []string

	Q Qualification
}

var idRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// Credential formats a result or declaration must not carry (CRED-7): API
// keys, JWTs, bearer headers and token fields. A tripwire, not a proof: the
// worker holds only placeholders.
var credRE = regexp.MustCompile(`(?i)(\bsk-[a-z0-9_-]{16,}|eyJ[a-z0-9_-]{8,}\.[a-z0-9_-]{4,}|bearer\s+[a-z0-9._~+/=-]{12,}|"?(access|refresh|id)_token"?\s*[:=]\s*"?[a-z0-9._-]{8,})`)

// LooksLikeCredential reports whether s carries a credential format.
func LooksLikeCredential(s string) bool { return credRE.MatchString(s) }

// Formats compiles the declaration's credential formats. It refuses none,
// one that does not compile, and one that matches the empty string, which
// would match every result (FMT-1).
func (d Declaration) Formats() ([]*regexp.Regexp, error) {
	if len(d.CredFormats) == 0 {
		return nil, fmt.Errorf("declaration %s: no credential format", d.ID)
	}
	out := make([]*regexp.Regexp, 0, len(d.CredFormats))
	for i, f := range d.CredFormats {
		re, err := regexp.Compile(f)
		if err != nil {
			return nil, fmt.Errorf("declaration %s: credential format %d does not compile", d.ID, i)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("declaration %s: credential format %d matches the empty string", d.ID, i)
		}
		out = append(out, re)
	}
	return out, nil
}

// Validate refuses a malformed declaration at load.
func (d Declaration) Validate() error {
	req := map[string]string{"id": d.ID, "cli": d.CLI, "version": d.Version, "image": d.Image}
	for k, v := range req {
		if v == "" {
			return fmt.Errorf("declaration %q: %s is missing", d.ID, k)
		}
	}
	if !idRE.MatchString(d.ID) {
		return fmt.Errorf("declaration id %q", d.ID)
	}
	if len(d.Argv) == 0 {
		return fmt.Errorf("declaration %s: no headless argv", d.ID)
	}
	if len(d.Idle) == 0 {
		return fmt.Errorf("declaration %s: no idle argv for the worker to start on", d.ID)
	}
	if !strings.HasPrefix(d.Cwd, "/") || !strings.HasPrefix(d.ResultPath, "/") {
		return fmt.Errorf("declaration %s: cwd and result path are absolute", d.ID)
	}
	switch d.Custody {
	case BrokerHeld:
		if len(d.Endpoints) == 0 {
			return fmt.Errorf("declaration %s: broker-held names no endpoint", d.ID)
		}
	case WorkerHeld:
	default:
		return fmt.Errorf("declaration %s: custody %q", d.ID, d.Custody)
	}
	if len(d.TaskClasses) == 0 || len(d.UsedUp) == 0 || len(d.ErrorEvents) == 0 || len(d.Pools) == 0 {
		return fmt.Errorf("declaration %s: task classes, used-up signal, error events and pools are needed", d.ID)
	}
	for _, p := range d.Pools {
		if p.Name == "" || p.ReadFrom == "" {
			return fmt.Errorf("declaration %s: pool %+v", d.ID, p)
		}
	}
	if len(d.SignInArgv) > 0 {
		if d.Custody != BrokerHeld || len(d.SignInLinks) == 0 || !strings.HasPrefix(d.SignInPage, "https://") || !contains(d.SignInLinks, d.SignInPage) || d.SignInFrom == "" {
			return fmt.Errorf("declaration %s: a sign-in needs broker custody, its links, its https page and its issuer", d.ID)
		}
	}
	if _, err := d.Formats(); err != nil {
		return err
	}
	var all []string
	all = append(append(append(all, d.Wrap...), d.Argv...), d.Env...)
	all = append(all, d.Idle...)
	all = append(append(all, d.SignInArgv...), d.SignInLinks...)
	all = append(all, d.Endpoints...)
	all = append(all, d.Placeholder, d.Cwd, d.ResultPath, d.Q.Evidence, d.Q.TermsURL)
	for _, s := range all {
		if LooksLikeCredential(s) {
			return fmt.Errorf("declaration %s carries a credential format", d.ID)
		}
	}
	for _, e := range d.Env {
		k, v, ok := strings.Cut(e, "=")
		if !ok || k == "" {
			return fmt.Errorf("declaration %s: env entry %q", d.ID, k)
		}
		// childproc refuses a start that passes a value on a token-named variable.
		if v != "" && strings.Contains(strings.ToUpper(k), "TOKEN") {
			return fmt.Errorf("declaration %s: env %s carries a token-named variable", d.ID, k)
		}
	}
	// A record qualifies the CLI version the declaration was written for;
	// one measured on another version is a different declaration (CAP-11).
	if d.Q.CLIVersion != "" && d.Q.CLIVersion != d.Version {
		return fmt.Errorf("declaration %s: qualification is for CLI %q, the declaration for %q", d.ID, d.Q.CLIVersion, d.Version)
	}
	return d.Q.validate()
}

// Builtins are the declarations the broker ships, by ID. Both ship with an
// incomplete record: Codex is off until #809 fills it; Claude stays off behind
// the owner's opt-in (#1380).
func Builtins() map[string]Declaration {
	return map[string]Declaration{
		"codex": {
			ID: "codex", CLI: "codex", Version: "0.162.1", Image: "codex",
			Wrap:        []string{"/usr/local/bin/agentos-codex-forwarder", "-listen", "127.0.0.1:18432", "-socket", "/run/agentos/route.sock", "--"},
			Argv:        []string{"codex", "exec", "--json", "--skip-git-repo-check", "--cd", "/var/lib/agentos-work", "-"},
			Cwd:         "/var/lib/agentos-work",
			Env:         []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/var/lib/agentos-codex", "CODEX_HOME=/var/lib/agentos-codex", "GIT_DIR=/dev/null"},
			Idle:        []string{"/bin/sleep", "infinity"},
			ResultPath:  "/var/lib/agentos-work/.agentos-result",
			Custody:     BrokerHeld,
			Endpoints:   []string{"chatgpt.com", "auth.openai.com"},
			Placeholder: "auth.json",
			Pools: []Pool{
				{Name: "primary", ReadFrom: "x-codex-primary-used-percent"},
				{Name: "secondary", ReadFrom: "x-codex-secondary-used-percent"},
			},
			TaskClasses: []string{"code", "research"},
			// codex exec --json reports failures as these events; the
			// agent's messages are item events and are never matched.
			ErrorEvents: []string{"error", "turn.failed"},
			UsedUp:      []string{"usage_limit_reached"},
			// The argv points the CLI's issuer at the forwarder, so the CLI
			// asks the forwarder for its code and prints the forwarder's
			// page (P11, #1701).
			SignInArgv:  []string{"codex", "login", "--device-auth", "--experimental_issuer", "http://127.0.0.1:18432"},
			SignInLinks: []string{"http://127.0.0.1:18432/codex/device", "https://auth.openai.com/codex/device"},
			SignInPage:  "https://auth.openai.com/codex/device",
			SignInFrom:  "OpenAI",
			// API keys, the ChatGPT access and id tokens (JWTs; the id
			// token may be unsigned) and the refresh token. The JWT and
			// refresh shapes are measured from a live sign-in (#2313,
			// spikes/S8-live/RESULTS.md): the refresh token is dot
			// segments 2.1.191 with no prefix. Its pattern allows '-' and
			// a shorter tail, since one sample fixes neither, and needs no
			// word boundary, so an escaped or percent-encoded prefix
			// cannot hide it. The public rt_ refresh shape and the API key
			// stay declared, since the issuer is server-side and a plan
			// sign-in issues no API key (ASSUMPTIONS.md P17).
			CredFormats: []string{
				`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`,
				`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*`,
				`[A-Za-z0-9_-]{2}\.[A-Za-z0-9_-]\.[A-Za-z0-9_-]{160,}`,
				`\brt_[A-Za-z0-9_-]{40,}`,
			},
			// The record is #809's: CLIVersion equals Version and
			// guest/codex/build-rootfs.sh CODEX_VERSION, and Evidence must
			// exist (both test-checked). The evidence is a supervised live run
			// on the owner's ChatGPT plan; it shows the limit-reached state
			// with credits available, not a credit draw, so none is claimed.
			// Verdict and the terms read are D-117's (#1377).
			Q: Qualification{
				CLIVersion: "0.162.1",
				Evidence:   "spikes/S8-live/RESULTS.md",
				TermsURL:   "https://openai.com/policies/terms-of-use",
				TermsRead:  "2026-10-13",
				Verdict:    Allowed,
			},
		},
		"claude": {
			ID: "claude", CLI: "claude", Version: "0", Image: "claude",
			Argv: []string{"claude", "-p", "--output-format", "json"},
			Cwd:  "/var/lib/agentos-work", ResultPath: "/var/lib/agentos-work/.agentos-result",
			Env:         []string{"PATH=/usr/local/bin:/usr/bin:/bin"},
			Idle:        []string{"/bin/sleep", "infinity"},
			Custody:     WorkerHeld,
			Pools:       []Pool{{Name: "5h", ReadFrom: "anthropic-ratelimit-unified-5h-utilization"}, {Name: "7d", ReadFrom: "anthropic-ratelimit-unified-7d-utilization"}},
			TaskClasses: []string{"code", "research"},
			ErrorEvents: []string{"error"},
			UsedUp:      []string{"rate_limit"},
			// Setup (OAuth) tokens, refresh tokens and API keys, scanned
			// for before a result leaves the worker (S8, mode W).
			CredFormats: []string{`\bsk-ant-(?:oat|ort|api|admin)[0-9]{2}-[A-Za-z0-9_-]{20,}`},
			Q:           Qualification{Verdict: Unclear}, // D-114: off until the owner opts in (#1380)
		},
	}
}
