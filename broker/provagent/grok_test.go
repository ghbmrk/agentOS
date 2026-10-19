package provagent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: CAP-11, CRED-5, CRED-7, CAP-9, RES-5

// xaiFormat is the xAI API key shape the grok declaration withholds; its
// synthetic canary joins the per-format table the CRED-7 test walks.
const xaiFormat = `\bxai-[A-Za-z0-9_-]{20,}`

const xaiCanary = "xai-CANARYcanary0000000000000000"

func init() { builtinCanaries[xaiFormat] = xaiCanary }

// grokRig is a runner whose grok route is the shipped declaration, with
// the image reporting the pinned CLI as built.
func grokRig(cli func(vm.Command, *stub) vm.ExecResult, d Declaration) *rig {
	g := newRig(cli)
	g.r.Decls["grok"] = d
	g.r.ImageVersion = func(string) string { return d.Version }
	return g
}

// grokQualified is a test-only copy of the shipped declaration with its
// qualification record filled and the stub's working directory.
func grokQualified() Declaration {
	d := Builtins()["grok"]
	d.Q.CLIVersion, d.Q.Evidence = d.Version, "spikes/grok-test"
	d.Cwd, d.ResultPath = "/work", "/work/.result"
	return d
}

func grokReq(brief string) Request {
	r := req(brief)
	r.Provider = "grok"
	return r
}

// CAP-11: the grok route is a declaration that validates like any other,
// and the same checks refuse it with a credential-shaped value, a missing
// field or an unknown custody.
func TestGrokDeclarationValidates(t *testing.T) {
	d, found := Builtins()["grok"]
	if !found {
		t.Fatal("no grok builtin")
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	if d.Custody != BrokerHeld || d.Q.Verdict != Allowed || d.Q.TermsURL == "" || d.Q.TermsRead == "" {
		t.Fatalf("custody %q, record %+v", d.Custody, d.Q)
	}
	if d.Q.Complete() {
		t.Fatal("the grok record is complete before #809 fills it")
	}
	for name, mut := range map[string]func(*Declaration){
		"xai key in argv":   func(d *Declaration) { d.Argv = append(d.Argv, xaiCanary) },
		"xai key in env":    func(d *Declaration) { d.Env = append(d.Env, "XAI_API_KEY="+xaiCanary) },
		"token in env":      func(d *Declaration) { d.Env = append(d.Env, "GROK_TOKEN="+canaryToken) },
		"no argv":           func(d *Declaration) { d.Argv = nil },
		"no result path":    func(d *Declaration) { d.ResultPath = "" },
		"no endpoints":      func(d *Declaration) { d.Endpoints = nil },
		"no used-up signal": func(d *Declaration) { d.UsedUp = nil },
		"unknown custody":   func(d *Declaration) { d.Custody = "shared" },
	} {
		c := Builtins()["grok"]
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: validated", name)
		}
	}
}

// CAP-11: until #809 fills the CLI version and evidence, a grok run is
// refused unqualified before any worker exists or any login is seeded.
func TestGrokRefusesUnqualifiedUntilRecordFilled(t *testing.T) {
	g := grokRig(ok("done"), Builtins()["grok"])
	out, err := g.r.Run(context.Background(), grokReq("b"))
	if out != "" || reasonOf(err) != Unqualified {
		t.Fatalf("%q %v", out, err)
	}
	if len(g.h.created) != 0 || len(g.sd.calls) != 0 {
		t.Fatalf("worker %v, seeds %v", g.h.created, g.sd.calls)
	}
	// A filled record whose CLI is not the one the image built is refused
	// the same way.
	d := grokQualified()
	g = grokRig(ok("done"), d)
	g.r.ImageVersion = func(string) string { return "0.0.1" }
	if _, err := g.r.Run(context.Background(), grokReq("b")); reasonOf(err) != Unqualified || len(g.sd.calls) != 0 {
		t.Fatalf("version drift: %v, seeds %v", err, g.sd.calls)
	}
}

// CAP-11: a test-only qualified copy runs a stub end to end, seeded with
// grok's own login and no other provider's.
func TestGrokQualifiedStubRuns(t *testing.T) {
	g := grokRig(ok("done"), grokQualified())
	out, err := g.r.Run(context.Background(), grokReq("b"))
	if err != nil || out != "done" {
		t.Fatalf("run: %q %v", out, err)
	}
	if len(g.sd.providers) != 1 || g.sd.providers[0] != "grok" {
		t.Fatalf("seeded %v", g.sd.providers)
	}
	if len(g.h.created) != 1 || len(g.h.destroyed) != 1 {
		t.Fatalf("worker lifecycle: %v %v", g.h.created, g.h.destroyed)
	}
}

// CRED-7: a result carrying a credential in a shape grok declares is
// withheld by the declared format alone, and the canary is in no error.
func TestGrokResultWithCanaryCredentialWithheld(t *testing.T) {
	for _, canary := range []string{xaiCanary, builtinCanaries[Builtins()["codex"].CredFormats[1]]} {
		g := grokRig(ok("here you go "+canary+" done"), grokQualified())
		g.r.Scan = func(string) bool { return false }
		out, err := g.r.Run(context.Background(), grokReq("b"))
		if out != "" || reasonOf(err) != Withheld {
			t.Fatalf("%s: %q %v", canary[:8], out, err)
		}
		if strings.Contains(fmt.Sprint(err), canary) || strings.Contains(strings.Join(g.logs, "\n"), canary) {
			t.Fatal("the canary left in an error or log")
		}
	}
}

// CAP-9: the CLI's used-up signals end the run as used-up, which falls back.
func TestGrokUsedUpFallsBack(t *testing.T) {
	for _, sig := range Builtins()["grok"].UsedUp {
		g := grokRig(ok(`{"type":"error","message":"`+sig+`"}`), grokQualified())
		_, err := g.r.Run(context.Background(), grokReq("b"))
		if reasonOf(err) != UsedUp || !FallsBack(err) {
			t.Errorf("%s: %v", sig, err)
		}
	}
	if len(Builtins()["grok"].UsedUp) < 2 {
		t.Fatal("grok declares fewer than its two used-up signals")
	}
}

// CRED-5: the declaration's hosts are exactly the egress route's, so a
// route endpoint the declaration does not name (or the reverse) fails.
func TestGrokEndpointsMatchTheEgressRoute(t *testing.T) {
	route := egress.Grok()
	if route.Provider != "grok" {
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
	want := append([]string(nil), Builtins()["grok"].Endpoints...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("route hosts %v, declared %v", got, want)
	}
}
