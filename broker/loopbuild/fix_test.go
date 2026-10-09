package loopbuild

// REQ: LOOP-9, CHG-2, LOOP-2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
)

// minimized is a seeded finding's minimized regression, as Loop 2 hands it
// to its fixer; other is another case's input and held a held-back
// variant, neither of which the fixer may ever see (CHG-1, CHG-2).
const (
	minimized = `{"tree_rule":[{"path":"config/privacy.json","pointer":"/private_routes","op":"subset","value":["local"]}]}`
	other     = `{"tree_rule":[{"path":"context/web.json","pointer":"/select","op":"subset","value":["pages"]}]}`
	held      = `{"tree_rule":[{"path":"config/privacy.json","pointer":"/fallback","op":"eq","value":"local"}]}`
)

func finding() loops.Finding {
	return loops.Finding{ID: "seeded-1", Check: loops.CheckSeeded, Subject: "private work may use the cloud route",
		Detail: "config/privacy.json lists cloud as a private route", Severity: loops.High, Rule: []byte(minimized)}
}

// LOOP-9 through Loop 1's builder (P3-4b-5): one finding is one job on a
// fresh fix machine, whose brief carries the finding's subject, detail
// and minimized regression and nothing else; the candidate comes back
// unstamped, for Loop 2 to stamp, written only in the namespace the
// finding names.
func TestAFindingIsOneFixJobBriefedOnlyWithItself(t *testing.T) {
	f := &machines{}
	var raw string
	var refused int
	f.guest = func(id, dir string) {
		c := guestClient(dir)
		_, raw = call(c, "GET", "/brief", nil)
		refused, _ = call(c, "POST", "/candidate", Submission{Files: map[string]string{"procedures/p.json": "{}"}})
		call(c, "POST", "/candidate", Submission{Files: map[string]string{"config/privacy.json": `{"private_routes":["local"]}`}})
	}
	b := newBuilder(t, f, nil)
	cand, err := b.Fix(context.Background(), finding())
	if err != nil {
		t.Fatal(err)
	}
	if len(f.destroyed) != 1 || !strings.HasPrefix(f.destroyed[0], FixPrefix) {
		t.Fatalf("jobs %v, want one fix machine", f.destroyed)
	}
	if refused != http.StatusUnprocessableEntity {
		t.Fatalf("a write outside the finding's namespace answered %d", refused)
	}
	if len(cand.Files) != 1 || string(cand.Files["config/privacy.json"]) != `{"private_routes":["local"]}` {
		t.Fatalf("candidate files %v", cand.Files)
	}
	if cand.Source != "" || cand.Origin != "" || cand.Finding != "" || cand.Public || cand.Goals != nil || cand.Claim != "" {
		t.Fatalf("the fixer stamped its candidate: %+v", cand)
	}
	var got Brief
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	if got.Signal != FixSignal || got.Writes != "config" || got.Class != string(change.ClassConfig) || got.Key != "seeded-1" ||
		got.Subject != finding().Subject || got.Detail != finding().Detail || len(got.Steps) != 0 ||
		len(got.Cases) != 1 || string(got.Cases[0].Input) != minimized {
		t.Fatalf("brief %s", raw)
	}
	for _, leak := range []string{other, held, "context/web.json", "/fallback"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("brief carries %q: %s", leak, raw)
		}
	}
}

// C-3c-4 kept: a finding that names no single namespace a fix may write
// (none, two, or one only the owner changes) gets no job at all.
func TestAFindingWithoutOneFixableNamespaceGetsNoJob(t *testing.T) {
	two := `{"tree_rule":[{"path":"config/a.json","op":"absent"},{"path":"context/b.json","op":"absent"}]}`
	for name, rule := range map[string]string{
		"no rule":       "",
		"not a rule":    `{"q":1}`,
		"two":           two,
		"grants":        `{"tree_rule":[{"path":"grants/g.json","op":"absent"}]}`,
		"suites":        `{"tree_rule":[{"path":"suites/s.json","op":"absent"}]}`,
		"routing":       `{"tree_rule":[{"path":"routing/rule.json","op":"absent"}]}`,
		"invalid op":    `{"tree_rule":[{"path":"config/a.json","op":"ne"}]}`,
		"empty clauses": `{"tree_rule":[]}`,
	} {
		f := &machines{}
		b := newBuilder(t, f, nil)
		fd := finding()
		fd.Rule = []byte(rule)
		if rule == "" {
			fd.Rule = nil
		}
		if _, err := b.Fix(context.Background(), fd); !errors.Is(err, ErrNoNamespace) || !errors.Is(err, loops.ErrNotFixable) {
			t.Errorf("%s: %v", name, err)
		}
		if len(f.destroyed) != 0 || len(f.ms) != 0 {
			t.Errorf("%s: a machine was made", name)
		}
	}
}

// LOOP-2: fix jobs and Loop 1's jobs are told apart by ID, so each is its
// own share of the spare meter; a fix job's tokens never count against
// Loop 1's builder share.
func TestFixJobsAreTheirOwnShare(t *testing.T) {
	if strings.HasPrefix(FixPrefix, BuildPrefix) || strings.HasPrefix(BuildPrefix, FixPrefix) ||
		!strings.HasPrefix(FixPrefix, Prefix) || !strings.HasPrefix(BuildPrefix, Prefix) {
		t.Fatalf("prefixes %q %q", BuildPrefix, FixPrefix)
	}
	m, err := meter.Open(meter.Config{Path: t.TempDir() + "/m.json", MachineCap: meter.DefaultMachineCap, OverallCap: meter.Limits{Calls: 100, Tokens: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetShares([]meter.Share{{Prefix: BuildPrefix, Max: 0.35}, {Prefix: FixPrefix, Max: 0.15}}); err != nil {
		t.Fatal(err)
	}
	f := &machines{}
	f.guest = func(id, dir string) {
		call(guestClient(dir), "POST", "/candidate", Submission{Files: map[string]string{"procedures/mail": "v"}})
	}
	b := newBuilder(t, f, nil)
	if _, err := b.Build(context.Background(), brief(change.ClassProcedure)); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(f.destroyed[0], BuildPrefix) {
		t.Fatalf("loop 1 job %s", f.destroyed[0])
	}
}

// No model grant: the builder says why it cannot fix, without a job, so
// Loop 2 keeps the request open and STATUS names the cause.
func TestABuilderWithoutModelAccessSaysSo(t *testing.T) {
	b := newBuilder(t, &machines{}, nil)
	if why := b.Unready(); why != NoModel {
		t.Fatalf("unready %q", why)
	}
	m, err := meter.Open(meter.Config{Path: t.TempDir() + "/m.json", MachineCap: meter.DefaultMachineCap, OverallCap: meter.Limits{Calls: 100, Tokens: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	b = newBuilder(t, &machines{}, func(c *Config) {
		c.Meter = m
		c.Model = func(string) http.Handler { return http.NotFoundHandler() }
	})
	if why := b.Unready(); why != "" {
		t.Fatalf("unready %q with a model route", why)
	}
}
