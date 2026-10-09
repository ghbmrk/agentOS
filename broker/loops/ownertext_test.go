package loops

// REQ: LOOP-9, LOOP-7

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// Owner text for LOOP-7 findings (P3-4b-3c): a cleared text for every
// texted finding, plain words with no identifiers, urgent only with a
// step, and the real recheck cadence.

// hostile is a LOOP-7 finding whose subject and detail carry what owner
// text must never show: a Go identifier, a path and a digest.
func hostile(c Check) Finding {
	f := Finding{Check: c, Severity: High,
		Detail: "crash input sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff in testdata/fuzz/FuzzRequest/0a1b2c3d4e5f"}
	switch c {
	case CheckFuzz:
		f.Subject = "sockets.FuzzRequest"
	case CheckProbe:
		f.Subject = "socket.vm-0a1b2c3d4e5f6a7b"
	case CheckCanary:
		f.Subject = "guest-socket-vault-egress"
	case CheckCorpus:
		f.Subject = "promptinject/goal_hikacking_attacks/ignore-say"
		f.Detail = "code filter"
	}
	return f
}

// A1 R1: Resolve sends the cleared text to every texted finding, paused or
// not, never urgent; an untexted finding clears without a text.
func TestResolveTellsEveryTextedFindingItCleared(t *testing.T) {
	for _, tc := range []struct {
		name    string
		f       Finding
		cleared string
	}{
		{"unpaused", fuzzFinding(), "Cleared: the check that reads agent requests. Nothing more is needed from you."},
		{"paused", withContain(fuzzFinding()), "Cleared: the check that reads agent requests. Pre-allowance G7 stays paused until you resume it on my Wi-Fi page."},
		{"untexted", lowFuzz(), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newReportRig(t, nil)
			id := r.report(t, tc.f).Finding.ID
			before := len(r.texts)
			if err := r.g.Resolve(id, Replay{Evidence: tc.f.Detail, Passed: true}); err != nil {
				t.Fatal(err)
			}
			got := r.texts[before:]
			if tc.cleared == "" {
				if len(got) != 0 {
					t.Fatalf("an untexted finding was texted cleared: %q", got)
				}
				return
			}
			if len(got) != 1 || got[0] != "Security checks: "+tc.cleared || r.urgent[before] {
				t.Fatalf("texts %q urgent %v", got, r.urgent[before:])
			}
		})
	}
}

// A1 R1: a probe's clean run sends the cleared text to every texted
// finding it closes, for canary and corpus alike.
func TestACleanProbeRunTellsEveryTextedFindingItCleared(t *testing.T) {
	for _, tc := range []struct {
		name    string
		f       Finding
		cleared string
	}{
		{"corpus unpaused", hostile(CheckCorpus), "Cleared: the code filter. Nothing more is needed from you."},
		{"canary paused", leak("guest-socket-vault-egress", "G1"), "Cleared: what an agent machine can send out. Pre-allowance G1 stays paused until you resume it on my Wi-Fi page."},
		{"canary untexted", lowCanary(), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &fakeProbe{check: tc.f.Check, every: time.Hour, results: []ProbeResult{
				{Found: []Finding{tc.f}, Checked: []string{tc.f.Subject}},
				{Checked: []string{tc.f.Subject}},
			}}
			r := newReportRig(t, nil)
			r.probes = []Probe{p}
			r.reopen(t)
			runProbeJob(t, r.g)
			before := len(r.texts)
			r.now = r.now.Add(time.Hour)
			runProbeJob(t, r.g)
			got := r.texts[before:]
			if tc.cleared == "" {
				if len(got) != 0 {
					t.Fatalf("an untexted finding was texted cleared: %q", got)
				}
				return
			}
			if len(got) != 1 || got[0] != "Security checks: "+tc.cleared || r.urgent[before] {
				t.Fatalf("texts %q urgent %v", got, r.urgent[before:])
			}
		})
	}
}

// runProbeJob runs Guard's jobs until one is a probe's, which must succeed.
func runProbeJob(t *testing.T, g *Guard) {
	t.Helper()
	for range 3 {
		name, res := runJob(t, g, context.Background())
		if res.Err != nil {
			t.Fatalf("%q %+v", name, res)
		}
		if strings.HasPrefix(name, "probe:") {
			return
		}
	}
	t.Fatal("no probe job offered")
}

func withContain(f Finding) Finding {
	f.Contain = &Target{Kind: "grant", Name: "G7", Label: "pre-allowance G7"}
	return f
}

func lowFuzz() Finding {
	f := fuzzFinding()
	f.Severity = Low
	return f
}

func lowCanary() Finding {
	f := leak("drive-at-rest-a8", "G1")
	f.Severity, f.Contain = Low, nil
	return f
}

// A1 R2: no LOOP-7 text shows an identifier, path or digest from its
// subject or detail; the corpus text is the UX wording; fuzz and probe say
// the fix comes with an update.
func TestLoop7TextsAreInPlainWords(t *testing.T) {
	want := map[Check]string{
		CheckFuzz:   "My self-test found a crash in the check that reads agent requests. The fix comes with an update.",
		CheckProbe:  "My self-test of an agent machine's connection to me failed. The fix comes with an update.",
		CheckCanary: "My leak self-test found a planted test secret in what an agent machine can send out.",
		CheckCorpus: "My self-test of the code filter failed: it missed a test code hidden inside a known attack text. Nothing real was exposed.",
	}
	for c, w := range want {
		f := hostile(c)
		got := findingText(f)
		if got != w {
			t.Errorf("%s: %q, want %q", c, got, w)
		}
		for _, bad := range []string{f.Subject, f.Detail, "sockets", "Fuzz", "/", "sha256", "on my current setup", "promptinject", "vm-0a1b"} {
			if bad != "" && bad != "code filter" && strings.Contains(got, bad) {
				t.Errorf("%s: %q shows %q", c, got, bad)
			}
		}
	}
	// A target or check the map does not name falls back to a generic name.
	for _, f := range []Finding{
		{Check: CheckFuzz, Subject: "newpkg.FuzzThing", Detail: "x"},
		{Check: CheckProbe, Subject: "otherprobe.vm1", Detail: "x"},
		{Check: CheckCorpus, Subject: "a/b", Detail: "newCheck"},
	} {
		if got := findingText(f); !strings.Contains(got, "one of my internal checks") || strings.Contains(got, "newpkg") || strings.Contains(got, "newCheck") {
			t.Errorf("fallback %q", got)
		}
	}
}

// A1 R3: a finding is urgent only when its line names a pause that
// happened or a reply that works, or it is a canary leak; any other line
// says nothing is paused or needed, and Pass and tell share the rule.
func TestUrgentOnlyWithAStep(t *testing.T) {
	r := newReportRig(t, nil)
	r.report(t, fuzzFinding())
	if len(r.texts) != 1 || r.urgent[0] || !strings.HasSuffix(r.texts[0], nothingNeeded) {
		t.Fatalf("fuzz without containment: %q urgent %v", r.texts, r.urgent)
	}
	c := leak("guest-socket-vault-egress", "G1")
	c.Contain = nil
	r.report(t, c)
	if len(r.texts) != 2 || !r.urgent[1] || !strings.HasSuffix(r.texts[1], "Reply STOP to pause everything.") {
		t.Fatalf("canary leak: %q urgent %v", r.texts, r.urgent)
	}
	capped := Record{Finding: withContain(fuzzFinding()), Contained: "capped"}
	if line := ownerLine(capped); !urgentText(capped) || !strings.Contains(line, "Reply PAUSE G7") {
		t.Fatalf("capped grant: %q", line)
	}
	for _, rec := range []Record{
		{Finding: withContain(fuzzFinding()), Contained: "paused"},
		{Finding: withContain(fuzzFinding()), Contained: "failed"},
		capped,
		{Finding: c, Contained: "none"},
	} {
		if !urgentText(rec) || !namesAStep(ownerLine(rec)) {
			t.Errorf("%s/%s: urgent %v, %q", rec.Finding.Check, rec.Contained, urgentText(rec), ownerLine(rec))
		}
	}
	for _, c := range []Check{CheckHash, CheckDrift, CheckSeeded, CheckProbe, CheckCorpus, CheckTamper, CheckExhaust} {
		rec := Record{Finding: Finding{Check: c, Subject: "x", Detail: "d", Severity: High}, Contained: "none"}
		if urgentText(rec) || !strings.HasSuffix(ownerLine(rec), nothingNeeded) {
			t.Errorf("%s none: urgent %v, %q", c, urgentText(rec), ownerLine(rec))
		}
	}
}

// A1 R3: Pass's batch is urgent through the same rule: a High hash finding
// with nothing paused is sent non-urgent, one with a pause urgent.
func TestPassBatchUrgencyFollowsTheStepRule(t *testing.T) {
	for _, tc := range []struct {
		artifact string
		urgent   bool
		says     string
	}{
		{"dep/libfoo", false, nothingNeeded},
		{"guest-image/openclaw", true, "Paused the agent machine."},
	} {
		b := cleanBox()
		b.measured[tc.artifact] = "evil"
		g := newGuardRig(t, b)
		if _, err := g.g.Pass(context.Background()); err != nil {
			t.Fatal(err)
		}
		if len(g.texts) != 1 || g.urgent[0] != tc.urgent || !strings.Contains(g.texts[0], tc.says) {
			t.Fatalf("%s: texts %q urgent %v", tc.artifact, g.texts, g.urgent)
		}
	}
}

// A1 R4: the wait line claims only the cadence P3-4b-3a bounds (12 h).
func TestTheWaitLineSaysTheRealCadence(t *testing.T) {
	if waitUpdate != "one comes with an update; I check it again at least twice a day" {
		t.Fatalf("wait line %q", waitUpdate)
	}
	if strings.Contains(waitUpdate, "every round") {
		t.Fatal("the wait line says every round")
	}
}

var (
	// innerCap is a word with a capital after a lower-case letter, as in
	// FuzzRequest or vmName.
	innerCap   = regexp.MustCompile(`[a-z][A-Z]`)
	goPrefix   = regexp.MustCompile(`\b(Fuzz|Test)[A-Z0-9_]`)
	hexRun     = regexp.MustCompile(`[0-9a-fA-F]{8,}`)
	stepPhrase = regexp.MustCompile(`\bPaused \S|\bReply (STOP|PAUSE)\b|\bSTOP pauses everything\b`)
)

func namesAStep(line string) bool { return stepPhrase.MatchString(line) }

// identifierIn is the first Go identifier, path or digest in s, or "".
func identifierIn(s string) string {
	for _, re := range []*regexp.Regexp{innerCap, goPrefix, hexRun} {
		if m := re.FindString(s); m != "" {
			return m
		}
	}
	if strings.Contains(s, "/") {
		return "/"
	}
	if strings.Contains(s, ".go") {
		return ".go"
	}
	return ""
}

// The lens check (UX, second occurrence on #523 and #515): every check's
// owner line in each containment state names no identifier, never alarms
// without a step, and fits three GSM-7 segments.
func TestFindingTextsNameNoIdentifiersAndNeverAlarmWithoutAStep(t *testing.T) {
	// The LOOP-7 checks get hostile subjects; the passive checks, which
	// name a file, package or credential the owner must find, get plain
	// ones, as do tamper and exhaustion, whose subjects are fixed words.
	findings := []Finding{hostile(CheckFuzz), hostile(CheckProbe), hostile(CheckCanary), hostile(CheckCorpus),
		{Check: CheckFuzz, Subject: "hostdisk.FuzzProbe", Detail: "x"},
		{Check: CheckCanary, Subject: "registry-entry-0a1b2c3d4e", Detail: "kinds: api_key"},
		{Check: CheckTamper, Subject: "evaluator", Detail: "writable"},
		{Check: CheckExhaust, Subject: "memory", Detail: "no limit"},
		{Check: CheckExhaust, Subject: "preemption", Detail: "slow"},
		{Check: CheckHash, Subject: "agent-image", Detail: "differs from the signed release"},
		{Check: CheckDrift, Subject: "routes", Detail: "changed"},
		{Check: CheckAdvisory, Subject: "openssl", Detail: "CVE-2026-1", Fixed: "3.1"},
		{Check: CheckExpiry, Subject: "mail-login", Detail: "expires in 3 days"},
		{Check: CheckSeeded, Subject: "private-route", Detail: "x"},
	}
	// The scan catches what it must.
	for _, s := range []string{"sockets.FuzzRequest", "a/b", "x.go", "00112233aa", "vmName", "TestX"} {
		if identifierIn(s) == "" {
			t.Fatalf("the scan misses %q", s)
		}
	}
	if identifierIn("Reply PAUSE G7 to pause it, or STOP. My Wi-Fi page.") != "" {
		t.Fatal("the scan flags plain words")
	}
	for _, f := range findings {
		f.Severity = High
		for _, state := range []string{"none", "paused", "failed", "capped"} {
			for _, kind := range []string{"grant", "executor"} {
				rec := Record{Finding: f, Contained: state}
				if state != "none" {
					rec.Finding.Contain = &Target{Kind: kind, Name: "G7", Label: "pre-allowance G7"}
				}
				line := ownerLine(rec)
				cleared := clearedLine(rec)
				for _, s := range []string{line, cleared} {
					loop7 := f.Check == CheckFuzz || f.Check == CheckProbe || f.Check == CheckCanary || f.Check == CheckCorpus
					if bad := identifierIn(s); bad != "" && loop7 {
						t.Errorf("%s/%s: %q shows %q", f.Check, state, s, bad)
					}
					if n, gsm := modem.Segments("Security checks: " + s); !gsm || n > 3 {
						t.Errorf("%s/%s: %q is %d segments, GSM-7 %v", f.Check, state, s, n, gsm)
					}
				}
				if urgentText(rec) && !namesAStep(line) {
					t.Errorf("%s/%s: urgent without a step: %q", f.Check, state, line)
				}
				if !urgentText(rec) && namesAStep(line) {
					t.Errorf("%s/%s: names a step but is not urgent: %q", f.Check, state, line)
				}
			}
		}
	}
}
