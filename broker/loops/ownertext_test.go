package loops

// REQ: LOOP-9, LOOP-7

import (
	"context"
	"errors"
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
		{"unpaused", fuzzFinding(), "Cleared: the crash in the check that reads agent requests. Nothing more is needed from you."},
		{"paused", withContain(fuzzFinding()), "Cleared: the crash in the check that reads agent requests. Pre-allowance G7 stays paused until you resume it on my Wi-Fi page."},
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
				{Found: []Finding{tc.f}, Checked: []string{checkedKey(tc.f)}},
				{Checked: []string{checkedKey(tc.f)}},
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
// happened or a reply that works; a leak or tampering (canary, hash,
// drift, tamper) always offers STOP and so stays urgent unpaused
// (Security 4a on #558); any other line says nothing is paused or needed,
// and Pass and tell share the rule.
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
	for _, c := range []Check{CheckHash, CheckDrift, CheckTamper, CheckCanary} {
		rec := Record{Finding: Finding{Check: c, Subject: "x", Detail: "d", Severity: High}, Contained: "none"}
		if line := ownerLine(rec); !urgentText(rec) || !strings.HasSuffix(line, "Reply STOP to pause everything.") || strings.Contains(line, nothingNeeded) {
			t.Errorf("%s none: urgent %v, %q", c, urgentText(rec), line)
		}
	}
	for _, c := range []Check{CheckSeeded, CheckFuzz, CheckProbe, CheckCorpus, CheckExhaust, CheckAdvisory} {
		rec := Record{Finding: Finding{Check: c, Subject: "x", Detail: "d", Severity: High}, Contained: "none"}
		if line := ownerLine(rec); urgentText(rec) || !strings.HasSuffix(line, nothingNeeded) || namesAStep(line) {
			t.Errorf("%s none: urgent %v, %q", c, urgentText(rec), line)
		}
	}
}

// A1 R3: Pass's batch is urgent through the same rule: a hash mismatch is
// urgent paused or not, offering STOP when nothing was paused; an
// advisory with nothing paused is not.
func TestPassBatchUrgencyFollowsTheStepRule(t *testing.T) {
	for _, tc := range []struct {
		artifact string
		urgent   bool
		says     string
	}{
		{"dep/libfoo", true, "Reply STOP to pause everything."},
		{"guest-image/openclaw", true, "Paused the agent machine."},
		{"advisory", false, nothingNeeded},
	} {
		b := cleanBox()
		if tc.artifact == "advisory" {
			b.pkgs[0].Contain = nil
			b.snap.Advisories[0].Fixed = "3.0.16"
		} else {
			b.measured[tc.artifact] = "evil"
		}
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

// REQ: LOOP-7, RES-1
//
// P3-4b-4c-step (#548 UX 1): a limit above the configured budget says
// which resource and that the machine is over its budget, not that no
// limit exists; with no containment (S37) its line says nothing is
// paused and nothing is needed.
func TestAnAboveBudgetLimitSaysSoAndThatNothingIsNeeded(t *testing.T) {
	for subject, want := range map[string]string{
		"memory":    "A load test found an agent machine can use more memory than its budget.",
		"processes": "A load test found an agent machine can start more processes than its budget.",
		"disk":      "A load test found an agent machine can use more disk space than its budget.",
		"cpu":       "A load test found an agent machine can take as large a share of processor time as I get.",
	} {
		f := Finding{Check: CheckExhaust, Subject: subject, Detail: "above budget", Severity: High}
		if got := ownerLine(Record{Finding: f}); got != want+" "+nothingNeeded {
			t.Errorf("%s: %q", subject, got)
		}
	}
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
		{Check: CheckExhaust, Subject: "memory", Detail: "above budget"},
		{Check: CheckExhaust, Subject: "processes", Detail: "above budget"},
		{Check: CheckExhaust, Subject: "disk", Detail: "above budget"},
		{Check: CheckExhaust, Subject: "cpu", Detail: "above budget"},
		{Check: CheckExhaust, Subject: "preemption", Detail: "slow"},
		{Check: CheckHash, Subject: "agent-image", Detail: "differs from the signed release"},
		{Check: CheckDrift, Subject: "routes", Detail: "changed"},
		{Check: CheckAdvisory, Subject: "openssl", Detail: "CVE-2026-1", Fixed: "3.1"},
		{Check: CheckExpiry, Subject: "mail-login", Detail: "expires in 3 days"},
		{Check: CheckSeeded, Subject: "private-route", Detail: "x"},
		{Check: CheckFuzz, Subject: "sockets.FuzzRequest", Detail: FuzzOverrunDetail},
		{Check: CheckFuzz, Subject: "sockets.FuzzRequest", Detail: FuzzStallDetail},
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
				// A hang is not a crash (P3-4b-3r-fuzz).
				if hangDetail(f.Detail) && strings.Contains(strings.ToLower(line), "crash") {
					t.Errorf("%s/%s: a hang reads as a crash: %q", f.Check, state, line)
				}
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

// A1 R1, L3 #558 point 1: plain names can join distinct findings (two
// crashes in one target, two machines' probes), so "Cleared: X" is sent
// only once no open texted finding shares X, and once per X.
func TestClearedWaitsForEveryFindingSharingItsPlainName(t *testing.T) {
	t.Run("Resolve", func(t *testing.T) {
		r := newReportRig(t, nil)
		a, b := fuzzFinding(), fuzzFinding()
		b.Detail = "crash input sha256:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
		ida, idb := r.report(t, a).Finding.ID, r.report(t, b).Finding.ID
		before := len(r.texts)
		if err := r.g.Resolve(ida, Replay{Evidence: a.Detail, Passed: true}); err != nil {
			t.Fatal(err)
		}
		if got := r.texts[before:]; len(got) != 0 {
			t.Fatalf("cleared while another crash in the same check is open: %q", got)
		}
		if err := r.g.Resolve(idb, Replay{Evidence: b.Detail, Passed: true}); err != nil {
			t.Fatal(err)
		}
		if got := r.texts[before:]; len(got) != 1 || !strings.Contains(got[0], "Cleared: the crash in the check that reads agent requests.") {
			t.Fatalf("texts %q", got)
		}
	})
	t.Run("runProbe", func(t *testing.T) {
		pa, pb := hostile(CheckCorpus), hostile(CheckCorpus)
		pb.Subject = "other/item"
		p := &fakeProbe{check: CheckCorpus, every: time.Hour, results: []ProbeResult{
			{Found: []Finding{pa, pb}, Checked: []string{checkedKey(pa), checkedKey(pb)}},
			{Found: []Finding{pb}, Checked: []string{checkedKey(pa), checkedKey(pb)}},
			{Checked: []string{checkedKey(pa), checkedKey(pb)}},
		}}
		r := newReportRig(t, nil)
		r.probes = []Probe{p}
		r.reopen(t)
		runProbeJob(t, r.g)
		before := len(r.texts)
		r.now = r.now.Add(time.Hour)
		runProbeJob(t, r.g)
		if got := r.texts[before:]; len(got) != 0 {
			t.Fatalf("cleared while another item on the same check is open: %q", got)
		}
		r.now = r.now.Add(time.Hour)
		runProbeJob(t, r.g)
		if got := r.texts[before:]; len(got) != 1 || got[0] != "Security checks: Cleared: the code filter. Nothing more is needed from you." {
			t.Fatalf("texts %q", got)
		}
	})
}

// clearedTexts is the texts since before that say a finding cleared.
func clearedTexts(texts []string, before int) []string {
	var out []string
	for _, t := range texts[before:] {
		if strings.Contains(t, "Cleared:") {
			out = append(out, t)
		}
	}
	return out
}

// P3-4b-3r-pass requirement 1 (#558 Security 4a point 2, L3 point 3): a
// check that failed to run closes none of its open findings, seen or
// not, so no "Cleared" is sent for a finding nothing looked at; the next
// clean run closes it and says so once.
func TestAFailedCheckClosesNothing(t *testing.T) {
	for _, c := range []struct {
		name   string
		break_ func(*box)
		fail   func(*box, error)
		fix    func(*box)
		want   string
	}{
		{"paused hash, Signed errors",
			func(b *box) { b.measured["guest-image/openclaw"] = "tampered" },
			func(b *box, err error) { b.signedErr = err },
			func(b *box) { b.measured["guest-image/openclaw"] = "aa" },
			"Cleared: guest-image/openclaw. The agent machine stays paused until you resume it on my Wi-Fi page."},
		{"unpaused drift, Live errors",
			func(b *box) { b.live["config/quiet.json"] = "edited" },
			func(b *box, err error) { b.liveErr = err },
			func(b *box) { b.live["config/quiet.json"] = "c1" },
			"Cleared: config/quiet.json. Nothing more is needed from you."},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := cleanBox()
			c.break_(b)
			r := newGuardRig(t, b)
			if n := r.pass(t); n != 1 || len(r.texts) != 1 {
				t.Fatalf("findings %d, texts %q", n, r.texts)
			}
			c.fix(b) // repaired, but the check cannot look
			c.fail(b, errors.New("unreadable"))
			before := len(r.texts)
			r.now = r.now.Add(6 * time.Hour)
			r.pass(t)
			if got := clearedTexts(r.texts, before); len(got) != 0 {
				t.Fatalf("cleared while its check failed: %q", got)
			}
			if len(r.g.Evidence()) != 1 || len(r.g.st.Open) != 1 {
				t.Fatalf("finding closed while its check failed: %+v", r.g.st.Open)
			}
			c.fail(b, nil)
			r.now = r.now.Add(6 * time.Hour)
			r.pass(t)
			if got := clearedTexts(r.texts, before); len(got) != 1 || !strings.Contains(got[0], c.want) {
				t.Fatalf("cleared texts %q, want one with %q", got, c.want)
			}
			if len(r.g.st.Open) != 0 {
				t.Fatalf("still open: %+v", r.g.st.Open)
			}
			r.now = r.now.Add(6 * time.Hour)
			r.pass(t)
			if got := clearedTexts(r.texts, before); len(got) != 1 {
				t.Fatalf("cleared said again: %q", got)
			}
		})
	}
}

// P3-4b-3r-pass requirement 2 (#558 Potency; S39): Pass texts "Cleared"
// for every texted finding, paused or not, through the dedupe Resolve
// and runProbe use, and never urgently; an untexted one clears only in
// STATUS and the digest.
func TestPassTellsEveryTextedFindingItCleared(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*box)
		fix    func(*box)
		want   string // "" means no text
	}{
		{"texted unpaused",
			func(b *box) { b.live["config/quiet.json"] = "edited" },
			func(b *box) { b.live["config/quiet.json"] = "c1" },
			"Cleared: config/quiet.json. Nothing more is needed from you."},
		{"texted paused",
			func(b *box) { b.measured["guest-image/openclaw"] = "tampered" },
			func(b *box) { b.measured["guest-image/openclaw"] = "aa" },
			"Cleared: guest-image/openclaw. The agent machine stays paused until you resume it on my Wi-Fi page."},
		{"untexted",
			func(b *box) {
				b.expiries = append(b.expiries, Expiry{Name: "cal-cert", NotAfter: t0.Add(3 * 24 * time.Hour)})
			},
			func(b *box) { b.expiries = b.expiries[:1] },
			""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := cleanBox()
			c.break_(b)
			r := newGuardRig(t, b)
			if n := r.pass(t); n != 1 {
				t.Fatalf("findings %d: %+v", n, r.g.Evidence())
			}
			c.fix(b)
			before := len(r.texts)
			r.now = r.now.Add(6 * time.Hour)
			r.pass(t)
			got := r.texts[before:]
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("untexted finding texted on clearing: %q", got)
				}
				return
			}
			if len(got) != 1 || !strings.Contains(got[0], c.want) || strings.Count(got[0], "Cleared:") != 1 {
				t.Fatalf("texts %q, want one with %q", got, c.want)
			}
			if r.urgent[len(r.urgent)-1] {
				t.Fatalf("cleared text sent urgent: %q", got[0])
			}
		})
	}

	// Two texted findings whose plain names join ("config/a!" and
	// "config/a" both read config/a) send one line, once both cleared.
	t.Run("shared plain name", func(t *testing.T) {
		b := cleanBox()
		b.live["config/a!"], b.live["config/a"] = "x", "y"
		r := newGuardRig(t, b)
		if n := r.pass(t); n != 2 {
			t.Fatalf("findings %d", n)
		}
		before := len(r.texts)
		delete(b.live, "config/a!")
		r.now = r.now.Add(6 * time.Hour)
		r.pass(t)
		if got := clearedTexts(r.texts, before); len(got) != 0 {
			t.Fatalf("cleared while another config/a is open: %q", got)
		}
		delete(b.live, "config/a")
		r.now = r.now.Add(6 * time.Hour)
		r.pass(t)
		if got := clearedTexts(r.texts, before); len(got) != 1 || strings.Count(got[0], "Cleared: config/a.") != 1 {
			t.Fatalf("cleared texts %q", got)
		}
	})
	// One clears in the pass where another with its plain name is found:
	// the new alert goes out, and no "Cleared" for the same name with it.
	t.Run("shared plain name, found as one clears", func(t *testing.T) {
		b := cleanBox()
		b.live["config/a!"] = "x"
		r := newGuardRig(t, b)
		r.pass(t)
		before := len(r.texts)
		delete(b.live, "config/a!")
		b.live["config/a"] = "y"
		r.now = r.now.Add(6 * time.Hour)
		r.pass(t)
		if got := clearedTexts(r.texts, before); len(got) != 0 {
			t.Fatalf("cleared sent with a new config/a: %q", got)
		}
	})
}

// Security 4a point 1 on #585: a finding that moves between two details
// keeps one plain name open, its return counted Again; "Cleared" for that
// name is never texted while it is open, Again or not.
func TestNoClearedWhileAFindingMovesBetweenDetails(t *testing.T) {
	for _, c := range []struct {
		name       string
		a, b, back func(*box)
	}{
		{"unpaused drift",
			func(b *box) { b.live["config/quiet.json"] = "edited" },
			func(b *box) { delete(b.live, "config/quiet.json") },
			func(b *box) { b.live["config/quiet.json"] = "edited" }},
		{"paused hash",
			func(b *box) { b.measured["guest-image/openclaw"] = "tampered" },
			func(b *box) { delete(b.signed, "guest-image/openclaw") },
			func(b *box) { b.signed["guest-image/openclaw"] = "aa" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := cleanBox()
			c.a(b)
			r := newGuardRig(t, b)
			r.pass(t)
			for _, step := range []func(*box){c.b, c.back} {
				step(b)
				r.now = r.now.Add(6 * time.Hour)
				r.pass(t)
			}
			if got := clearedTexts(r.texts, 0); len(got) != 0 {
				t.Fatalf("cleared while a finding on the same name is open: %q", got)
			}
			if len(r.g.st.Open) != 1 {
				t.Fatalf("open %+v", r.g.st.Open)
			}
		})
	}
}
