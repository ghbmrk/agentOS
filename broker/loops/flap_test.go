package loops

// REQ: LOOP-9, CH-15
//
// P3-4b-3r-told requirement 2 (Security README, "A 'Cleared' or return
// text disagrees with the finding's state", second PR #585, #586): one
// helper drives a finding through each close path, Pass, Resolve,
// runProbe and CloseTarget, and checks the owner's texts after every
// step: alert, cleared, a return within ReText, a move between two
// details, each with and without a restart (reopen) after every step.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// flapPath is one close path's adapter. set makes detail 0 and detail 1
// of one plain name observed (on) or not and runs the path once; a
// detail turned on is reported before one turned off is closed, so a
// move between details never leaves the name unheld.
type flapPath struct {
	texts   func() ([]string, []bool)
	set     func(t *testing.T, on [2]bool)
	reopen  func(t *testing.T)
	advance func(time.Duration)
}

const itIsBackLead = "Security checks: It is back: "

// flapStep is one step and the texts it must send: alert (a first
// alert), back (a return after "Cleared"), cleared, or nothing.
type flapStep struct {
	on   [2]bool
	want []string
}

// The full flap of one detail (requirements 4 and 5): alert, cleared,
// back, cleared, then an untexted return and an untexted close; a return
// after ReText is a first alert again. At most four texts per ReText,
// and the owner's last text matches the state until the bound is spent.
var flapSeq = []flapStep{
	{[2]bool{true, false}, []string{"alert"}},
	{[2]bool{false, false}, []string{"cleared"}},
	{[2]bool{true, false}, []string{"back"}},
	{[2]bool{false, false}, []string{"cleared"}},
	{[2]bool{true, false}, nil},
	{[2]bool{false, false}, nil},
}

// The move (Security 4a on #585, L3 #586 point 4): the finding moves to
// its other detail and back, then clears. No "Cleared" is said while
// either is open, a return the owner never heard cleared is not texted
// as "back", and once both close the held "Cleared" is owed and said
// once, so the owner is not left on the second detail's alert (L3 1 on
// #644).
var moveSeq = []flapStep{
	{[2]bool{true, false}, []string{"alert"}},
	{[2]bool{false, true}, []string{"alert"}},
	{[2]bool{true, false}, nil},
	{[2]bool{false, false}, []string{"cleared"}},
	{[2]bool{false, false}, nil},
	// The owed line covers both details: either one's return is "back"
	// (UX and Potency deltas on #644), and is bounded as any Back is.
	{[2]bool{true, false}, []string{"back"}},
	{[2]bool{false, false}, []string{"cleared"}},
	{[2]bool{false, true}, []string{"back"}},
	{[2]bool{false, false}, []string{"cleared"}},
	{[2]bool{false, true}, nil},
	// The owed line was spent: a later untexted close says nothing.
	{[2]bool{false, false}, nil},
}

// Both heard (L3 delta 1 on #644): both details open and texted; detail 0
// closes while detail 1 holds the name (owed), detail 1 closes with its
// own line, and detail 0's return is "back", since its "Cleared" was said.
var bothSeq = []flapStep{
	{[2]bool{true, false}, []string{"alert"}},
	{[2]bool{true, true}, []string{"alert"}},
	{[2]bool{false, true}, nil},
	{[2]bool{false, false}, []string{"cleared"}},
	{[2]bool{true, false}, []string{"back"}},
	{[2]bool{false, false}, []string{"cleared"}},
}

func runFlap(t *testing.T, mk func(t *testing.T) flapPath) {
	for _, restart := range []bool{false, true} {
		name := "no restart"
		if restart {
			name = "restart at each step"
		}
		t.Run(name, func(t *testing.T) {
			p := mk(t)
			playFlap(t, p, flapSeq, restart)
			p.advance(25 * time.Hour)
			playFlap(t, p, []flapStep{{[2]bool{true, false}, []string{"alert"}}, {[2]bool{false, false}, []string{"cleared"}}}, restart)
		})
		t.Run(name+", move", func(t *testing.T) {
			playFlap(t, mk(t), moveSeq, restart)
		})
		t.Run(name+", both heard", func(t *testing.T) {
			playFlap(t, mk(t), bothSeq, restart)
		})
	}
}

func playFlap(t *testing.T, p flapPath, seq []flapStep, restart bool) {
	t.Helper()
	for i, st := range seq {
		before, _ := p.texts()
		n := len(before)
		p.advance(time.Hour)
		p.set(t, st.on)
		all, urgent := p.texts()
		got := all[n:]
		if len(got) != len(st.want) {
			t.Fatalf("step %d %v: texts %q, want %v", i, st.on, got, st.want)
		}
		for j, w := range st.want {
			g := got[j]
			ok := false
			switch w {
			case "alert":
				ok = !strings.Contains(g, "Cleared") && !strings.Contains(g, "It is back")
			case "back":
				ok = strings.HasPrefix(g, itIsBackLead) && !strings.Contains(g, "Cleared")
			case "cleared":
				// The extra "Cleared" is unsolicited and non-urgent, so it
				// takes CH-15's paced path downstream (requirement 5).
				ok = strings.HasPrefix(g, "Security checks: Cleared: ") && !urgent[n+j]
			}
			if !ok {
				t.Fatalf("step %d %v: text %q (urgent %v), want %s", i, st.on, g, urgent[n+j], w)
			}
		}
		if restart {
			p.reopen(t)
		}
	}
}

// Pass: drift findings on two files whose plain names join (config/a!
// and config/a both read config/a), each changed (on) or gone (off).
func TestFlapThroughPass(t *testing.T) {
	runFlap(t, func(t *testing.T) flapPath {
		b := cleanBox()
		r := newGuardRig(t, b)
		return flapPath{
			texts: func() ([]string, []bool) { return r.texts, r.urgent },
			set: func(t *testing.T, on [2]bool) {
				for i, name := range []string{"config/a!", "config/a"} {
					if on[i] {
						b.live[name] = "x"
					} else {
						delete(b.live, name)
					}
				}
				r.pass(t)
			},
			reopen:  r.reopen,
			advance: func(d time.Duration) { r.now = r.now.Add(d) },
		}
	})
}

// reportPath is the adapter for a path whose findings are reported
// (Report) and closed by close.
func reportPath(t *testing.T, details [2]Finding, close func(r *reportRig, id string, f Finding) error) flapPath {
	r := newReportRig(t, nil)
	var on [2]bool
	var ids [2]string
	return flapPath{
		texts: func() ([]string, []bool) { return r.texts, r.urgent },
		set: func(t *testing.T, want [2]bool) {
			for i, f := range details {
				if want[i] && !on[i] {
					ids[i] = r.report(t, f).Finding.ID
				}
			}
			for i, f := range details {
				if on[i] && !want[i] {
					if err := close(r, ids[i], f); err != nil {
						t.Fatal(err)
					}
				}
			}
			on = want
		},
		reopen:  r.reopen,
		advance: func(d time.Duration) { r.now = r.now.Add(d) },
	}
}

// Resolve: two crash inputs in one fuzz target.
func TestFlapThroughResolve(t *testing.T) {
	a, b := fuzzFinding(), fuzzFinding()
	b.Detail = "crash input sha256:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	runFlap(t, func(t *testing.T) flapPath {
		return reportPath(t, [2]Finding{a, b}, func(r *reportRig, id string, f Finding) error {
			return r.g.Resolve(id, Replay{Evidence: f.Detail, Passed: true, Binary: binB})
		})
	})
}

// CloseTarget: an overrun and a stall of one target, both hangs.
func TestFlapThroughCloseTarget(t *testing.T) {
	runFlap(t, func(t *testing.T) flapPath {
		return reportPath(t, [2]Finding{hangFinding(FuzzOverrunDetail), hangFinding(FuzzStallDetail)}, func(r *reportRig, id string, _ Finding) error {
			return r.g.CloseTarget(id, goodStep())
		})
	})
}

// flapProbe finds the details its on says, and checks both.
type flapProbe struct {
	mu      sync.Mutex
	details [2]Finding
	on      [2]bool
}

func (p *flapProbe) Check() Check         { return p.details[0].Check }
func (p *flapProbe) Every() time.Duration { return time.Hour }
func (p *flapProbe) Run(context.Context) (ProbeResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	res := ProbeResult{Checked: []string{checkedKey(p.details[0]), checkedKey(p.details[1])}}
	for i, f := range p.details {
		if p.on[i] {
			res.Found = append(res.Found, f)
		}
	}
	return res, nil
}

// runProbe: two corpus items of one filter.
func TestFlapThroughRunProbe(t *testing.T) {
	a, b := hostile(CheckCorpus), hostile(CheckCorpus)
	b.Subject = "other/item"
	runFlap(t, func(t *testing.T) flapPath {
		p := &flapProbe{details: [2]Finding{a, b}}
		r := newReportRig(t, nil)
		r.probes = []Probe{p}
		r.reopen(t)
		return flapPath{
			texts: func() ([]string, []bool) { return r.texts, r.urgent },
			set: func(t *testing.T, on [2]bool) {
				p.mu.Lock()
				p.on = on
				p.mu.Unlock()
				runProbeJob(t, r.g)
			},
			reopen:  r.reopen,
			advance: func(d time.Duration) { r.now = r.now.Add(d) },
		}
	})
}

// Security round-2 delta 1 on #644: a crash and an oversize input of one
// target say different "Cleared" lines, so they never share a key. The
// crash's line is said when it resolves, not held by the oversize, and
// only a crash the owner heard cleared is texted "It is back".
func TestACrashLineIsNotHeldByAnOversizeOfItsTarget(t *testing.T) {
	r := newReportRig(t, nil)
	crash := fuzzFinding()
	over := Finding{Check: CheckFuzz, Subject: crash.Subject, Severity: High, Detail: FuzzOversizeDetail}
	cid := r.report(t, crash).Finding.ID
	oid := r.report(t, over).Finding.ID
	before := len(r.texts)
	r.now = r.now.Add(time.Hour)
	must(t, r.g.Resolve(cid, Replay{Evidence: crash.Detail, Passed: true, Binary: binB}))
	if got := r.texts[before:]; len(got) != 1 || !strings.Contains(got[0], "Cleared: the crash in the check that reads agent requests.") {
		t.Fatalf("crash resolved while an oversize is open: texts %q", got)
	}
	r.reopen(t)
	r.now = r.now.Add(time.Hour)
	must(t, r.g.Resolve(oid, Replay{Evidence: over.Detail, Passed: true, Binary: binB}))
	if got := r.texts[before+1:]; len(got) != 1 || !strings.Contains(got[0], "is tested again") || strings.Contains(got[0], "crash") {
		t.Fatalf("oversize resolved: texts %q", got)
	}
	r.now = r.now.Add(time.Hour)
	if back := r.report(t, crash); !back.Back {
		t.Fatalf("a crash whose Cleared was said came back: %+v", back)
	}
}

// Every distinct owed line is said when its key is released, so a held
// paused finding's "stays paused" line is not dropped for an unpaused
// one's (Security 3 on #644, owed half), and an owed record is kept once
// however often it closes while held (Security round-2 delta 2).
func TestOwedLinesAreSaidOnceEach(t *testing.T) {
	r := newReportRig(t, nil)
	a := withContain(fuzzFinding())
	b := fuzzFinding()
	b.Detail = "crash input sha256:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	ra := r.report(t, a)
	idb := r.report(t, b).Finding.ID
	k := clearedKey(ra)
	before := len(r.texts)
	must(t, r.g.Resolve(ra.Finding.ID, Replay{Evidence: a.Detail, Passed: true, Binary: binB}))
	r.now = r.now.Add(25 * time.Hour)
	ra = r.report(t, a)
	must(t, r.g.Resolve(ra.Finding.ID, Replay{Evidence: a.Detail, Passed: true, Binary: binB}))
	if n := len(r.g.st.Owed[k]); n != 1 {
		t.Fatalf("owed %d records for one finding closed twice while held", n)
	}
	must(t, r.g.Resolve(idb, Replay{Evidence: b.Detail, Passed: true, Binary: binB}))
	got := clearedTexts(r.texts, before)
	if len(got) != 1 || strings.Count(got[0], "Cleared:") != 2 ||
		!strings.Contains(got[0], "Nothing more is needed from you.") || !strings.Contains(got[0], "Pre-allowance G7 stays paused") {
		t.Fatalf("texts %q, want the unpaused and the paused line once each", got)
	}
	if len(r.g.st.Owed) != 0 {
		t.Fatalf("owed left: %v", r.g.st.Owed)
	}
}
