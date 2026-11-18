package browser

// REQ: CLK-3, KRN-8

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// These tests pin rules whose deletion no other test noticed
// (BROWSER-mutants-kill, #6085): each names the rule it holds.

// A URL with no query keeps its bytes, even when its path holds a pair that
// names a token parameter: untoken blanks values only in a query (CLK-3).
func TestUntokenLeavesAURLWithoutAQueryAlone(t *testing.T) {
	g := &Gate{tokens: map[string]bool{"csrf": true}}
	for _, u := range []string{"https://shop.example.test/a&csrf=synthT1", "https://shop.example.test/a&csrf=synthT1#top"} {
		if got := g.untoken(u); got != u {
			t.Errorf("untoken %s = %s", u, got)
		}
	}
}

// A URL that does not parse may change state (fail closed), and a page URL
// that does not parse makes any http(s) link one that leaves it.
func TestUnparsableURLsFailClosed(t *testing.T) {
	const bad = "https://shop.example.test/%zz"
	if !(stateLinks{}).match(bad) {
		t.Error("an unparsable URL did not match as a state link")
	}
	if !leaves("https://shop.example.test/a", bad) {
		t.Error("a link from an unparsable page does not leave it")
	}
	if w := urlWords(bad); w != nil {
		t.Errorf("urlWords of an unparsable URL: %q", w)
	}
	if (&Gate{}).mayAct([]byte("not a request")) {
		t.Error("a line that does not parse may act")
	}
}

// A required argument that is missing is named as missing, not as one of
// the wrong type.
func TestParseNamesAMissingArgument(t *testing.T) {
	_, err := Parse([]byte(`{"v":0,"verb":"navigate"}`))
	if err == nil || !strings.Contains(err.Error(), "navigate needs url") {
		t.Fatalf("got %v", err)
	}
}

// say keeps only text the agent put on a page, at most maxTyped of it;
// past that it marks the gate lost and keeps nothing more (G10).
func TestSayIgnoresEmptyTextAndStopsAtItsBound(t *testing.T) {
	g := &Gate{}
	g.say(make([]string, maxTyped+1)...)
	if len(g.said) != 0 || g.lost {
		t.Fatalf("empty text kept: %d, lost %v", len(g.said), g.lost)
	}
	for i := 0; i < maxTyped; i++ {
		g.say("synthSaid")
	}
	if g.lost {
		t.Fatal("lost before the bound")
	}
	g.say("synthOne", "synthTwo")
	if !g.lost || len(g.said) != maxTyped {
		t.Fatalf("past the bound: %d kept, lost %v", len(g.said), g.lost)
	}
}

// remember keeps at most maxTyped refs: a new ref past that marks the gate
// lost and is not kept, while a ref already kept is still updated (G10).
func TestRememberStopsAtItsBound(t *testing.T) {
	g := &Gate{}
	for i := 0; i < maxTyped; i++ {
		g.remember(Request{Ref: "e" + strings.Repeat("1", i+1), Text: "synthTyped"}, "https://shop.example.test/")
	}
	if g.lost {
		t.Fatal("lost before the bound")
	}
	g.remember(Request{Ref: "e1", Text: "synthNew"}, "https://shop.example.test/")
	if g.lost || g.typed["e1"].text != "synthNew" {
		t.Fatalf("a kept ref: lost %v, %+v", g.lost, g.typed["e1"])
	}
	g.remember(Request{Ref: "e2", Text: "synthNew"}, "https://shop.example.test/")
	if _, ok := g.typed["e2"]; ok || !g.lost || len(g.typed) != maxTyped {
		t.Fatalf("a new ref past the bound: kept %v, lost %v, %d refs", ok, g.lost, len(g.typed))
	}
}

// scanFile withholds an output file it cannot read whole and as one
// singly linked regular file, says why, and reports the bytes it read.
func TestScanFileWithholdsWhatItCannotRead(t *testing.T) {
	ws := t.TempDir()
	g := &Gate{ws: ws}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(ws, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("big.bin", "synth")
	if r := g.scanFile(Result{OK: true, Path: "big.bin", Bytes: MaxDownloadScan + 1}, "downloaded file"); r.Detail != "downloaded file too large to scan" {
		t.Errorf("too large: %+v", r)
	}
	write("linked.bin", "synth")
	if err := os.Link(filepath.Join(ws, "linked.bin"), filepath.Join(ws, "other.bin")); err != nil {
		t.Fatal(err)
	}
	if r := g.scanFile(Result{OK: true, Path: "linked.bin", Bytes: 5}, "downloaded file"); r.OK || r.Detail != "downloaded file unreadable" {
		t.Errorf("a hard link: %+v", r)
	}
	write("ok.bin", "synth")
	r := g.scanFile(Result{OK: true, Path: "ok.bin", Bytes: 99}, "downloaded file")
	if !r.OK || r.Bytes != 5 {
		t.Errorf("a plain file: %+v", r)
	}
	// The descriptor it read through is closed.
	p := filepath.Join(ws, "ok.bin")
	fds, _ := os.ReadDir("/proc/self/fd")
	for _, fd := range fds {
		if l, _ := os.Readlink(filepath.Join("/proc/self/fd", fd.Name())); l == p {
			t.Errorf("fd %s still open on %s", fd.Name(), p)
		}
	}
	// A regular file whose read fails: /proc/self/mem at offset 0.
	if r := (&Gate{ws: "/proc/self"}).scanFile(Result{OK: true, Path: "mem"}, "downloaded file"); r.OK || r.Detail != "downloaded file unreadable" {
		t.Errorf("a failed read: %+v", r)
	}
	if r := g.scanFile(Result{OK: true}, "downloaded file"); r.Detail != "downloaded file missing" {
		t.Errorf("no path: %+v", r)
	}
}

// checkPath refuses a hidden name or one with a slash even when the file
// it names exists in the workspace.
func TestCheckPathRefusesExistingNonFlatNames(t *testing.T) {
	ws := t.TempDir()
	g := &Gate{ws: ws}
	if err := os.Mkdir(filepath.Join(ws, "a"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{".hidden", "a/b"} {
		if err := os.WriteFile(filepath.Join(ws, n), []byte("synth"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := g.checkPath(n); err == nil {
			t.Errorf("%s accepted", n)
		}
	}
}

// post names an invalid output file as a driver error, counts the bytes it
// found rather than the driver's, counts redactions in refused navigations,
// and never cuts a snapshot inside a character.
func TestPostChecksWhatTheDriverReports(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	const page = "https://shop.example.test/"
	if r, _ := h.g.post("download", Result{OK: true, URL: page, Path: "missing.bin"}); r.Error != "driver" || r.Detail != "executor named an invalid output file" {
		t.Errorf("an invalid file: %+v", r)
	}
	if err := os.WriteFile(filepath.Join(h.ws, "out.bin"), []byte("synth"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r, _ := h.g.post("download", Result{OK: true, URL: page, Path: "out.bin", Bytes: MaxDownloadScan + 1}); r.Bytes != 5 {
		t.Errorf("bytes: %+v", r)
	}
	r, _ := h.g.post("snapshot", Result{OK: true, URL: page, RefusedNavigations: []string{"https://elsewhere.example.test/?s=vaultCanarySessionV4lt"}})
	if r.Redactions != 1 || strings.Contains(r.RefusedNavigations[0], "vaultCanary") {
		t.Errorf("refused navigations: %+v", r)
	}
	r, _ = h.g.post("snapshot", Result{OK: true, URL: page, Snapshot: strings.Repeat("é", MaxSnapshot)})
	if !r.Truncated || !utf8.ValidString(r.Snapshot) {
		t.Errorf("cut inside a character: truncated %v", r.Truncated)
	}
}

// A submit or a re-ask the gate refuses says why, not that it needs no
// approval; one that needs none says so.
func TestSubmitAndReaskSayWhyTheyRefuse(t *testing.T) {
	h := newHarness(t, nil, "", 0)
	if r := h.g.reask([]byte("not a request")); r.Error != "protocol" {
		t.Errorf("reask of a bad line: %+v", r)
	}
	if r := h.g.reask([]byte(`{"v":0,"verb":"snapshot"}`)); r.Error != "not_a_submit" {
		t.Errorf("reask of a read: %+v", r)
	}
	if r, written, _ := h.g.submit(context.Background(), []byte("not a request"), "", "", false, nil); written || r.Error != "protocol" {
		t.Errorf("submit of a bad line: %+v", r)
	}
}

// A screenshot whose first look at the page times out reports the timeout;
// one whose bytes are withheld asks nothing more of the driver; one whose
// second look times out reports that; and one whose page shows an untyped
// field value only by then is withheld for that reason (CRED-4, CRED-10).
func TestScreenshotSaysWhyItStopped(t *testing.T) {
	const page = "https://shop.example.test/"
	clean := map[string]any{"ok": true, "url": page, "snapshot": "a kettle"}
	shot := map[string]any{"ok": true, "url": page, "path": "out.bin"}
	h := newHarness(t, map[string]any{"snapshot": "hang", "screenshot": shot}, "png", 300*time.Millisecond)
	if r := h.do(t, `{"v":0,"verb":"screenshot"}`); r.Error != "timeout" {
		t.Errorf("first look hung: %+v", r)
	}
	h = newHarness(t, map[string]any{"snapshot": clean, "screenshot": shot}, "PNG vaultCanarySessionV4lt", 0)
	if r := h.do(t, `{"v":0,"verb":"screenshot"}`); r.Error != "withheld" {
		t.Errorf("secret bytes: %+v", r)
	}
	if got := h.received(t); len(got) != 2 {
		t.Errorf("want snapshot, screenshot; driver received %v", got)
	}
	h = newHarness(t, map[string]any{"snapshot": []any{clean, "hang"}, "screenshot": shot}, "png", 300*time.Millisecond)
	if r := h.do(t, `{"v":0,"verb":"screenshot"}`); r.Error != "timeout" {
		t.Errorf("second look hung: %+v", r)
	}
	field := map[string]any{"ok": true, "url": page, "snapshot": `- textbox "Code" [ref=e5]: synthValue`}
	h = newHarness(t, map[string]any{"snapshot": []any{clean, field}, "screenshot": shot}, "png", 0)
	if r := h.do(t, `{"v":0,"verb":"screenshot"}`); r.Detail != "page showed a field value you did not type during the screenshot (CRED-4)" {
		t.Errorf("a field value by the second look: %+v", r)
	}
}

// A cancelled request stops the executor at once, whether the driver has
// not read the request or has not answered it (K8).
func TestACancelledRequestStopsTheExecutor(t *testing.T) {
	for _, c := range []struct{ name, driver string }{{"unread", "exec sleep 3600"}, {"unanswered", "cat >/dev/null"}} {
		t.Run(c.name, func(t *testing.T) {
			g, err := Start(context.Background(), Config{
				Driver: []string{"/bin/sh", "-c", c.driver}, Origins: []string{"https://shop.example.test"},
				Workspace: t.TempDir(), Timeout: 5 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { g.Close() })
			if c.name == "unread" {
				// Fill the request pipe so the request's write blocks.
				filled := make(chan struct{})
				go func() { _, _ = g.stdin.Write(make([]byte, 64<<10)); close(filled) }()
				select {
				case <-filled:
				case <-time.After(2 * time.Second): // a smaller pipe is full already
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			r, _, _ := g.do(ctx, []byte(`{"v":0,"verb":"snapshot"}`), nil)
			if r.Detail != "request cancelled; executor stopped" || !g.stopped {
				t.Fatalf("%+v", r)
			}
		})
	}
}

// omitUnparsed keeps the role of a line it cannot parse; an empty text
// child of an omitted field stays empty; a placeholder is no value; an
// entry line that cannot be parsed gives its refs and nothing else.
func TestOmitKeepsStructureItCanRead(t *testing.T) {
	if got := OmitValues(`- textbox "x [ref=e5]: hunter2Canary`, map[string]bool{"e5": true}); got != `- textbox [ref=e5]: `+omittedMark {
		t.Errorf("unparsed line: %q", got)
	}
	in := "- textbox \"P\" [ref=e1]: hunter2Canary\n  - text:"
	if got := OmitValues(in, map[string]bool{"e1": true}); got != "- textbox \"P\" [ref=e1]: "+omittedMark+"\n  - text:" {
		t.Errorf("empty child: %q", got)
	}
	refs, stale := entryRefs("- textbox \"Q\" [ref=e5]:\n  - /placeholder: Search", map[string]string{"e5": "synthTyped"})
	if len(refs) != 0 || !stale["e5"] {
		t.Errorf("placeholder: refs %v, stale %v", refs, stale)
	}
	refs, stale = entryRefs("- textbox \"x [ref=e5]: synthValue\n  - text: synthChild", map[string]string{"e5": "synthValue"})
	if len(refs) != 1 || !refs["e5"] || len(stale) != 0 {
		t.Errorf("unparsed entry: refs %v, stale %v", refs, stale)
	}
	lines := []string{`- textbox "A" [ref=e1]: synthA`, `- textbox "B" [ref=e2]: synthB`, `- textbox "C": synthC`}
	if own := keptValues(lines, map[string]bool{"e2": true}); len(own) != 1 || own[1] == 0 {
		t.Errorf("kept values: %v", own)
	}
}

// A typed field that now shows nothing is forgotten before omission, so a
// node under it is checked for the agent's text like any other line.
func TestAStaleTypedFieldKeepsNothing(t *testing.T) {
	const url = "https://shop.example.test/"
	g := &Gate{typed: map[string]typedField{"e5": {text: "synthTypedNote", url: url}}, said: []string{"synthTypedNote"}}
	snap := "- textbox \"Pw\" [ref=e1]: hunter2Canary\n- textbox \"Note\" [ref=e5]:\n  - paragraph: synthTypedNote"
	if out, _ := g.omit(snap, url); out != withheldMark {
		t.Fatalf("got %q", out)
	}
}

// A post the task did not approve is recorded as refused unsent, so Probe
// answers notdone rather than unknown (KRN-8).
func TestUnapprovedPostProbesNotdone(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	s := post("https://shop.example.test/products/kettle", `{"v":0,"verb":"navigate","url":"https://shop.example.test/products/kettle"}`)
	r.run(t, 1, "p", r.root, s)
	if err := r.k.Tick(3 * hour); err != nil {
		t.Fatal(err)
	}
	if st := r.step("p"); st.Detail != "unapproved" {
		t.Fatalf("phase %s (%s)", st.Phase, st.Detail)
	}
	if p := r.c.Probe(kernel.Request{Plan: plan("p", r.root, s)}, r.k.State()).Outcome; p != "notdone" {
		t.Fatalf("probe %s", p)
	}
}

// An omitted field's ancestor is scrubbed of each distinct form once,
// longest first, and equal lengths in the order each field's own forms
// sort, also on a line that holds two fields. Overlapping forms of one
// length leave different text in another order, so the output is pinned
// and a change to that order is a reviewed one.
func TestAncestorScrubsInAFixedOrder(t *testing.T) {
	snap := "- group \"G bbababbbaaba\":\n  - textbox \"P\" [ref=e1]: hunter2Canary"
	said := strings.Split("ccb,bc,ac,acb,ac,cca,ba,bba,bac,aca,aab", ",")
	want := "- group \"G " + omittedMark + omittedMark + "b" + omittedMark + "a" + omittedMark + "\":\n  - textbox \"P\" [ref=e1]: " + omittedMark
	if got := omitValues(snap, map[string]bool{"e1": true}, map[string]bool{}, said); got != want {
		t.Fatalf("one field: got %q", got)
	}
	snap = "- group \"G bacaabacacab\":\n  - textbox \"P\" [ref=e1]: hunter2Canary\n  - textbox \"Q\" [ref=e2]: bb"
	said = strings.Split("bb,bac,aba,bb,ba,cbb,ab,ca,aa,baa", ",")
	want = "- group \"G " + omittedMark + "a" + omittedMark + omittedMark + omittedMark + "b\":\n  - textbox \"P\" [ref=e1]: " + omittedMark + "\n  - textbox \"Q\" [ref=e2]: " + omittedMark
	if got := omitValues(snap, map[string]bool{"e1": true, "e2": true}, map[string]bool{}, said); got != want {
		t.Fatalf("two fields: got %q", got)
	}
}

// A read's content claims nothing, whatever other arguments its step
// carries: the clerk's own facts give a read no print (KEY-2).
func TestAReadClaimsNoPrint(t *testing.T) {
	r := newClerkRig(t, newHarness(t, nil, "", 0))
	r.h.g.refs["e9"] = link{role: "button", name: "Buy"}
	s := read(`{"v":0,"verb":"snapshot"}`)
	s.Args["msg"] = `{"v":0,"verb":"click","ref":"e9"}`
	r.c.Clock = func() int64 { return 3 * hour }
	res := r.c.Do(kernel.Request{Plan: plan("r", r.root, s)}, r.k.State())
	// The step is refused later (it was never dispatched), never for its claims.
	if res.Detail == check.RClaim {
		t.Fatalf("%+v", res)
	}
}
