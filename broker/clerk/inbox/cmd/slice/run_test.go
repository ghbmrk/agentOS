package main

// REQ: EVL-2, VRB-2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/inbox"
)

const evalDir = "../../../../../evals/slice-inbox"

type fixtureMail struct {
	ID    string `json:"id"`
	File  string `json:"file"`
	Class string `json:"class"`
}

// loadFixture reads the eval set's world, key records and mail (read only).
func loadFixture(t testing.TB) (inbox.World, []fixtureMail, map[string][]byte) {
	t.Helper()
	var w inbox.World
	var meta struct {
		Mails []fixtureMail `json:"mails"`
	}
	read := func(name string, v any) {
		b, err := os.ReadFile(filepath.Join(evalDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	read("world.json", &w)
	read("world.json", &meta)
	read("keys.json", &w.DKIMKeys)
	raw := map[string][]byte{}
	for _, m := range meta.Mails {
		b, err := os.ReadFile(filepath.Join(evalDir, m.File))
		if err != nil {
			t.Fatal(err)
		}
		raw[m.ID] = b
	}
	return w, meta.Mails, raw
}

func fixtureInput(t *testing.T) Input {
	t.Helper()
	w, mails, raw := loadFixture(t)
	in := Input{World: w, Owner: "owner@home.test", OneClickBody: "List-Unsubscribe=One-Click", RetentionDays: 30,
		Prior: []inbox.Delivery{{From: "team@digest.test", Date: "2026-08-02"}}}
	for _, m := range mails {
		in.Mails = append(in.Mails, inbox.Mail{ID: m.ID, Raw: raw[m.ID], Class: m.Class})
	}
	return in
}

func TestRunReplaysIdentically(t *testing.T) {
	in := fixtureInput(t)
	a, err := Run(in)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Run(in)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) || a.LogDigest == "" {
		t.Fatal("two runs of the same input differ")
	}
}

func TestRunUnsubscribesOnlyEligibleAndHoldsFirst(t *testing.T) {
	out, err := Run(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Requests) != 3 || len(out.Holds) != 3 {
		t.Fatalf("requests %d holds %d, want 3 and 3 (M01 to M03)", len(out.Requests), len(out.Holds))
	}
	for _, h := range out.Holds {
		want := "novelty"
		if h.Mail == "M03" {
			want = "base"
		}
		if h.Window != want {
			t.Errorf("%s hold %s, want %s", h.Mail, h.Window, want)
		}
	}
}

func TestRunKeepsMailTextInsideTheClerk(t *testing.T) {
	out, err := Run(fixtureInput(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(struct {
		O []string
		R []inbox.Post
	}{out.OutsideMailClerk, out.Requests})
	for _, s := range []string{"agentos-canary-slice-inbox", "555 0142"} {
		if strings.Contains(string(b), s) {
			t.Errorf("%q left the clerk", s)
		}
	}
}

// A mailbox past the daily cap: the cap counts organize and trash only, trash is
// spent first, unsubscribes still go out, and the work left over is said once.
func TestRunCapsOrganizeAndTrashNotUnsubscribe(t *testing.T) {
	small := fixtureInput(t)
	base, err := Run(small)
	if err != nil {
		t.Fatal(err)
	}
	big := small
	big.Mails = nil
	trash, total := 0, 0
	for i := 0; i < 40; i++ {
		for _, m := range small.Mails {
			m.ID = m.ID + "-x" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			big.Mails = append(big.Mails, m)
			total++
			if m.Class == "spam" || m.Class == "phishing" {
				trash++
			}
		}
	}
	if total <= 200 || trash == 0 || trash > 200 {
		t.Fatalf("fixture does not exercise the cap: %d mails, %d to trash", total, trash)
	}
	out, err := Run(big)
	if err != nil {
		t.Fatal(err)
	}
	organized, trashed := 0, 0
	for _, e := range out.Effects {
		switch e.Verb {
		case "organize":
			organized++
		case "trash":
			trashed++
		}
	}
	if trashed != trash || organized+trashed != 200 {
		t.Fatalf("effects: %d organized, %d trashed, want %d trashed and 200 in all", organized, trashed, trash)
	}
	if len(out.Requests) != len(base.Requests) || len(out.Holds) != len(base.Holds) {
		t.Fatalf("unsubscribes were cut by the cap: %d requests, %d holds, want %d and %d",
			len(out.Requests), len(out.Holds), len(base.Requests), len(base.Holds))
	}
	var lines []string
	for _, s := range out.StatusLines {
		if s.Cause == "daily-cap" {
			lines = append(lines, s.Text)
		}
	}
	want := "Over today's limit of 200: " + strconv.Itoa(total-organized) + " to label left for tomorrow."
	if len(lines) != 1 || lines[0] != want {
		t.Fatalf("status lines %q, want one %q", lines, want)
	}
}

// REQ: VRB-2 (assumption MIG-3-15)
// More spam than the cap: the cap is spent on trash alone, nothing is labelled,
// and the mails left over are said once, counted as trash.
func TestRunCapsTrashAndSaysWhatIsLeft(t *testing.T) {
	in := fixtureInput(t)
	var spam inbox.Mail
	for _, m := range in.Mails {
		if m.Class == "spam" {
			spam = m
			break
		}
	}
	in.Mails = nil
	for i := 0; i < 250; i++ {
		m := spam
		m.ID = "S" + strconv.Itoa(i)
		in.Mails = append(in.Mails, m)
	}
	out, err := Run(in)
	if err != nil {
		t.Fatal(err)
	}
	trashed := 0
	for _, e := range out.Effects {
		if e.Verb != "trash" {
			t.Fatalf("effect %+v besides trash", e)
		}
		trashed++
	}
	want := "Over today's limit of 200: 50 to trash and 250 to label left for tomorrow."
	var got []string
	for _, s := range out.StatusLines {
		if s.Cause == "daily-cap" {
			got = append(got, s.Text)
		}
	}
	if trashed != 200 || len(got) != 1 || got[0] != want {
		t.Fatalf("%d trashed, status %q, want 200 and %q", trashed, got, want)
	}
}
