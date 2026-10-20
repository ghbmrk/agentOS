package slice

// REQ: EVL-2, VRB-2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/inbox"
)

const evalDir = "../../../../evals/slice-inbox"

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
