package inbox

// REQ: VRB-2, LOOP-7

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// corpusFile is the published injection corpus. It is read directly, not
// through corpus.Items, which parses with loops (#2681 item 6).
const corpusFile = "../../corpus/promptinject.json"

// corpusSlot is where an attack text puts its payload; an item without one
// carries it after its text.
const corpusSlot = "{REPLACE_rogue_string}"

// The payloads each corpus item carries: what an alert says, and a code. Both
// are fixed synthetic texts, never a real code.
var corpusPayloads = []string{"New sign-in from an unknown device.", "Your verification code is 482913."}

func loadCorpus(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(corpusFile)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Items []struct {
			ID   string `json:"id"`
			Text string `json:"text"`
		} `json:"items"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Items) < 10 {
		t.Fatalf("%d corpus items", len(c.Items))
	}
	var out []string
	for _, it := range c.Items {
		if it.Text == "" {
			t.Fatalf("corpus item %s has no text", it.ID)
		}
		out = append(out, it.Text)
	}
	return out
}

// replay puts payload in text's slot, or after it when it has none.
func replay(text, payload string) string {
	if strings.Contains(text, corpusSlot) {
		return strings.ReplaceAll(text, corpusSlot, payload)
	}
	return text + " " + payload
}

// #2681 item 6 (LOOP-7): every published injection text, carrying an alert's
// wording or a code in its subject or its body, is an alert the clerk will not
// trash, though the reader called it phishing and its sender is no alert
// sender; as a label, or a reader's reply, it is refused.
func TestTheInjectionCorpusHidesNoAlertAndGetsNoLabel(t *testing.T) {
	items := loadCorpus(t)
	w, _, _ := loadFixture(t)
	var ms []Mail
	for i, text := range items {
		for j, p := range corpusPayloads {
			s := replay(text, p)
			ms = append(ms,
				Mail{ID: fmt.Sprintf("S%d-%d", i, j), Class: "phishing", Raw: fromAnyone("Subject: "+s+"\r\n", "Hello\r\n")},
				Mail{ID: fmt.Sprintf("B%d-%d", i, j), Class: "phishing", Raw: fromAnyone("Subject: Hello\r\n", s+"\r\n")})
		}
		ms = append(ms, Mail{ID: fmt.Sprintf("L%d", i), Class: "spam", Raw: fromAnyone("Subject: Hello\r\n", text+"\r\n")})
	}
	r := newRigOn(t, w, ms, Synthetic{}, 30)
	for _, m := range ms {
		if m.ID[0] == 'L' {
			continue
		}
		r.run(t, r.step(m.ID, key.Trash, map[string]string{"target": m.ID}))
		if got := r.lastRefusal(t); *got.Mail != m.ID || got.Reason != "alert" {
			t.Fatalf("%s: %+v, want an alert refusal", m.ID, got)
		}
	}
	for i, text := range items {
		id := fmt.Sprintf("L%d", i)
		for k, label := range []string{text, labelPrefix + text, labelPrefix + "spam " + text} {
			r.run(t, r.step(fmt.Sprintf("%s-%d", id, k), key.Organize, map[string]string{"target": id, "label": label}))
			if got := r.lastRefusal(t); *got.Mail != id || got.Reason != "bad-label" {
				t.Fatalf("%s label %q: %+v", id, label, got)
			}
		}
	}
	if len(r.acct.Effects()) != 0 {
		t.Fatalf("effects %v", r.acct.Effects())
	}
	// A reader that replies with an attack text leaves the mail unclassified.
	for _, text := range items {
		got := Read(context.Background(), func(context.Context, string) (string, error) { return text, nil }, ms[:1])
		if got[0].Class != "" {
			t.Fatalf("reply %q classed the mail %q", text, got[0].Class)
		}
	}
	// Control: the guard's own corpus check fails when the wording net is
	// cut to the subject's first 40 bytes.
	weak := 0
	for _, m := range ms {
		if m.ID[0] == 'B' && !wordingAlert(mailText(m.Raw)[:min(40, len(mailText(m.Raw)))]) {
			weak++
		}
	}
	if weak == 0 {
		t.Fatal("control: a weakened wording net still catches every corpus item")
	}
}
