package inbox

// REQ: VRB-2, CLK-2

// #6416's tests: mail the wording net cannot read is an alert, so it is never
// trashed or unsubscribed unread (ASSUMPTIONS.md MUT-pin-inbox-badct), and a
// full read keeps a logged mail once. Their own file, named to sort last,
// keeps go test's run order before it unchanged, which mutgate reads (#6385).

import (
	"encoding/base64"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// alertWords is a real alert's text: the wording net marks it.
const alertWords = "Your verification code is 482913"

// b64Mail is a two-part mail whose second part is text/plain in base64
// carrying text; ct is the top Content-Type.
func b64Mail(ct, text string) string {
	return "From: alerts@bank.test\r\nSubject: Hello\r\nContent-Type: " + ct + "\r\n\r\n" +
		"--XX\r\nContent-Type: text/plain\r\n\r\nSee below.\r\n" +
		"--XX\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString([]byte(text)) + "\r\n--XX--\r\n"
}

const goodCT = "multipart/mixed; boundary=XX"

// brokenCTs are top Content-Types the net cannot read. A func, not an
// initialized package var, so only the tests calling it reach it (mutgate).
func brokenCTs() []string {
	return []string{
		"multipart/mixed; boundary=XX; =broken",
		"multipart/mixed; boundary=XX; b@d=1",
		`multipart/mixed; boundary="XX`,
		";;;",
	}
}

// The acceptance test: spam that is a real alert in a base64 text part under
// a broken Content-Type is refused as an alert, as it is under a good one;
// the same spam with no alert under a good one is trashed, and under a broken
// one it is refused too, since the net cannot tell.
func TestUnreadableMailIsNeverTrashed(t *testing.T) {
	cases := []struct {
		id, ct, text string
		trashed      bool
	}{
		{"good-plain", goodCT, "Spring sale on garden chairs", true},
		{"good-alert", goodCT, alertWords, false},
	}
	for i, ct := range brokenCTs() {
		cases = append(cases,
			struct {
				id, ct, text string
				trashed      bool
			}{"broken-alert-" + string(rune('a'+i)), ct, alertWords, false},
			struct {
				id, ct, text string
				trashed      bool
			}{"broken-plain-" + string(rune('a'+i)), ct, "Spring sale on garden chairs", false})
	}
	for _, c := range cases {
		w := World{AuthServ: authServ, AlertSenders: []string{"kept.test"}}
		r := newRigOn(t, w, []Mail{{ID: "S", Raw: []byte(b64Mail(c.ct, c.text)), Class: "spam"}}, Synthetic{}, 30)
		r.run(t, r.step("t", key.Trash, map[string]string{"target": "S"}))
		if got := len(r.acct.Effects()) == 1; got != c.trashed {
			t.Errorf("%s: trashed %v, want %v (refusals %v)", c.id, got, c.trashed, r.acct.Refusals())
		} else if !got && r.lastRefusal(t).Reason != "alert" {
			t.Errorf("%s: refused %q, want alert", c.id, r.lastRefusal(t).Reason)
		}
	}
}

// mailText reports each way the net cannot read a mail, and reads the rest.
func TestMailTextReportsWhatItCannotRead(t *testing.T) {
	part := func(ct, cte, body string) string {
		h := "--XX\r\n"
		if ct != "" {
			h += "Content-Type: " + ct + "\r\n"
		}
		if cte != "" {
			h += "Content-Transfer-Encoding: " + cte + "\r\n"
		}
		return h + "\r\n" + body + "\r\n"
	}
	top := "Subject: S\r\nContent-Type: " + goodCT + "\r\n\r\n"
	end := "--XX--\r\n"
	for _, c := range []struct {
		name, raw, want string
		ok              bool
	}{
		{"no header block", "not a header line\r\n\r\nbody", "", false},
		{"no Content-Type", "Subject: Hi\r\n\r\nthere", "Hi\nthere", true},
		{"broken top Content-Type", "Subject: S\r\nContent-Type: ;;;\r\n\r\nbroken", "", false},
		{"broken part Content-Type", top + part("text/plain; =x", "", "a") + end, "", false},
		{"part with no Content-Type", top + part("", "", "a") + end, "S\na", true},
		{"identity encodings", top + part("text/plain", "7bit", "a") + part("text/plain", " 8BIT ", "b") + part("text/plain", "binary", "c") + end, "S\na\nb\nc", true},
		{"quoted-printable", top + part("text/plain", "quoted-printable", "sign=\r\nin") + end, "S\nsignin", true},
		{"unknown encoding", top + part("text/plain", "x-uuencode", "a") + end, "", false},
		{"unknown encoding on a part not read", top + part("image/png", "x-uuencode", "a") + end, "S", true},
		{"base64 across lines", top + part("text/plain", "base64", "c2lnbiBp\r\nbiBub3c=") + end, "S\nsign in now", true},
		{"base64 that does not decode", top + part("text/plain", "base64", "!!!!") + end, "", false},
		{"no closing boundary", top + part("text/plain", "", "a"), "", false},
		{"no boundary parameter", "Subject: S\r\nContent-Type: multipart/mixed\r\n\r\n" + part("text/plain", "", "a") + end, "", false},
		{"wrong boundary", "Subject: S\r\nContent-Type: multipart/mixed; boundary=YY\r\n\r\n" + part("text/plain", "", "a") + end, "", false},
		{"broken nested part", top + "--XX\r\nContent-Type: multipart/alternative; boundary=ZZ\r\n\r\n--ZZ\r\nContent-Type: text/plain; =x\r\n\r\na\r\n--ZZ--\r\n" + end, "", false},
	} {
		got, ok := mailText([]byte(c.raw))
		if ok != c.ok || ok && got != c.want {
			t.Errorf("%s: mailText = %q, %v; want %q, %v", c.name, got, ok, c.want, c.ok)
		}
		if w := (World{}); isAlert([]byte(c.raw), w) != (!c.ok || wordingAlert(got)) {
			t.Errorf("%s: isAlert does not follow what the net read", c.name)
		}
	}
}

// A full read that meets a read mail it already logged keeps it once: the
// second keep charges nothing, leaves its entry as the first logged it and
// queues no second eviction slot. Driven on the state directly, since only
// map order in a fill decides whether a read reaches this (mutgate, #6429).
func TestAFullReadKeepsALoggedMailOnce(t *testing.T) {
	o, err := newOpened("2026-10-19", SeenLog{})
	if err != nil {
		t.Fatal(err)
	}
	o.full = true
	id := [16]byte{7}
	o.keep(id, "a@x.test", 1)
	kept, e := o.kept, o.log[id]
	o.keep(id, "a@x.test", 2)
	if o.kept != kept || o.log[id] != e || len(o.fresh) != 1 {
		t.Fatalf("second keep: charged %d, entry %+v (was %+v), fresh %d; want nothing new", o.kept-kept, o.log[id], e, len(o.fresh))
	}
}
