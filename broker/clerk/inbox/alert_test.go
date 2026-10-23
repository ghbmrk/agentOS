package inbox

// REQ: VRB-2 (assumptions MIG-4-mail-reader-2, -3)

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const authServ = "mx.example.test"

// withAuth puts the provider's Authentication-Results above a fixture mail,
// where the provider's server writes it.
func withAuth(raw []byte, value string) []byte {
	return append([]byte("Authentication-Results: "+value+"\r\n"), raw...)
}

// alertRig is the fixture mailbox with M01 (bulk, unsubscribable) and M19
// (spam) sent by senders the owner keeps as alert senders, through a DMARC
// pass the provider wrote.
func alertRig(t *testing.T, senders ...string) *rig {
	t.Helper()
	w, mails, raw := loadFixture(t)
	w.AuthServ, w.AlertSenders = authServ, senders
	var ms []Mail
	for _, m := range mails {
		b := raw[m.ID]
		switch m.ID {
		case "M01":
			b = withAuth(b, authServ+"; dmarc=pass header.from=shop.test")
		case "M19":
			b = withAuth(b, authServ+"; dmarc=pass header.from=spamco.test")
		}
		ms = append(ms, Mail{ID: m.ID, Raw: b, Class: m.Class})
	}
	return newRigOn(t, w, ms, Synthetic{}, 30)
}

// #2604: an alert is never trashed or unsubscribed, whatever the reader
// called it; the same mails from senders not kept as alert senders are.
func TestAnAlertIsNeverTrashedOrUnsubscribed(t *testing.T) {
	plain := alertRig(t, "unrelated.test")
	if _, ok := plain.acct.eligible(plain.acct.mails["M01"]); !ok {
		t.Fatal("control: M01 is not unsubscribable without the guard")
	}
	plain.run(t, plain.step("t", key.Trash, map[string]string{"target": "M19"}))
	if len(plain.acct.Effects()) != 1 {
		t.Fatalf("control: M19 not trashed: %v", plain.acct.Refusals())
	}

	r := alertRig(t, "news@shop.test", "@spamco.test")
	for _, it := range r.acct.Listing() {
		if it.Mail == "M01" && it.Sender != "" {
			t.Fatal("the planner got a sender handle for an alert")
		}
	}
	r.run(t, r.step("t", key.Trash, map[string]string{"target": "M19"}))
	if len(r.acct.Effects()) != 0 || r.lastRefusal(t).Reason != "alert" {
		t.Fatalf("effects %v refusals %v", r.acct.Effects(), r.acct.Refusals())
	}
	// A handle obtained before the sender became an alert sender is refused
	// when the step runs: the guard reads the world then.
	h := handleOfMail(t, plain, "M01")
	plain.world.AlertSenders = []string{"shop.test"}
	plain.run(t, plain.onKey(plain.unsub, "u", key.Unsubscribe, map[string]string{"to": h}), t0+dayMS)
	if len(plain.acct.Posts()) != 0 || plain.lastRefusal(t).Reason != "no-longer-eligible" {
		t.Fatalf("posts %v refusals %v", plain.acct.Posts(), plain.acct.Refusals())
	}
}

// The guard trusts only the provider's own, topmost result, aligned with From.
func TestTheAlertGuardTrustsOnlyTheProvidersAlignedPass(t *testing.T) {
	w := World{AuthServ: authServ, AlertSenders: []string{"bank.test"}}
	mail := func(from string, auth ...string) []byte {
		var b []byte
		for _, a := range auth {
			b = append(b, "Authentication-Results: "+a+"\r\n"...)
		}
		return append(b, "From: Bank <"+from+">\r\nSubject: Statement\r\n\r\nbody\r\n"...)
	}
	for _, c := range []struct {
		name  string
		raw   []byte
		alert bool
	}{
		{"aligned pass", mail("notice@bank.test", authServ+"; dmarc=pass header.from=bank.test"), true},
		{"subdomain sender", mail("notice@mail.bank.test", authServ+"; dmarc=pass header.from=mail.bank.test"), true},
		{"authserv case", mail("notice@bank.test", "MX.Example.Test; dmarc=pass header.from=bank.test"), true},
		{"no result", mail("notice@bank.test"), false},
		{"dmarc fail", mail("notice@bank.test", authServ+"; dmarc=fail header.from=bank.test"), false},
		{"unaligned", mail("notice@bank.test", authServ+"; dmarc=pass header.from=other.test"), false},
		{"pass in a comment", mail("notice@bank.test", authServ+"; dmarc=fail (dmarc=pass) header.from=bank.test"), false},
		{"another server", mail("notice@bank.test", "relay.test; dmarc=pass header.from=bank.test"), false},
		{"sender's own below the provider's", mail("notice@bank.test",
			authServ+"; dmarc=fail header.from=bank.test", authServ+"; dmarc=pass header.from=bank.test"), false},
		{"not an alert sender", mail("notice@shop.test", authServ+"; dmarc=pass header.from=shop.test"), false},
		{"lookalike domain", mail("notice@evilbank.test", authServ+"; dmarc=pass header.from=evilbank.test"), false},
	} {
		if got := isAlert(c.raw, w); got != c.alert {
			t.Errorf("%s: alert %v, want %v", c.name, got, c.alert)
		}
	}
	// With no authserv-id configured, no header is the provider's, even one
	// that names no server.
	for _, auth := range []string{authServ + "; dmarc=pass header.from=bank.test", "; dmarc=pass header.from=bank.test", `""; dmarc=pass header.from=bank.test`} {
		if isAlert(mail("notice@bank.test", auth), World{AlertSenders: w.AlertSenders}) {
			t.Errorf("%q: an alert without the provider's authserv-id", auth)
		}
	}
}

// fromAnyone is a mail from a sender the owner does not keep as an alert
// sender, with no Authentication-Results, so only the wording net can call
// it an alert.
func fromAnyone(headers, body string) []byte {
	return []byte("From: Someone <someone@nowhere.test>\r\n" + headers + "\r\n" + body)
}

// #2681 item 1, VRB-2's second net: security-alert wording or a code marks a
// mail an alert whoever sent it, in the subject (encoded words too) or in any
// text part, however the part is encoded.
func TestTheWordingNetMarksAnAlertWhoeverSentIt(t *testing.T) {
	w := World{AuthServ: authServ, AlertSenders: []string{"bank.test"}}
	b64 := base64.StdEncoding.EncodeToString([]byte("We noticed unusual activity on your account."))
	for _, c := range []struct {
		name  string
		raw   []byte
		alert bool
	}{
		{"phrase in the subject", fromAnyone("Subject: New sign-in from an unknown device\r\n", "Hello\r\n"), true},
		{"phrase in any case", fromAnyone("Subject: PASSWORD RESET\r\n", "Hello\r\n"), true},
		{"phrase across a fold", fromAnyone("Subject: Was this\r\n you?\r\n", "Hello\r\n"), true},
		{"encoded-word subject", fromAnyone("Subject: =?UTF-8?B?"+base64.StdEncoding.EncodeToString([]byte("Security alert"))+"?=\r\n", "Hello\r\n"), true},
		{"phrase in the body", fromAnyone("Subject: Hi\r\n", "Your password was changed today.\r\n"), true},
		{"code in the body", fromAnyone("Subject: Hi\r\n", "Your code is 482 913.\r\n"), true},
		{"fullwidth code", fromAnyone("Subject: Hi\r\n", "Your code is ４８２９１３.\r\n"), true},
		{"key-shaped token", fromAnyone("Subject: Hi\r\n", "token ghp_"+strings.Repeat("a1", 18)+"\r\n"), true},
		{"quoted-printable", fromAnyone("Subject: Hi\r\nContent-Transfer-Encoding: quoted-printable\r\n",
			"Someone tried a login =\r\nattempt on your account=2E\r\n"), true},
		{"base64 html part", fromAnyone("Subject: Hi\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=b\r\n",
			"--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n"+
				base64.StdEncoding.EncodeToString([]byte("<p>Unusual&nbsp;<b>activity</b></p>"))+"\r\n--b--\r\n"), true},
		{"second text part", fromAnyone("Subject: Hi\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n",
			"--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n"+b64+"\r\n--b--\r\n"), true},
		{"no wording", fromAnyone("Subject: You have won\r\n", "Claim your prize, order 20261019.\r\n"), false},
		{"an amount is not a code", fromAnyone("Subject: Sale\r\n", "Save 2500 dollars on order 7731.\r\n"), false},
	} {
		if got := isAlert(c.raw, w); got != c.alert {
			t.Errorf("%s: alert %v, want %v", c.name, got, c.alert)
		}
	}
}

// #2681 item 1's failure path: phishing that copies an alert's wording from a
// sender not on the list is not trashed; the clerk refuses, as for any alert.
func TestPhishingInAnAlertsWordingIsNotTrashed(t *testing.T) {
	w, _, raw := loadFixture(t)
	ms := []Mail{{ID: "P1", Class: "phishing", Raw: fromAnyone("Subject: New sign-in to your account\r\n", "Was this you?\r\n")},
		{ID: "M19", Class: "spam", Raw: raw["M19"]}}
	r := newRigOn(t, w, ms, Synthetic{}, 30)
	r.run(t, r.step("p", key.Trash, map[string]string{"target": "P1"}))
	if len(r.acct.Effects()) != 0 || r.lastRefusal(t).Reason != "alert" {
		t.Fatalf("effects %v refusals %v", r.acct.Effects(), r.acct.Refusals())
	}
	r.run(t, r.step("s", key.Trash, map[string]string{"target": "M19"}))
	if len(r.acct.Effects()) != 1 {
		t.Fatalf("control: M19 not trashed: %v", r.acct.Refusals())
	}
}

// #2681 item 2: the guard never switches off silently. With no authserv-id or
// no alert senders the clerk trashes and unsubscribes nothing, with a typed
// reason, and hands the planner no sender to unsubscribe.
func TestAnAccountWithoutAlertInputsRefusesTrash(t *testing.T) {
	for name, strip := range map[string]func(*World){
		"no authserv":      func(w *World) { w.AuthServ = "" },
		"no alert senders": func(w *World) { w.AlertSenders = nil },
		"blank senders":    func(w *World) { w.AlertSenders = []string{"", " "} },
	} {
		r := newRig(t, 30)
		h := handleOfMail(t, r, "M01")
		strip(r.world)
		r.run(t, r.step("t", key.Trash, map[string]string{"target": "M19"}))
		if len(r.acct.Effects()) != 0 || r.lastRefusal(t).Reason != "no-alert-guard" {
			t.Fatalf("%s: effects %v refusals %v", name, r.acct.Effects(), r.acct.Refusals())
		}
		r.run(t, r.onKey(r.unsub, "u", key.Unsubscribe, map[string]string{"to": h}), t0+dayMS)
		if len(r.acct.Posts()) != 0 || r.lastRefusal(t).Reason != "no-alert-guard" {
			t.Fatalf("%s: posts %v refusals %v", name, r.acct.Posts(), r.acct.Refusals())
		}
		w, mails, raw := loadFixture(t)
		strip(&w)
		var ms []Mail
		for _, m := range mails {
			ms = append(ms, Mail{ID: m.ID, Class: m.Class, Raw: raw[m.ID]})
		}
		for _, it := range newRigOn(t, w, ms, Synthetic{}, 30).acct.Listing() {
			if it.Sender != "" {
				t.Fatalf("%s: the planner got a sender handle for %s", name, it.Mail)
			}
		}
	}
}

// #2681 item 3: the guard holds for an alert the reader called phishing, and
// an address entry matches that address only, never by suffix.
func TestTheGuardHoldsForPhishingAndMatchesAddressesExactly(t *testing.T) {
	w, _, _ := loadFixture(t)
	w.AlertSenders = []string{"deals@spamco.test"}
	pass := func(from string) []byte {
		return withAuth([]byte("From: <"+from+">\r\nSubject: Offer\r\n\r\nbody\r\n"), "mx.mailhub.test; dmarc=pass header.from=spamco.test")
	}
	ms := []Mail{
		{ID: "A", Class: "phishing", Raw: pass("deals@spamco.test")},
		{ID: "B", Class: "phishing", Raw: pass("hotdeals@spamco.test")},
		{ID: "C", Class: "phishing", Raw: pass("x.deals@spamco.test")},
		{ID: "D", Class: "phishing", Raw: pass("other@spamco.test")},
	}
	r := newRigOn(t, w, ms, Synthetic{}, 30)
	for _, id := range []string{"A", "B", "C", "D"} {
		r.run(t, r.step(id, key.Trash, map[string]string{"target": id}))
	}
	var trashed []string
	for _, e := range r.acct.Effects() {
		trashed = append(trashed, e.Mail)
	}
	if !slices.Equal(trashed, []string{"B", "C", "D"}) {
		t.Fatalf("trashed %v refusals %v", trashed, r.acct.Refusals())
	}
	if rs := r.acct.Refusals(); len(rs) != 1 || rs[0].Reason != "alert" || *rs[0].Mail != "A" {
		t.Fatalf("refusals %+v", rs)
	}
}

// #2681 item 5: a mail with two From headers, or a provider's result whose
// DMARC results conflict, is never an alert by its sender, so a forged alert
// cannot reach the owner as one from a trusted sender.
func TestTheSenderNetFailsClosedOnAmbiguousMail(t *testing.T) {
	w := World{AuthServ: authServ, AlertSenders: []string{"bank.test"}}
	body := "Subject: Statement\r\n\r\nbody\r\n"
	for _, c := range []struct {
		name string
		raw  string
	}{
		{"two From headers", "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test\r\nFrom: <notice@bank.test>\r\nFrom: <x@evil.test>\r\n" + body},
		{"two addresses in From", "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test\r\nFrom: <notice@bank.test>, <x@evil.test>\r\n" + body},
		{"pass then fail", "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test; dmarc=fail header.from=bank.test\r\nFrom: <notice@bank.test>\r\n" + body},
		{"fail then pass", "Authentication-Results: " + authServ + "; dmarc=fail header.from=bank.test; dmarc=pass header.from=bank.test\r\nFrom: <notice@bank.test>\r\n" + body},
		{"pass for another domain too", "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test; dmarc=pass header.from=evil.test\r\nFrom: <notice@bank.test>\r\n" + body},
	} {
		if isAlert([]byte(c.raw), w) {
			t.Errorf("%s: an alert by its sender", c.name)
		}
	}
	if !isAlert([]byte("Authentication-Results: "+authServ+"; dmarc=pass header.from=bank.test\r\nFrom: <notice@bank.test>\r\n"+body), w) {
		t.Fatal("control: a single aligned pass is not an alert")
	}
}
