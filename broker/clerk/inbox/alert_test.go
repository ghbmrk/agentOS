package inbox

// REQ: VRB-2 (assumptions MIG-4-mail-reader-2, -3)

import (
	"bytes"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const authServ = "mx.example.test"

// withAuth puts the provider's SMTP hop and its Authentication-Results above
// a fixture mail, where the provider's server writes them; the hop names the
// field's authserv-id as its "by" host.
func withAuth(raw []byte, value string) []byte {
	id, _, _ := strings.Cut(value, ";")
	return append([]byte(smtpRecv(strings.TrimSpace(id))+"Authentication-Results: "+value+"\r\n"), raw...)
}

// smtpRecv is the Received field a provider writes when it takes a mail over
// SMTP, in Gmail's shape.
func smtpRecv(by string) string {
	return "Received: from relay.sender.test (relay.sender.test. [192.0.2.1])\r\n        by " + by +
		" with ESMTPS id a1si2;\r\n        Sun, 25 Oct 2026 20:00:00 -0700 (PDT)\r\n"
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
		if len(auth) > 0 {
			b = []byte(smtpRecv(authServ))
		}
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

// #3201: a field naming the provider counts only below the provider's own
// SMTP hop. Mail with no provider field of its own (imported, inserted or
// fetched by POP) carries the sender's forged field and Received, and is left
// to the wording net.
func TestTheSenderNetNeedsTheProvidersSMTPHop(t *testing.T) {
	w := World{AuthServ: authServ, AlertSenders: []string{"bank.test"}}
	forged := smtpRecv(authServ) + "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test\r\n"
	ar := "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test\r\n"
	const date = "; Sun, 25 Oct 2026 20:00:00 -0700\r\n"
	const body = "From: Bank <notice@bank.test>\r\nSubject: Statement\r\n\r\nbody\r\n"
	for _, c := range []struct {
		name, head string
		alert      bool
	}{
		{"forged field, no provider field above", ar, false},
		{"forged field and hop, nothing above", forged, true}, // the residual A22 checks: see TN-alert-guard-forged-ar
		{"fetched by POP", "Received: from pop.other.test [192.0.2.7]\r\n        by " + authServ + " with POP3 id p1\r\n        for <owner@example.test> (single-drop)" + date + forged, false},
		{"fetched by POP, another by host", "Received: from pop.other.test by 2002:a05:6a10::1 with POP3 id p1" + date + forged, false},
		{"added through the API", "Received: from 1029384756 named unknown by gmailapi.google.com with HTTPREST" + date + forged, false},
		{"a hop above with no protocol", "Received: by 2002:a05:6a10::1 id z1" + date + forged, false},
		{"a hop above with two protocols", "Received: by 2002:a05:6a10::1 with SMTP with POP3 id z1" + date + forged, false},
		{"provider's internal SMTP hop above", "Received: by 2002:a05:6a10::1 with SMTP id z1" + date + forged, true},
		{"protocol in any case", "Received: from relay.sender.test by " + authServ + " with esmtps id a1" + date + ar, true},
		{"field above the hop", ar + smtpRecv(authServ), false},
		{"hop only in a comment", "Received: from relay.sender.test (by " + authServ + " with ESMTPS) by relay.test with ESMTP id r1" + date + ar, false},
		{"lookalike by host", smtpRecv(authServ+".evil.test") + ar, false},
		{"protocol only in a comment", "Received: from relay.sender.test by " + authServ + " (with ESMTPS) with POP3 id a1" + date + ar, false},
	} {
		if got := alertSender([]byte(c.head+body), w); got != c.alert {
			t.Errorf("%s: alert by its sender %v, want %v", c.name, got, c.alert)
		}
	}
	// It fails closed to the wording net: the same POP mail with alert wording
	// is still an alert.
	pop := "Received: from pop.other.test by " + authServ + " with POP3 id p1" + date + forged +
		"From: Bank <notice@bank.test>\r\nSubject: New sign-in from an unknown device\r\n\r\nbody\r\n"
	if alertSender([]byte(pop), w) || !isAlert([]byte(pop), w) {
		t.Error("a POP mail with alert wording is not left to the wording net")
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
		{"two From headers", smtpRecv(authServ) + "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test\r\nFrom: <notice@bank.test>\r\nFrom: <x@evil.test>\r\n" + body},
		{"two addresses in From", smtpRecv(authServ) + "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test\r\nFrom: <notice@bank.test>, <x@evil.test>\r\n" + body},
		{"pass then fail", smtpRecv(authServ) + "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test; dmarc=fail header.from=bank.test\r\nFrom: <notice@bank.test>\r\n" + body},
		{"fail then pass", smtpRecv(authServ) + "Authentication-Results: " + authServ + "; dmarc=fail header.from=bank.test; dmarc=pass header.from=bank.test\r\nFrom: <notice@bank.test>\r\n" + body},
		{"pass for another domain too", smtpRecv(authServ) + "Authentication-Results: " + authServ + "; dmarc=pass header.from=bank.test; dmarc=pass header.from=evil.test\r\nFrom: <notice@bank.test>\r\n" + body},
	} {
		if isAlert([]byte(c.raw), w) {
			t.Errorf("%s: an alert by its sender", c.name)
		}
	}
	// A single sender in a well-formed From is an alert however its header is
	// written: folded, or with a name encoded in a charset Go cannot decode.
	for _, from := range []string{
		"<notice@bank.test>",
		"\"Bank of Test Customer Security Team\"\r\n <notice@bank.test>",
		"=?windows-1252?Q?S=E9curit=E9_Banque?= <notice@bank.test>",
		"=?iso-2022-jp?B?GyRCJWEhPCVrGyhC?= <notice@bank.test>",
	} {
		if !isAlert([]byte(smtpRecv(authServ)+"Authentication-Results: "+authServ+"; dmarc=pass header.from=bank.test\r\nFrom: "+from+"\r\n"+body), w) {
			t.Errorf("control: From %q with a single aligned pass is not an alert", from)
		}
	}
}

// An alert counts as a signal only once the clerk verifies its DKIM
// signature itself, aligned with the From domain: the provider's DMARC pass
// alone, a signature for another domain, a broken one or an expired one is
// not enough. The guard is unchanged: none of them is trashed.
func TestAnAlertCountsOnlyWhenItsDKIMVerifies(t *testing.T) {
	const from = "alerts@security.test"
	pass := authServ + "; dmarc=pass header.from=security.test"
	good, keys := signed(t, from, "https://security.test/u", "security.test", "")
	other, otherKeys := signed(t, from, "https://security.test/u", "elsewhere.test", "")
	expired, _ := signed(t, from, "https://security.test/u", "security.test", "; x="+unix(t, "2026-10-01T00:00:00Z"))
	for k, v := range otherKeys {
		keys[k] = v
	}
	w := World{DKIMKeys: keys, Today: "2026-10-19", AuthServ: authServ, AlertSenders: []string{"security.test"}}
	cases := map[string]struct {
		raw  []byte
		want bool
	}{
		"verified":        {withAuth(good, pass), true},
		"no dmarc pass":   {good, false},
		"unsigned":        {withAuth([]byte("From: "+from+"\r\nSubject: New sign-in\r\n\r\nHello.\r\n"), pass), false},
		"other domain":    {withAuth(other, pass), false},
		"changed after":   {withAuth(bytes.Replace(good, []byte("Hello."), []byte("Hello!"), 1), pass), false},
		"expired":         {withAuth(expired, pass), false},
		"not kept sender": {withAuth(good, pass), false},
	}
	for name, c := range cases {
		cw := w
		if name == "not kept sender" {
			cw.AlertSenders = []string{"bank.test"}
		}
		if got := VerifiedAlert(c.raw, cw); got != c.want {
			t.Errorf("%s: VerifiedAlert = %v, want %v", name, got, c.want)
		}
	}
	ms := []Mail{{ID: "a1", Raw: withAuth(good, pass), Class: "spam"}, {ID: "a2", Raw: good, Class: "spam"}}
	r := newRigOn(t, w, ms, Synthetic{}, 30)
	if got := r.acct.Alerts(); len(got) != 1 || got[0] != "a1" {
		t.Fatalf("Alerts = %v, want [a1]", got)
	}
}

// #2888: ordinary promotional wording is not an alert. A phrase counts only on
// word boundaries, so "designing" and "design in" hold no "signin" or "sign in",
// and a year (19xx, 20xx) next to a code word is a date, which CH-19 lets pass.
// A plainly written alert keeps its protection, inflected, run on or beside
// another script: only the start of a phrase is bounded.
func TestPromotionalWordingIsNotAnAlert(t *testing.T) {
	for _, c := range []struct {
		text  string
		alert bool
	}{
		{"We are designing a new spring collection", false},
		{"Our new design in stores now", false},
		{"Season pass 2026 on sale", false},
		{"Key dates for 2026 events", false},
		{"Codes for the 1999 reunion", false},
		{"Use code SAVE20 at checkout", false},
		{"Use code SPRING25 at checkout", false},
		{"Save 25% today with code SAVE2026", false},
		{"Promo code: WELCOME10", false},
		{"Enter code 20OFF", false},
		{"Use code SAVE-20", false},
		{"Your code is 2026", true},
		{"Your code is: 2026", true},
		{"Code: 1999", true},
		{"Your passcode is 2026.", true},
		{"Your code is G-482913", true},
		{"Your code is A1B2C3", true},
		{"Your code is K7XQ", true},
		{"Your code is AB12", true},
		{"Your code is SAVE20 and your sign-in is ready", true},
		{"Sign in to see your offers", true},
		{"Our new design in stores; sign in to shop", true},
		{"New sign-in from Chrome", true},
		{"Someone tried to signin to your account", true},
		{"Was this you?", true},
		{"Your code is 2100", true},
		{"Your code is 1899", true},
		{"Your code is 482913", true},
		{"PIN 2026-77", true},
		{"Multiple failed login attempts on your account", true},
		{"Review recent sign-ins to your account", true},
		{"Someone signed into your account from Windows", true},
		{"We noticed new logins to your account", true},
		{"Your verification codes are below", true},
		{"Security alerts for your account", true},
		{"Unusual signon activity", true},
		{"新しいsign-inがありました", true},
		{"アカウントのsecurity alert", true},
	} {
		if got := wordingAlert(c.text); got != c.alert {
			t.Errorf("%q: alert %v, want %v", c.text, got, c.alert)
		}
	}
}
