package inbox

// REQ: VRB-2 (assumptions MIG-4-mail-reader-2, -3)

import (
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
	plain := alertRig(t)
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
