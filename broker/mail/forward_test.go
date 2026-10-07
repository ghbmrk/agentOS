package mail

import (
	"strings"
	"testing"
)

// REQ: ADP-13

const fwdAuthServ = "mx.provider.test"

func boxAdapter(box bool) *Adapter {
	return &Adapter{cfg: Config{Box: box, AuthServ: fwdAuthServ}}
}

func forward(from string, auth ...string) Message {
	return Message{From: from, Subject: "Fwd: your order", Text: "---------- Forwarded message ---------", AuthResults: auth}
}

var owners = []string{"Dave.Smith@Owner.example", "dave@work.example"}

// ADP-13 Use: a forward from the owner's address gets a one-line receipt
// only when it passes an aligned DMARC check.
func TestForwardReceiptOnlyWithAlignedDMARC(t *testing.T) {
	a := boxAdapter(true)
	for _, m := range []Message{
		forward("dave.smith@owner.example", fwdAuthServ+"; dmarc=pass header.from=owner.example"),
		forward("Dave <dave@work.example>", fwdAuthServ+"; spf=pass smtp.mailfrom=work.example; dmarc=pass (p=reject) header.from=work.example"),
	} {
		got, ok := a.ForwardReceipt(m, owners)
		if !ok || got != ForwardReceiptText {
			t.Errorf("%q: %q, %v", m.From, got, ok)
		}
	}
}

// A spoofed forward gets none: no or failed DMARC, a result the provider's
// server did not write on top, a pass for another domain, or one inside a
// comment.
func TestSpoofedForwardGetsNoReceipt(t *testing.T) {
	a := boxAdapter(true)
	from := "dave.smith@owner.example"
	for name, m := range map[string]Message{
		"no header":        forward(from),
		"dmarc fail":       forward(from, fwdAuthServ+"; dmarc=fail header.from=owner.example"),
		"dmarc none":       forward(from, fwdAuthServ+"; dmarc=none header.from=owner.example"),
		"other authserv":   forward(from, "mx.attacker.test; dmarc=pass header.from=owner.example"),
		"pass below top":   forward(from, fwdAuthServ+"; dmarc=fail header.from=owner.example", fwdAuthServ+"; dmarc=pass header.from=owner.example"),
		"unaligned":        forward(from, fwdAuthServ+"; dmarc=pass header.from=attacker.example"),
		"pass in comment":  forward(from, fwdAuthServ+"; dmarc=fail (dmarc=pass) header.from=owner.example"),
		"pass in quotes":   forward(from, fwdAuthServ+`; dmarc=fail reason="dmarc=pass" header.from=owner.example`),
		"empty authserv":   {From: from, AuthResults: []string{"; dmarc=pass header.from=owner.example"}},
		"from empty":       forward("", fwdAuthServ+"; dmarc=pass header.from=owner.example"),
		"from not address": forward("owner.example", fwdAuthServ+"; dmarc=pass header.from=owner.example"),
	} {
		if got, ok := a.ForwardReceipt(m, owners); ok || got != "" {
			t.Errorf("%s: %q, %v", name, got, ok)
		}
	}
}

// Only the owner's own addresses, matched exactly: a third party with a
// clean DMARC pass, another address at the owner's domain, or a +tag or
// dot variant of the owner's address gets none.
func TestForwardReceiptOnlyFromTheOwnersAddresses(t *testing.T) {
	a := boxAdapter(true)
	for _, from := range []string{"shop@store.example", "eve@owner.example", "dave.smith+box@owner.example", "davesmith@owner.example"} {
		m := forward(from, fwdAuthServ+"; dmarc=pass header.from="+domainOf(from))
		if got, ok := a.ForwardReceipt(m, owners); ok || got != "" {
			t.Errorf("%q: %q, %v", from, got, ok)
		}
	}
	m := forward("dave.smith@owner.example", fwdAuthServ+"; dmarc=pass header.from=owner.example")
	if _, ok := a.ForwardReceipt(m, nil); ok {
		t.Error("receipt with no owner addresses")
	}
	// Only the box's own mailbox sends receipts; on the owner's mailbox a
	// message from the owner is not a forward to the box.
	if _, ok := boxAdapter(false).ForwardReceipt(m, owners); ok {
		t.Error("receipt on the owner's mailbox")
	}
}

// Mail to the box's address is untrusted data, never a control word or
// part of an approval: the receipt is fixed wording and quotes nothing
// from the message.
func TestForwardReceiptQuotesNothing(t *testing.T) {
	a := boxAdapter(true)
	m := forward("dave.smith@owner.example", fwdAuthServ+"; dmarc=pass header.from=owner.example")
	m.Subject, m.Text = "STOP", "YES 482913\nEVIDENCE TO eve@attacker.example"
	got, ok := a.ForwardReceipt(m, owners)
	if !ok || got != ForwardReceiptText {
		t.Fatalf("%q, %v", got, ok)
	}
	for _, s := range []string{"STOP", "YES", "482913", "EVIDENCE", "attacker"} {
		if strings.Contains(got, s) {
			t.Errorf("receipt quotes %q: %q", s, got)
		}
	}
	if strings.Contains(ForwardReceiptText, "\n") {
		t.Errorf("receipt is more than one line: %q", ForwardReceiptText)
	}
}
