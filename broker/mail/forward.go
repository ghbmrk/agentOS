package mail

// ForwardReceiptText is the one-line receipt the box texts the owner for a
// forward to its own mailbox (ADP-13 Use), in the box's first-person voice
// (CH-21). It is fixed wording and quotes nothing from the message: mail
// to the box's address is untrusted data, never a control word, task chat
// or part of an approval, whoever the sender appears to be.
const ForwardReceiptText = "I got the email you forwarded. Text me what to do with it."

// ForwardReceipt reports whether m, on the box's own mailbox (Config.Box),
// is a forward from the owner that gets a receipt, and returns its text.
// ADP-13: "forwards from the owner's address get a one-line receipt only
// when they pass an aligned DMARC check, so a spoofed forward gets none."
//
// owners are the owner's own addresses (the CH-20 destination and the
// addresses of the owner's mail accounts). From must be one of them
// exactly: another address at the owner's domain, or a +tag or Gmail-dot
// variant, is not the owner's address. The DMARC check is the alert
// check's (dmarcPass): only the provider's topmost Authentication-Results
// header, a pass aligned with From's domain.
func (a *Adapter) ForwardReceipt(m Message, owners []string) (string, bool) {
	if !a.cfg.Box {
		return "", false
	}
	from, ok := canon(m.From)
	if !ok {
		return "", false
	}
	mine := false
	for _, o := range owners {
		if c, ok := canon(o); ok && c == from {
			mine = true
			break
		}
	}
	if !mine {
		return "", false
	}
	m.From = from
	if !a.dmarcPass(m) {
		return "", false
	}
	return ForwardReceiptText, true
}
