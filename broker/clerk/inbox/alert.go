package inbox

import (
	"mime"
	"net/mail"
	"slices"
	"strings"
)

// isAlert is the alert guard (#2604, #2681): a mail is an alert when its
// sender passes an aligned DMARC check the provider wrote and is one the owner
// keeps as an alert sender (the provider's security sender, a service the owner
// holds an account with, a sender marked financial or identity); or, whoever
// sent it, when it carries security-alert wording or a code (VRB-2's second
// net, wordingAlert). The clerk never trashes or unsubscribes an alert,
// whatever the reader called it.
func isAlert(raw []byte, w World) bool {
	return alertSender(raw, w) || wordingAlert(mailText(raw))
}

// VerifiedAlert reports whether an alert counts as a signal (TN-gmail-api):
// its sender passes the first net (an aligned DMARC pass the provider wrote,
// from a kept alert sender) and the clerk itself verifies a current DKIM
// signature on it with the world's key records, aligned with the From domain
// and covering the From header (VRB-2's verifier). A provider's header alone
// never makes a signal. The guard stays wider: an alert that does not verify
// is still never trashed or unsubscribed; it only does not count.
func VerifiedAlert(raw []byte, w World) bool {
	if !alertSender(raw, w) {
		return false
	}
	_, domain, _ := strings.Cut(canonAddr(FromAddress(raw)), "@")
	if domain == "" {
		return false
	}
	var pass []Sig
	for _, s := range VerifyDKIM(raw, w.DKIMKeys) {
		if s.Pass {
			pass = append(pass, s)
		}
	}
	current, _ := currentSigs(pass, w.Today)
	for _, s := range current {
		if aligned(s.D, domain) && slices.Contains(s.H, "from") {
			return true
		}
	}
	return false
}

// guardOff reports whether the guard lacks an input it needs: with no
// authserv-id no header is the provider's, and with no alert senders no
// sender is one, so the first net would be off without a trace. The clerk
// then trashes and unsubscribes nothing (no-alert-guard).
func guardOff(w World) bool {
	if strings.TrimSpace(w.AuthServ) == "" {
		return true
	}
	for _, e := range w.AlertSenders {
		if strings.TrimSpace(e) != "" {
			return false
		}
	}
	return true
}

// alertSender is the first net. A mail with more than one From header, or
// more than one address in it, is never an alert by its sender: which one the
// provider's DMARC result is for is not known, so a forged alert must not
// reach the owner as one from a trusted sender (#2681 item 5).
func alertSender(raw []byte, w World) bool {
	hs, _ := splitMessage(raw)
	auth, froms := "", 0
	var from []byte
	for _, h := range hs {
		switch h.key() {
		case "authentication-results":
			if auth == "" { // the topmost: the provider's own
				auth = string(h.value)
			}
		case "from":
			froms++
			from = h.value
		}
	}
	if froms != 1 {
		return false
	}
	// Unfolded, and with an encoded-word name in any charset read as raw
	// bytes, so a well-formed single sender is never taken for two.
	p := mail.AddressParser{WordDecoder: &mime.WordDecoder{CharsetReader: rawCharset}}
	if l, err := p.ParseList(strings.TrimSpace(unfold.Replace(string(from)))); err != nil || len(l) != 1 {
		return false
	}
	addr := FromAddress(raw)
	return dmarcPass(auth, addr, w.AuthServ) && senderIn(addr, w.AlertSenders)
}

// unfold joins a folded header value onto one line.
var unfold = strings.NewReplacer("\r\n", "", "\n", "", "\r", "")

// dmarcPass reads only the topmost Authentication-Results header, and only if
// the provider's own server wrote it (its authserv-id): a sender can add more
// of these headers, never above the provider's. Every DMARC result in it must
// pass aligned with the From domain, so a header whose results conflict
// passes nothing (#2681 item 5).
func dmarcPass(header, from, authServ string) bool {
	if authServ == "" || header == "" || from == "" {
		return false
	}
	id, rs := parseAuthResults(header)
	if !strings.EqualFold(id, authServ) {
		return false
	}
	pass := false
	for _, r := range rs {
		if r.Method != "dmarc" {
			continue
		}
		if r.Result != "pass" || !strings.EqualFold(r.Props["header.from"], domainOf(from)) {
			return false
		}
		pass = true
	}
	return pass
}

func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return strings.ToLower(addr[i+1:])
	}
	return ""
}

// senderIn reports whether addr matches an entry: the address itself, or a
// domain (with or without a leading @) of which addr's domain is the domain or
// a subdomain.
func senderIn(addr string, entries []string) bool {
	addr = strings.ToLower(addr)
	d := domainOf(addr)
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if strings.Contains(strings.TrimPrefix(e, "@"), "@") {
			if e == addr {
				return true
			}
			continue
		}
		e = strings.TrimPrefix(e, "@")
		if d != "" && (d == e || strings.HasSuffix(d, "."+e)) {
			return true
		}
	}
	return false
}
