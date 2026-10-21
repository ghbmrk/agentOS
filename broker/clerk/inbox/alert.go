package inbox

import "strings"

// isAlert is the alert guard (#2604): a mail is an alert when its sender
// passes an aligned DMARC check the provider wrote and is one the owner keeps
// as an alert sender (the provider's security sender, a service the owner
// holds an account with, a sender marked financial or identity). The clerk
// never trashes or unsubscribes an alert, whatever the reader called it.
// VRB-2's second net, security-alert wording whoever sent it, waits on the
// eval's phishing case (ASSUMPTIONS.md MIG-4-mail-reader-3).
func isAlert(raw []byte, w World) bool {
	hs, _ := splitMessage(raw)
	for _, h := range hs {
		if h.key() == "authentication-results" { // the topmost: the provider's own
			from := FromAddress(raw)
			return dmarcPass(string(h.value), from, w.AuthServ) && senderIn(from, w.AlertSenders)
		}
	}
	return false
}

// dmarcPass reads only the topmost Authentication-Results header, and only if
// the provider's own server wrote it (its authserv-id): a sender can add more
// of these headers, never above the provider's. The DMARC result must be
// aligned with the From domain.
func dmarcPass(header, from, authServ string) bool {
	if authServ == "" || header == "" || from == "" {
		return false
	}
	id, rs := parseAuthResults(header)
	if !strings.EqualFold(id, authServ) {
		return false
	}
	for _, r := range rs {
		if r.Method == "dmarc" && r.Result == "pass" && strings.EqualFold(r.Props["header.from"], domainOf(from)) {
			return true
		}
	}
	return false
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
