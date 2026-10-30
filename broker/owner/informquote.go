package owner

import "unicode/utf8"

// InformQuote is agent-derived request text s as the broker's own texts
// quote it (grants' Inform texts): clipped to 64 bytes on a rune
// boundary, or "A request" when s or its clip is secret-shaped or takes
// the CH-21 vocabulary or reply grammar (AgentSecret, AgentVoice), since
// Inform runs neither check and planner text carries no label to tell it
// from the broker's (CH-21, #2189). The clip is checked too: it can cut
// a word into a term ("codebook" to "code...", L3 on #4017).
func InformQuote(s string) string {
	q := s
	if len(q) > 64 {
		n := 64
		for n > 0 && !utf8.RuneStart(q[n]) {
			n--
		}
		q = q[:n] + "..."
	}
	for _, t := range []string{s, q} {
		if AgentSecret(t) || AgentVoice(t) {
			return "A request"
		}
	}
	return q
}
