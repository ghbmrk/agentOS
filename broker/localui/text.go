package localui

import "strings"

// gsmSafe keeps only plain GSM-7 basic characters (CH-12) and cuts to max.
func gsmSafe(s string, max int) string {
	const ok = " ,.-+()/:'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(ok, r) {
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// Example tasks for the "All set" text (ONB-8), by what is connected. The
// defaults need nothing but an AI provider.
var (
	defaultExamples = []string{
		"Plan 3 days in Lisbon in May with a rough budget",
		"Draft a polite note asking my landlord to fix the heater",
		"Each morning, text me a 3-line news summary",
	}
	accountExamples = map[string]string{
		"email":    "Tell me which emails from today need a reply",
		"calendar": "What is on my calendar tomorrow?",
		"files":    "Summarize the newest document in my files",
	}
)

// AllSetText is the first message after setup (ONB-8): three example tasks
// suited to what is connected, plus HELP. When no provider may see private
// data (CAP-9), private tasks would have no route, so only PUBLIC tasks
// without accounts are suggested. It fits CH-12: GSM-7, at most three segments.
func AllSetText(connected []string, privateOK bool) string {
	var ex []string
	if !privateOK {
		connected = nil
	}
	for _, k := range []string{"email", "calendar", "files"} {
		for _, c := range connected {
			if c == k && len(ex) < 3 {
				ex = append(ex, accountExamples[k])
			}
		}
	}
	for _, d := range defaultExamples {
		if len(ex) < 3 {
			ex = append(ex, d)
		}
	}
	if !privateOK {
		// Task text is private by default (§5), so without a provider
		// allowed private data only PUBLIC tasks have a route (CH-11).
		for i := range ex {
			ex[i] = "PUBLIC " + ex[i]
		}
	}
	return "All set. Text me a task, for example:\n1. " + ex[0] + "\n2. " + ex[1] + "\n3. " + ex[2] + "\nHELP for commands."
}
