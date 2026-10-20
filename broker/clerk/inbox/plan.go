package inbox

import (
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Plans is the planner: from the clerk's listing alone, one plan per action.
// Organize every mail under its class, trash spam and phishing, and
// unsubscribe once from each sender the clerk offered a handle for. It sees
// no mail text, so a mail cannot steer it (INJ-1); a plan per action means
// one refused action never takes the others with it.
func Plans(listing []Item, k key.Key) []kernel.Plan {
	var out []kernel.Plan
	add := func(id string, v key.Verb, args map[string]string) {
		a := map[string]key.Arg{}
		for n, val := range args {
			a[n] = key.Arg{Value: val}
		}
		step := kernel.Normalize(id, key.Step{Verb: v, Clerk: Name, Args: a})
		out = append(out, kernel.Plan{ID: id, Key: k, Steps: []key.Step{step}})
	}
	for _, it := range listing {
		add("organize-"+it.Mail, key.Organize, map[string]string{"target": it.Mail, "label": it.Class})
	}
	for _, it := range listing {
		if it.Class == "spam" || it.Class == "phishing" {
			add("trash-"+it.Mail, key.Trash, map[string]string{"target": it.Mail})
		}
	}
	seen := map[string]bool{}
	for _, it := range listing {
		if it.Sender != "" && !seen[it.Sender] {
			seen[it.Sender] = true
			add("unsub-"+it.Sender, key.Unsubscribe, map[string]string{"to": it.Sender})
		}
	}
	return out
}
