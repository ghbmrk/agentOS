package inbox

import (
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// DailyCap is VRB-2's bound: organize and trash effects per account per day.
// Unsubscribe is not counted.
const DailyCap = 200

// Left is the work the daily cap put off, counted by action.
type Left struct{ Organize, Trash int }

// Plans is the planner: from the clerk's listing alone, one plan per action.
// Trash spam and phishing, organize every mail under its class, and
// unsubscribe once from each sender the clerk offered a handle for. Trash is
// submitted first so the cap never spends itself on labels while spam stays;
// what the cap puts off comes back as Left. It sees no mail text, so a mail
// cannot steer it (INJ-1); a plan per action means one refused action never
// takes the others with it.
func Plans(listing []Item, k key.Key) ([]kernel.Plan, Left) {
	var left Left
	room := DailyCap
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
		if it.Class == "spam" || it.Class == "phishing" {
			if room == 0 {
				left.Trash++
				continue
			}
			room--
			add("trash-"+it.Mail, key.Trash, map[string]string{"target": it.Mail})
		}
	}
	for _, it := range listing {
		if room == 0 {
			left.Organize++
			continue
		}
		room--
		add("organize-"+it.Mail, key.Organize, map[string]string{"target": it.Mail, "label": "agentOS/" + it.Class})
	}
	seen := map[string]bool{}
	for _, it := range listing {
		if it.Sender != "" && !seen[it.Sender] {
			seen[it.Sender] = true
			add("unsub-"+it.Sender, key.Unsubscribe, map[string]string{"to": it.Sender})
		}
	}
	return out, left
}
