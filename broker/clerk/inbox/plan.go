package inbox

import (
	"crypto/ed25519"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// DailyCap is VRB-2's bound: organize and trash effects per account per day.
// Unsubscribe is not counted.
const DailyCap = 200

// PlannerKeys derives the two sibling keys a planner is handed. The first
// carries organize and trash and the daily cap, so the cap is counted at the
// clerk from the log and survives a restart; the second carries unsubscribe and
// the hold, which the cap does not count. Neither can be widened by the planner.
func PlannerKeys(root key.Key, holder ed25519.PrivateKey, planner ed25519.PublicKey, holdBaseMS, holdNoveltyMS int64) (bulk, unsub key.Key, err error) {
	bulk, err = key.Derive(root, holder, planner, key.LimitVerbs(key.Organize, key.Trash), key.LimitRate(DailyCap))
	if err != nil {
		return key.Key{}, key.Key{}, err
	}
	unsub, err = key.Derive(root, holder, planner, key.LimitVerbs(key.Unsubscribe), key.LimitHold(holdBaseMS, holdNoveltyMS))
	return bulk, unsub, err
}

// Left is the work the daily cap put off, counted by action.
type Left struct{ Organize, Trash int }

// Plans is the planner: from the clerk's listing alone, one plan per action.
// Trash spam and phishing, organize every mail under its class, and
// unsubscribe once from each sender the clerk offered a handle for. Trash is
// submitted first so the cap (the bulk key's, enforced at the clerk) never spends itself on labels while spam stays;
// what the cap puts off comes back as Left. It sees no mail text, so a mail
// cannot steer it (INJ-1); a plan per action means one refused action never
// takes the others with it.
func Plans(listing []Item, bulk, unsub key.Key) ([]kernel.Plan, Left) {
	var left Left
	room := DailyCap
	var out []kernel.Plan
	add := func(id string, v key.Verb, args map[string]string) {
		k := bulk
		if v == key.Unsubscribe {
			k = unsub
		}
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
		add("organize-"+it.Mail, key.Organize, map[string]string{"target": it.Mail, "label": labelPrefix + it.Class})
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
