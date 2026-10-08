package grants

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/ghbmrk/agentos/broker/journal"
)

// W5a-resume (Security R2 on #169): the box's Wi-Fi page lists the paused
// grants and asks to resume one. The ask is a grant change from the
// page's origin naming the pause the page showed (Spec.Pause); it is
// approved like any grant, on the page alone with a fresh code-generator
// code (CH-3, CH-10), and that code is bound to this grant and this pause
// through the item's sum (evaluateBroker). The channel texts the answer
// to the owner (owner.LocalAnswer).

// PausedGrant is a paused grant as the page shows it.
type PausedGrant struct {
	ID string
	// What is what resuming lets run again, in Describe's fixed wording.
	What string
	// By is who paused it: "you" (PAUSE by text) or "Loop 2".
	By string
	// Pause is the intent that paused it; a resume names it.
	Pause string
}

// ErrPauseChanged: the grant is not paused as the page showed it. It
// was resumed, revoked or paused again since.
var ErrPauseChanged = errors.New("grants: that grant is not paused as the page showed it")

// Paused lists the paused grants, by ID.
func (g *Gate) Paused() []PausedGrant {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []PausedGrant
	for _, gr := range g.grants {
		if gr.Paused {
			out = append(out, PausedGrant{ID: gr.ID, What: Describe(gr.Spec), By: pausedBy(gr.PausedBy), Pause: gr.Pause})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// resumeAsk is the page's latest resume ask for a grant.
type resumeAsk struct{ pause, intent string }

// pausedBy names a pause's origin for the owner.
func pausedBy(origin string) string {
	switch origin {
	case OriginOwner:
		return "you"
	case OriginLoop2:
		return "Loop 2"
	}
	return "the box"
}

// AskResume asks the owner, on the page, to resume grant id from pause,
// and returns the ask's intent ID. While an ask for that pause is still
// open, it returns that one rather than asking again. The request reaches
// the page when the gate next sends its batch (CH-15 pacing applies).
func (g *Gate) AskResume(ctx context.Context, id, pause string) (string, error) {
	g.mu.Lock()
	gr, eng := g.grants[id], g.eng
	if gr == nil || !gr.Paused || pause == "" || gr.Pause != pause {
		g.mu.Unlock()
		return "", ErrPauseChanged
	}
	open := g.resumes[id]
	g.mu.Unlock()
	if eng == nil {
		return "", errors.New("grants: not attached")
	}
	if open.pause == pause {
		if st, err := eng.Get(open.intent); err == nil && st.State == journal.Pending {
			return open.intent, nil
		}
	}
	b, err := json.Marshal(Spec{Resume: id, Pause: pause})
	if err != nil {
		return "", err
	}
	var spec map[string]any
	if err := json.Unmarshal(b, &spec); err != nil {
		return "", err
	}
	iid := fmt.Sprintf("local/resume/%s/%d.%d", id, g.cfg.Now().UnixNano(), len(eng.List()))
	st, err := g.Submit(journal.Intent{ID: iid, Origin: originLocal, Account: journal.BrokerAccount,
		Action: journal.ActionGrantChange, Params: map[string]any{"grant": spec}, Executor: ExecutorName})
	if err == nil && st.State == journal.Pending {
		st, err = g.Authorize(ctx, iid)
	}
	if err != nil {
		return "", err
	}
	if st.State != journal.Pending {
		return "", fmt.Errorf("grants: resume %s: %s %s", clip(id), st.State, st.Permission.Reason)
	}
	g.mu.Lock()
	if g.resumes == nil {
		g.resumes = map[string]resumeAsk{}
	}
	g.resumes[id] = resumeAsk{pause: pause, intent: iid} // one per grant
	g.mu.Unlock()
	return iid, nil
}
