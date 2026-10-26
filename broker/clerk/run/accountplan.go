package run

import (
	"errors"
	"slices"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk/accounts"
)

// Setup's account plan on the owner's socket (TN-account-plan slice b, SPEC
// §12.1 step 7): accountplan reads the senders of a Gmail account's newest
// mail under its grant (inbox.Gmail.PlanSenders), or of an IMAP account's
// (inbox.Live.PlanSenders), keeps only the domains the provider's DKIM
// verdict authenticates, and answers accounts.Build's items
// for them. Only plan items cross the socket: table IDs, the table's fixed
// wording and a source tag, never a byte of mail (DEV-8). The plan is kept
// in memory for this process's lifetime, for the account as it is now, and
// built again after a restart or a change of account; nothing is persisted.

// PlanItem is one plan item on the owner's socket: accounts.Item, and
// whether the account set up here is it.
type PlanItem struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Group       string `json:"group"`
	Source      string `json:"source"`
	Preselected bool   `json:"preselected,omitempty"`
	Label       string `json:"label"`
	Advice      string `json:"advice,omitempty"`
	Connected   bool   `json:"connected,omitempty"`
}

// AccountPlanned is accountplan's answer: the items, or no items and the
// typed reason the mailbox could not be read for them (DReconnect,
// DSignInRefused, DNoSignIn): never a part of a plan.
type AccountPlanned struct {
	Items  []PlanItem `json:"items,omitempty"`
	Reason string     `json:"reason,omitempty"`
}

// planState is the plan kept for the account as it was at changes.
type planState struct {
	mu      sync.Mutex // one build at a time
	plan    *AccountPlanned
	changes int64
}

// accountPlan is the plan for the account set up now: built once, then
// served from memory until the account changes. With no account it holds
// only the card, the wallet, the mailbox and the device-implied items. A
// Gmail account's senders are read through Gmail's declared metadata calls,
// an IMAP account's through the same two header fields over IMAP (#3220),
// both under PlanSender's rule and the world's authserv-id. While a sign-in
// failure stops the clerk, or when the mailbox refuses the sign-in or Gmail
// the grant at refresh (grant death, A22), the answer is the typed reason
// alone.
func (h *MailHost) accountPlan() (AccountPlanned, error) {
	h.planned.mu.Lock()
	defer h.planned.mu.Unlock()
	t, err := accounts.Known()
	if err != nil {
		return AccountPlanned{}, err
	}
	h.mu.Lock()
	changes, stop := h.changes, h.stop
	s, serr := readMail(h.dir)
	if p := h.planned.plan; p != nil && h.planned.changes == changes && stop == nil {
		h.mu.Unlock()
		return *p, nil
	}
	h.mu.Unlock()
	if stop != nil {
		d, _ := stopped(stop)
		return AccountPlanned{Reason: d}, nil
	}
	var domains, connected []string
	switch {
	case errors.Is(serr, ErrNoMailAccount):
	case serr != nil:
		return AccountPlanned{}, errMailUnreadable
	default:
		if s.API == APIGmail {
			connected = []string{APIGmail} // the table's Gmail entry has the API's own ID
		}
		// Over IMAP no item is marked connected: IMAP is Full power,
		// whichever provider serves it (A22, DEP-3).
		box, err := boxFor(s, h.sec, h.cfg)
		if err == nil {
			domains, err = box.PlanSenders(h.ctx, h.authServ())
		}
		if stops(err) {
			h.mu.Lock()
			if h.changes == changes {
				// As a step refused this way (Do): nothing is sent until the
				// owner signs in again, and STATUS says so (#2708 item 2).
				why, next := trouble(err, nil)
				h.why, h.stop = "I stopped working in your mailbox: "+why+". "+next, err
			}
			h.mu.Unlock()
			d, _ := stopped(err)
			return AccountPlanned{Reason: d}, nil
		}
		if err != nil {
			return AccountPlanned{}, err
		}
	}
	var p AccountPlanned
	for _, it := range accounts.Build(t, domains, nil) { // ONB-3's device kinds are not on main yet
		p.Items = append(p.Items, PlanItem{ID: it.ID, Name: it.Name, Kind: it.Kind, Group: it.Group, Source: string(it.Source),
			Preselected: it.Preselected, Label: it.Label, Advice: it.Advice, Connected: slices.Contains(connected, it.ID)})
	}
	h.mu.Lock()
	if h.changes == changes {
		h.planned.plan, h.planned.changes = &p, changes
	}
	h.mu.Unlock()
	return p, nil
}

// authServ is the mailbox provider's authserv-id, the world's: "" matches
// nothing (inbox.PlanSender).
func (h *MailHost) authServ() string {
	if h.cfg.World == nil {
		return ""
	}
	return h.cfg.World().AuthServ
}
