// Package accounts builds setup's account plan (SPEC §12.1 step 7,
// TN-account-plan): the payment card, the wallet and the optional mailbox,
// then the known services the owner's mail shows they use and the ones their
// devices imply. It is pure: it does no I/O and reads only the domains the
// mail clerk authenticated and the shipped table of known services
// (known.json, CLK-14). Every string in a plan comes from that table or a
// constant here, never from mail (DEV-8).
package accounts

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

//go:embed known.json
var known []byte

// The entries every table has, by id: the payment card (KEY-2), the payment
// wallet (CH-10) and the box's own optional mailbox (CLK-8). A plan always
// opens with them, in this order.
const (
	CardID    = "payment-card"
	WalletID  = "payment-wallet"
	MailboxID = "mailbox"
)

// The labels an item carries (CLK-9) and the advice an item with a narrower
// credential carries. IMAP is always Full power (DEP-3, A22).
const (
	LabelNarrower  = "Narrower than you, watched"
	LabelFull      = "Full power, same as yours"
	AdviceNarrower = "This service offers a sign-in narrower than yours, so connecting it lets me watch it without full power."
)

// NotConnected is the one wording an unconnected account carries to guests
// (PLN-7).
const NotConnected = "exists, not connected"

// Source is where an item came from.
type Source string

const (
	FromMail   Source = "mail"   // an authenticated sender domain matched it
	FromDevice Source = "device" // a connected device's kind implies it
	Always     Source = "always" // the card, the wallet and the mailbox
)

// Entry is one known service. Unknown fields are refused when the table
// loads, so a field #2860 adds is added here and in validate on purpose.
type Entry struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Group     string   `json:"group"`
	Domains   []string `json:"domains"`
	SignIn    []string `json:"signin"`
	Narrower  bool     `json:"narrower"`
	Route     string   `json:"route"`
	AtHome    bool     `json:"at_home"`
	Ongoing   bool     `json:"ongoing"`
	ImpliedBy []string `json:"implied_by"`
}

// SignInAllowed reports whether a sign-in may go to u: https, no user info
// or port, and a host the entry declares.
func (e Entry) SignInAllowed(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Port() != "" {
		return false
	}
	h := u.Hostname()
	return h != "" && slices.Contains(e.SignIn, h)
}

// Table is a validated table of known services, in its file's order.
type Table struct{ entries []Entry }

// Known is the shipped table.
func Known() (*Table, error) { return Load(known) }

// Load decodes and validates a table: a JSON array of entries.
func Load(b []byte) (*Table, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var es []Entry
	if err := d.Decode(&es); err != nil {
		return nil, fmt.Errorf("accounts: table: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("accounts: table: data after the array")
	}
	if err := validate(es); err != nil {
		return nil, err
	}
	return &Table{entries: es}, nil
}

// Entries is the table's entries, in order.
func (t *Table) Entries() []Entry { return slices.Clone(t.entries) }

// Entry is the entry with id.
func (t *Table) Entry(id string) (Entry, bool) {
	for _, e := range t.entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

var (
	kinds  = []string{"money", "identity", "mail", "utility", "shopping", "travel", "other"}
	groups = []string{"payment", "mailbox", "account"}
	routes = []string{"oauth", "imap", "password", "none"}
	token  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	label  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// hostname reports whether h is a lower-case A-label hostname of two labels
// or more: no scheme, path, port, user info or trailing dot.
func hostname(h string) bool {
	ls := strings.Split(h, ".")
	if len(h) > 253 || len(ls) < 2 {
		return false
	}
	for _, l := range ls {
		if !label.MatchString(l) {
			return false
		}
	}
	return true
}

// under reports whether d is p or a subdomain of p.
func under(d, p string) bool { return d == p || strings.HasSuffix(d, "."+p) }

func validate(es []Entry) error {
	ids := map[string]bool{}
	var domains []string
	for _, e := range es {
		bad := func(why string) error { return fmt.Errorf("accounts: table: entry %q: %s", e.ID, why) }
		switch {
		case !token.MatchString(e.ID):
			return bad("an id outside [a-z0-9-]")
		case ids[e.ID]:
			return bad("a duplicate id")
		case strings.TrimSpace(e.Name) == "":
			return bad("no name")
		case !slices.Contains(kinds, e.Kind):
			return bad("an unknown kind")
		case !slices.Contains(groups, e.Group):
			return bad("an unknown group")
		case !slices.Contains(routes, e.Route):
			return bad("an unknown route")
		case e.Route == "imap" && e.Narrower:
			return bad("an IMAP route marked narrower: IMAP is always full power")
		}
		ids[e.ID] = true
		for _, d := range e.Domains {
			if !hostname(d) {
				return bad("a domain that is not a lower-case A-label hostname: " + d)
			}
			for _, o := range domains {
				if under(d, o) || under(o, d) {
					return bad("a domain that sits in two entries: " + d)
				}
			}
		}
		domains = append(domains, e.Domains...)
		for _, h := range e.SignIn {
			if !hostname(h) {
				return bad("a sign-in host that is not a bare hostname: " + h)
			}
		}
		for _, k := range e.ImpliedBy {
			if !token.MatchString(k) {
				return bad("a device kind outside [a-z0-9-]")
			}
		}
	}
	for id, group := range map[string]string{CardID: "payment", WalletID: "payment", MailboxID: "mailbox"} {
		i := slices.IndexFunc(es, func(e Entry) bool { return e.ID == id })
		if i < 0 || es[i].Group != group {
			return fmt.Errorf("accounts: table: no %q entry in group %q", id, group)
		}
	}
	return nil
}

// Item is one line of the plan. Every string is the table's or a constant.
type Item struct {
	ID          string
	Name        string
	Kind        string
	Group       string
	Source      Source
	Preselected bool
	Label       string
	Advice      string
}

// Build is the plan for the sender domains the mail clerk authenticated and
// the device kinds the ONB-3 plan step connected: the card, the wallet and
// the mailbox, then every other entry matched by a domain (exactly or as a
// parent) or implied by a device, in table order. It is deterministic: the
// order of domains and devices does not matter, and an entry both found and
// implied appears once, as found in mail.
func Build(t *Table, domains, devices []string) []Item {
	if t == nil {
		return nil
	}
	var plan []Item
	for _, id := range []string{CardID, WalletID, MailboxID} {
		e, _ := t.Entry(id)
		plan = append(plan, item(e, Always))
	}
	for _, e := range t.entries {
		if always(e) {
			continue
		}
		switch {
		case found(e, domains):
			plan = append(plan, item(e, FromMail))
		case slices.ContainsFunc(e.ImpliedBy, func(k string) bool { return slices.Contains(devices, k) }):
			plan = append(plan, item(e, FromDevice))
		}
	}
	return plan
}

// Held is the domains, of those given, that Build matches to an entry: the
// authenticated sender domains of services in the table, in their order.
// The card, the wallet and the mailbox, which Build lists always, match
// none.
func (t *Table) Held(domains []string) []string {
	if t == nil {
		return nil
	}
	var held []string
	for _, d := range domains {
		if slices.ContainsFunc(t.entries, func(e Entry) bool { return !always(e) && matches(e, d) }) {
			held = append(held, d)
		}
	}
	return held
}

// always reports whether Build lists e whatever the domains and devices.
func always(e Entry) bool { return e.ID == CardID || e.ID == WalletID || e.ID == MailboxID }

// found reports whether one of domains matches e.
func found(e Entry, domains []string) bool {
	return slices.ContainsFunc(domains, func(d string) bool { return matches(e, d) })
}

// matches reports whether the authenticated domain d is one of e's domains
// or under one.
func matches(e Entry, d string) bool {
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	return slices.ContainsFunc(e.Domains, func(p string) bool { return under(d, p) })
}

func item(e Entry, src Source) Item {
	it := Item{ID: e.ID, Name: e.Name, Kind: e.Kind, Group: e.Group, Source: src, Label: LabelFull}
	switch e.ID {
	case CardID:
		it.Preselected = true // KEY-2: the card counts as preselected
	case MailboxID:
	default:
		it.Preselected = e.AtHome || e.Ongoing
	}
	if e.Narrower && e.Route != "imap" {
		it.Label, it.Advice = LabelNarrower, AdviceNarrower
	}
	return it
}

// Listing is an account found but not connected, as guests see it (PLN-7):
// its service name and kind, and nothing else. Its wording is NotConnected.
// PLN-3: the list is private content.
type Listing struct {
	Service string
	Kind    string
}

// Unconnected is every plan item whose id is not in connected, except the
// card, wallet and mailbox (Source Always): those are offers, and nothing
// shows the owner holds one, so listing them as "exists, not connected"
// would hand a planner a false fact (PLN-7, #3237).
func Unconnected(plan []Item, connected []string) []Listing {
	var out []Listing
	for _, it := range plan {
		if it.Source != Always && !slices.Contains(connected, it.ID) {
			out = append(out, Listing{Service: it.Name, Kind: it.Kind})
		}
	}
	return out
}
