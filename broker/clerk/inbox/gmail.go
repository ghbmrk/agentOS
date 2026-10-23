package inbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// GmailBase is the Gmail API's root for the signed-in account, and
// GmailToken Google's OAuth token endpoint (D-150).
const (
	GmailBase  = "https://gmail.googleapis.com/gmail/v1/users/me"
	GmailToken = "https://oauth2.googleapis.com/token"
)

// Gmail's declared calls, by name. Nothing else exists (CLK-3): no call
// deletes a mail for good (messages.delete, batchDelete), changes a setting
// (filters, forwarding, auto-forwarding, sign-in, delegates) or removes a
// label, so the read state (UNREAD) is never changed.
const (
	gList      = "messages.list"
	gListNext  = "messages.list.next"
	gMetadata  = "messages.get.metadata"
	gFull      = "messages.get.full"
	gRaw       = "messages.get.raw"
	gLabel     = "messages.label"
	gTrash     = "messages.trash"
	gUntrash   = "messages.untrash"
	gLabels    = "labels.list"
	gNewLabel  = "labels.create"
	gSend      = "messages.send"
	gHistory   = "history.list"
	gFilters   = "settings.filters.list"
	gForwards  = "settings.forwardingAddresses.list"
	gAutoFwd   = "settings.autoForwarding.get"
	gProfile   = "profile.get"
	gRawMax    = 1 << 20 // a raw message's answer; a mail past it is not read (fail closed)
	gPageMax   = 1 << 20 // a list's or history's page
	gSmallMax  = 64 << 10
	gListLimit = "500" // ids per list page, Gmail's most
)

// GmailCalls is Gmail's declaration over base (GmailBase, or a fake's), its
// secret in slot as a bearer token redeemed from the sealed refresh grant.
// They are the calls TN-gmail-api names (CLK-9): list and get (metadata,
// full, raw), adding an agentOS/ label, trash and untrash, the agentOS/
// labels, send, history, the reads of filters, forwarding and
// auto-forwarding, and the profile. The grant gmail.modify allows more
// (permanent deletion needs the full-mail scope and settings writes
// gmail.settings.*, which the box never asks for); this list is narrower
// still.
func GmailCalls(base, slot string) []clerk.Call {
	get := func(name, path string, max int64, args ...string) clerk.Call {
		return clerk.Call{Name: name, Args: args, Max: max, Op: clerk.Op{Method: "GET", URL: base + path,
			Slot: slot, Prefix: "Bearer ", Headers: map[string]string{"Accept": "application/json"}}}
	}
	post := func(name, path string, max int64, body map[string]string, args ...string) clerk.Call {
		c := get(name, path, max, args...)
		c.Method = "POST"
		if len(body) > 0 {
			c.Type, c.Body = clerk.TypeJSON, body
		}
		return c
	}
	next := get(gListNext, "/messages?labelIds=INBOX&maxResults="+gListLimit, gPageMax, "page")
	next.Query = map[string]string{"pageToken": "page"}
	history := get(gHistory, "/history?labelId=INBOX", gPageMax, "start")
	history.Query = map[string]string{"startHistoryId": "start"}
	label := post(gLabel, "/messages/{id}/modify", gSmallMax, map[string]string{"addLabelIds": "label"}, "id", "label")
	label.Lists = []string{"addLabelIds"}
	return []clerk.Call{
		get(gList, "/messages?labelIds=INBOX&maxResults="+gListLimit, gPageMax),
		next,
		get(gMetadata, "/messages/{id}?format=metadata&metadataHeaders=From&metadataHeaders=Message-ID", gSmallMax, "id"),
		get(gFull, "/messages/{id}?format=full", gRawMax, "id"),
		get(gRaw, "/messages/{id}?format=raw", gRawMax, "id"),
		label,
		post(gTrash, "/messages/{id}/trash", gSmallMax, nil, "id"),
		post(gUntrash, "/messages/{id}/untrash", gSmallMax, nil, "id"),
		get(gLabels, "/labels", gPageMax),
		post(gNewLabel, "/labels", gSmallMax, map[string]string{"name": "name"}, "name"),
		post(gSend, "/messages/send", gSmallMax, map[string]string{"raw": "raw"}, "raw"),
		history,
		get(gFilters, "/settings/filters", gPageMax),
		get(gForwards, "/settings/forwardingAddresses", gSmallMax),
		get(gAutoFwd, "/settings/autoForwarding", gSmallMax),
		get(gProfile, "/profile", gSmallMax),
	}
}

// GmailDeclaration is the mail clerk's declaration for a Gmail account.
func GmailDeclaration(base, token, slot string, guard *netguard.Policy, clock clerk.Clock) clerk.APIDeclaration {
	return clerk.APIDeclaration{Name: Name, Calls: GmailCalls(base, slot), Guard: guard, Refresh: token, Clock: clock}
}

// Gmail is the owner's mailbox over the Gmail API (D-150), beside Live's
// IMAP: the same Mailbox, its effects made through the exit's declared calls
// (clerk.API). A label is an agentOS/ user label, added and never removed; a
// trash moves the mail to Gmail's trash, never deletes it; each effect is
// read back before it counts. Gmail's API never marks a mail read on a get.
type Gmail struct {
	api    *clerk.API
	poster *Poster // nil, unless WithPoster: unsubscribes are refused (no-poster)

	mu     sync.Mutex
	refs   map[string]string // the clerk's mail id to Gmail's message id
	labels map[string]string // agentOS/ label name to its id
}

// NewGmail is a mailbox over api, which must be built from GmailCalls. It
// has no Poster, so its unsubscribes are refused until WithPoster.
func NewGmail(api *clerk.API) *Gmail {
	return &Gmail{api: api, refs: map[string]string{}, labels: map[string]string{}}
}

// WithPoster gives g a Poster on guard, the clerk's home-network policy, and
// returns g. Call it before g is used.
func (g *Gmail) WithPoster(guard *netguard.Policy) *Gmail {
	g.poster = NewPoster(guard, nil)
	return g
}

// The reasons a Gmail call refuses before acting, beside Mailbox's own.
const (
	nRefused     NotDone = "refused"        // the API answered 4xx: nothing was done
	nBusy        NotDone = "busy"           // 429: nothing was done
	nReconnect   NotDone = "reconnect"      // the grant is dead: the owner signs in again
	nGmailUnsent NotDone = "gmail-not-sent" // the clerk sent nothing (credential, address, token endpoint)
	nBadLabel    NotDone = "bad-label"      // the API named a label the clerk may not add
)

// call makes one declared call and decodes a 2xx answer into v (nil skips
// it). Its error is NotDone when the call did nothing.
func (g *Gmail) call(ctx context.Context, name string, args map[string]string, v any) (int, error) {
	ans, bad := g.api.Call(ctx, name, args)
	switch {
	case strings.HasPrefix(bad, clerk.DReconnect):
		return 0, nReconnect
	case bad == clerk.DUndeclared || strings.HasPrefix(bad, clerk.DArg) || bad == clerk.DCredential ||
		bad == clerk.DBlocked || strings.HasPrefix(bad, clerk.DRefresh):
		return 0, nGmailUnsent
	case bad != "":
		return ans.Status, errors.New("inbox: gmail: " + bad)
	}
	switch c := ans.Status; {
	case c/100 == 2:
		if v != nil && json.Unmarshal(ans.Body, v) != nil {
			return c, errors.New("inbox: gmail: an answer that does not decode")
		}
		return c, nil
	case c == http.StatusTooManyRequests:
		return c, nBusy
	case c >= 400 && c < 500 && c != http.StatusRequestTimeout && c != http.StatusConflict:
		return c, nRefused
	}
	return ans.Status, errors.New("inbox: gmail: http " + http.StatusText(ans.Status))
}

type gMessage struct {
	ID       string   `json:"id"`
	LabelIDs []string `json:"labelIds"`
	Raw      string   `json:"raw"`
}

// Read lists the newest readMax inbox mails and gets each one raw,
// unclassified. A mail whose answer passes gRawMax, or that is gone by the
// time it is fetched, is left out: the clerk does not act on a mail it could
// not read. It replaces what an earlier Read found.
func (g *Gmail) Read(ctx context.Context) ([]Mail, error) {
	var ids []string
	page := ""
	for len(ids) < readMax {
		var l struct {
			Messages []struct {
				ID string `json:"id"`
			} `json:"messages"`
			Next string `json:"nextPageToken"`
		}
		name, args := gList, map[string]string{}
		if page != "" {
			name, args = gListNext, map[string]string{"page": page}
		}
		if _, err := g.call(ctx, name, args, &l); err != nil {
			return nil, err
		}
		for _, m := range l.Messages {
			ids = append(ids, m.ID)
		}
		if l.Next == "" || len(l.Messages) == 0 {
			break
		}
		page = l.Next
	}
	ids = ids[:min(len(ids), readMax)] // Gmail lists newest first
	refs := map[string]string{}
	var out []Mail
	for _, id := range ids {
		if !gmailID.MatchString(id) {
			return nil, errors.New("inbox: gmail: a message id outside Gmail's form")
		}
		var m gMessage
		ans, bad := g.api.Call(ctx, gRaw, map[string]string{"id": id})
		if bad == clerk.DTooLarge || bad == "" && ans.Status == http.StatusNotFound {
			continue
		}
		if _, err := g.decodeInto(ans, bad, &m); err != nil {
			return nil, err
		}
		raw, err := decodeRaw(m.Raw)
		if m.ID != id || err != nil {
			return nil, errors.New("inbox: gmail: a raw message that does not decode")
		}
		mid := "gmail-" + id
		refs[mid] = id
		out = append(out, Mail{ID: mid, Raw: g.api.Redact(raw)})
	}
	g.mu.Lock()
	g.refs = refs
	g.mu.Unlock()
	return out, nil
}

// decodeInto reads an answer Read already has in hand as call does.
func (g *Gmail) decodeInto(ans clerk.Answer, bad string, v any) (int, error) {
	if bad != "" {
		return 0, errors.New("inbox: gmail: " + bad)
	}
	if ans.Status/100 != 2 || json.Unmarshal(ans.Body, v) != nil {
		return ans.Status, errors.New("inbox: gmail: a message that could not be read")
	}
	return ans.Status, nil
}

// gmailID is the form of Gmail's message ids; one outside it is refused
// before it fills a path segment.
var gmailID = regexp.MustCompile(`^[0-9A-Za-z_-]{1,64}$`)

// decodeRaw reads Gmail's base64url raw message, padded or not.
func decodeRaw(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (g *Gmail) mail(id string) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	m, ok := g.refs[id]
	if !ok {
		return "", nUnknown
	}
	return m, nil
}

// systemLabel is the form of Gmail's system label ids (INBOX, UNREAD,
// CATEGORY_PROMOTIONS): a label the clerk adds must not be one, whatever
// the API calls it, so no answer can turn a label into a read-state change.
var systemLabel = regexp.MustCompile(`^[A-Z_]+$`)

type gLabelRes struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// labelID is the id of the user label named name, created if the account
// has none. name is under labelPrefix.
func (g *Gmail) labelID(ctx context.Context, name string) (string, error) {
	g.mu.Lock()
	id, ok := g.labels[name]
	g.mu.Unlock()
	if ok {
		return id, nil
	}
	var l struct {
		Labels []gLabelRes `json:"labels"`
	}
	if _, err := g.call(ctx, gLabels, nil, &l); err != nil {
		return "", err
	}
	found := gLabelRes{}
	for _, x := range l.Labels {
		if x.Name == name {
			found = x
		}
	}
	if found.ID == "" {
		if _, err := g.call(ctx, gNewLabel, map[string]string{"name": name}, &found); err != nil {
			return "", err
		}
	}
	if found.Name != name || found.Type != "user" || systemLabel.MatchString(found.ID) || !gmailID.MatchString(found.ID) {
		return "", nBadLabel
	}
	g.mu.Lock()
	g.labels[name] = found.ID
	g.mu.Unlock()
	return found.ID, nil
}

// labelsOf reads the mail's labels back.
func (g *Gmail) labelsOf(ctx context.Context, id string) ([]string, error) {
	var m gMessage
	_, err := g.call(ctx, gMetadata, map[string]string{"id": id}, &m)
	if errors.As(err, new(NotDone)) {
		// The read-back did nothing, so it shows nothing either way.
		return nil, errors.New("inbox: gmail: the read-back was refused")
	}
	return m.LabelIDs, err
}

// Label adds the agentOS/ label to the mail and reads it back. Only the
// clerk's own labels are labels, and they are only ever added.
func (g *Gmail) Label(ctx context.Context, mail, label string) error {
	if !strings.HasPrefix(label, labelPrefix) {
		return nBadFlag
	}
	id, err := g.mail(mail)
	if err != nil {
		return err
	}
	lid, err := g.labelID(ctx, label)
	if err != nil {
		return err
	}
	if _, err := g.call(ctx, gLabel, map[string]string{"id": id, "label": lid}, nil); err != nil {
		return err
	}
	got, err := g.labelsOf(ctx, id)
	if err != nil {
		return err
	}
	if !slices.Contains(got, lid) {
		return errUnconfirmed
	}
	return nil
}

// Trash moves the mail to Gmail's trash, which keeps it 30 days, and reads
// it back. Gmail's trash is idempotent, so a resend after a lost answer is
// confirmed by the same read-back.
func (g *Gmail) Trash(ctx context.Context, mail string) error {
	id, err := g.mail(mail)
	if err != nil {
		return err
	}
	if _, err := g.call(ctx, gTrash, map[string]string{"id": id}, nil); err != nil {
		return err
	}
	got, err := g.labelsOf(ctx, id)
	if err != nil {
		return err
	}
	if !slices.Contains(got, "TRASH") {
		return errUnconfirmed
	}
	return nil
}

// Untrash takes a mail the clerk trashed back out of Gmail's trash (UNDO)
// and reads it back.
func (g *Gmail) Untrash(ctx context.Context, mail string) error {
	id, err := g.mail(mail)
	if err != nil {
		return err
	}
	if _, err := g.call(ctx, gUntrash, map[string]string{"id": id}, nil); err != nil {
		return err
	}
	got, err := g.labelsOf(ctx, id)
	if err != nil {
		return err
	}
	if slices.Contains(got, "TRASH") {
		return errUnconfirmed
	}
	return nil
}

// Post sends the one-click unsubscribe through the mailbox's Poster, as
// Live does; a Gmail with none refuses (no-poster).
func (g *Gmail) Post(ctx context.Context, p Post) error {
	if g.poster == nil {
		return nNoPoster
	}
	return g.poster.Post(ctx, p)
}

// Doors is what the account sends elsewhere on its own: its filters, its
// forwarding addresses and its auto-forwarding, read only, for a watch on
// them (CLK-9: the box's grant cannot change them).
type Doors struct {
	Filters     int
	Forwarding  []string
	AutoForward string // the address mail is auto-forwarded to, "" when off
}

// Doors reads the account's filters, forwarding and auto-forwarding.
func (g *Gmail) Doors(ctx context.Context) (Doors, error) {
	var f struct {
		Filter []json.RawMessage `json:"filter"`
	}
	var fw struct {
		Addresses []struct {
			Email string `json:"forwardingEmail"`
		} `json:"forwardingAddresses"`
	}
	var af struct {
		Enabled bool   `json:"enabled"`
		Email   string `json:"emailAddress"`
	}
	var d Doors
	if _, err := g.call(ctx, gFilters, nil, &f); err != nil {
		return d, err
	}
	if _, err := g.call(ctx, gForwards, nil, &fw); err != nil {
		return d, err
	}
	if _, err := g.call(ctx, gAutoFwd, nil, &af); err != nil {
		return d, err
	}
	d.Filters = len(f.Filter)
	for _, a := range fw.Addresses {
		d.Forwarding = append(d.Forwarding, a.Email)
	}
	if af.Enabled {
		d.AutoForward = af.Email
		if d.AutoForward == "" {
			d.AutoForward = "?" // on, to an address the API did not name
		}
	}
	return d, nil
}

// Mark is the account's history id now, so a caller can skip a read that
// would find nothing new (as Live's Mark).
func (g *Gmail) Mark(ctx context.Context) (string, error) {
	var p struct {
		History string `json:"historyId"`
	}
	if _, err := g.call(ctx, gProfile, nil, &p); err != nil {
		return "", err
	}
	if p.History == "" {
		return "", errors.New("inbox: gmail: the profile has no history id")
	}
	return p.History, nil
}

// Changed reports whether the inbox changed since mark. A mark Gmail no
// longer keeps history for (404), or an empty one, counts as changed (fail
// closed).
func (g *Gmail) Changed(ctx context.Context, mark string) (bool, error) {
	if mark == "" {
		return true, nil
	}
	var h struct {
		History []json.RawMessage `json:"history"`
		Next    string            `json:"nextPageToken"`
	}
	c, err := g.call(ctx, gHistory, map[string]string{"start": mark}, &h)
	if c == http.StatusNotFound {
		return true, nil
	}
	if err != nil {
		return true, err
	}
	return len(h.History) > 0 || h.Next != "", nil
}
