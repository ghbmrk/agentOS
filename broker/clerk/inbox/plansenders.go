package inbox

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"net/mail"
	"slices"
	"strings"

	"github.com/ghbmrk/agentos/broker/clerk"
)

// The account plan's declared calls (GmailCalls): every mail but spam and
// trash, newest first, with no query (Gmail refuses q under gmail.metadata),
// and each one's From and Authentication-Results.
const (
	gPlanList     = "messages.list.plan"
	gPlanListNext = "messages.list.plan.next"
	gPlanMetadata = "messages.get.plan"
)

// PlanMails is how many of the newest mails setup's account plan reads the
// senders of (TN-account-plan).
const PlanMails = 1000

// gPlanPagesMax bounds the plan's listing: an API that keeps naming a next
// page ends the listing there. A var for tests.
var gPlanPagesMax = 2 * PlanMails / 500

// PlanSender is the domain a mail's sender is DKIM-authenticated for, by
// the mailbox provider's own verdict (TN-account-plan-1), or "" when none:
// under gmail.metadata the box cannot check a body hash itself. Only the
// topmost Authentication-Results field counts, and only when authServ (the
// declaration's AuthServ; "" matches nothing) wrote it. It must carry a
// dkim=pass whose header.d is d (header.i's domain when header.d is absent,
// as Gmail writes it), and the one From address must be at d or under it.
// A pass inside a comment or a quoted value is no result. head is the mail's
// header lines, as IMAP or Gmail's metadata gives them, in message order.
func PlanSender(head []byte, authServ string) string {
	hs, _ := splitMessage(head)
	var fs [][2]string
	for _, h := range hs {
		fs = append(fs, [2]string{string(h.name), string(h.value)})
	}
	return planSender(fs, authServ)
}

// planSender is PlanSender over header fields, each a name and a value.
func planSender(fs [][2]string, authServ string) string {
	authServ = strings.TrimSpace(authServ)
	if authServ == "" {
		return ""
	}
	auth, from, froms, seen := "", "", 0, false
	for _, f := range fs {
		switch strings.ToLower(strings.TrimSpace(f[0])) {
		case "authentication-results":
			if !seen { // the topmost: the provider's own
				auth, seen = unfold.Replace(f[1]), true
			}
		case "from":
			froms++
			from = unfold.Replace(f[1])
		}
	}
	if froms != 1 || auth == "" {
		return ""
	}
	p := mail.AddressParser{WordDecoder: &mime.WordDecoder{CharsetReader: rawCharset}}
	l, err := p.ParseList(strings.TrimSpace(from))
	if err != nil || len(l) != 1 {
		return ""
	}
	fd := alabel(domainOf(l[0].Address))
	id, rs := parseAuthResults(auth)
	if fd == "" || !strings.EqualFold(id, authServ) {
		return ""
	}
	for _, r := range rs {
		if r.Method != "dkim" || r.Result != "pass" {
			continue
		}
		d, ok := r.Props["header.d"]
		if !ok {
			i := r.Props["header.i"]
			if !strings.Contains(i, "@") {
				continue
			}
			d = domainOf(i)
		}
		if d = alabel(d); d != "" && (fd == d || strings.HasSuffix(fd, "."+d)) {
			return d
		}
	}
	return ""
}

// PlanSenders lists the newest PlanMails mails in every label but spam and
// trash, gets each one's From and Authentication-Results by the two plan
// calls, and returns only the set of domains PlanSender authenticates,
// sorted: no name, local part, subject or date leaves this function. A mail
// gone between the list and the get, or whose headers pass gPageMax, is
// skipped. A refused refresh is
// ErrReconnect (grant death) and any other failure an error: never a part
// of the senders.
func (g *Gmail) PlanSenders(ctx context.Context, authServ string) ([]string, error) {
	var ids []string
	page := ""
	for n := 0; n < gPlanPagesMax && len(ids) < PlanMails; n++ {
		var l struct {
			Messages []struct {
				ID string `json:"id"`
			} `json:"messages"`
			Next string `json:"nextPageToken"`
		}
		name, args := gPlanList, map[string]string{}
		if page != "" {
			name, args = gPlanListNext, map[string]string{"page": page}
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
	ids = ids[:min(len(ids), PlanMails)] // Gmail lists newest first
	var out []string
	for _, id := range ids {
		if !gmailID.MatchString(id) {
			return nil, errors.New("inbox: gmail: a message id outside Gmail's form")
		}
		var h gHeaders
		ans, bad := g.api.Call(ctx, gPlanMetadata, map[string]string{"id": id})
		if bad == clerk.DTooLarge || bad == "" && ans.Status == http.StatusNotFound {
			continue // gone, or headers a sender padded past gPageMax
		}
		if _, err := g.answer(ans, bad, &h); err != nil {
			return nil, err
		}
		if h.ID != id {
			return nil, errors.New("inbox: gmail: a mail's headers that name another mail")
		}
		var fs [][2]string
		for _, f := range h.Payload.Headers {
			fs = append(fs, [2]string{f.Name, f.Value})
		}
		if d := planSender(fs, authServ); d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out, nil
}
