package localui

import (
	"fmt"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// lineTexts says, in fixed words, what the owner line's last outage and
// the bridge's counts mean for the owner's texts (P2-2w d2a, UX U-B1,
// UX-170-1). The outage reads as the recovery text did (modemlink).
// Times are the box's (loc). A line that is fine has none.
func lineTexts(l localapi.Line, loc *time.Location) []string {
	var out []string
	if o := l.Outage; o != nil {
		const layout = "Jan 2 15:04"
		what := "Nothing was missed."
		if o.Missed > 0 {
			what = plural(o.Missed, "text", "texts")
			if o.Requests > 0 {
				what = plural(o.Requests, "approval request", "approval requests")
				if rest := o.Missed - o.Requests; rest > 0 {
					what += " and " + plural(rest, "other text", "other texts")
				}
			}
			what += " didn't reach you"
			if o.Requests > 0 {
				what += "; your agent can ask again"
			}
			what += "."
		}
		out = append(out, fmt.Sprintf("Last time I couldn't text you: %s to %s. %s", o.From.In(loc).Format(layout), o.To.In(loc).Format(layout), what))
	}
	if n := l.Others; n > 0 {
		s := "Since I started, 1 text to my number came from a number other than yours. I set it aside unread."
		if n > 1 {
			s = fmt.Sprintf("Since I started, %d texts to my number came from numbers other than yours. I set them aside unread.", n)
		}
		out = append(out, s)
	}
	if n := l.TimedOut; n > 0 {
		s := "Since I started, 1 text to you may not have gone: my phone modem didn't confirm it."
		if n > 1 {
			s = fmt.Sprintf("Since I started, %d texts to you may not have gone: my phone modem didn't confirm them.", n)
		}
		out = append(out, s)
	}
	if l.Dropped {
		out = append(out, "Since I started, some texts to me were dropped because too many came at once.")
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
