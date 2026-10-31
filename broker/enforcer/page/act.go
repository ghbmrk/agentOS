package page

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
)

// actWords is each asserted action in the page's words.
var actWords = map[action.Act]string{
	action.On:     "Turn on",
	action.Open:   "Open",
	action.Fly:    "Fly",
	action.Unlock: "Unlock",
	action.Disarm: "Disarm",
	action.Off:    "Turn off",
	action.Arm:    "Arm",
}

// actConsequence is what approving an action does, in the page's words.
func actConsequence(a action.Act) string {
	switch a {
	case action.Off, action.Arm:
		return "This can stop the device's alerts to your phone. It happens as soon as you approve, once."
	}
	return "This happens as soon as you approve, once, and only within " + minutes(action.Window) + "."
}

// minutes is a whole-minute duration in the page's words. The screen
// names the window as a length, never as a clock time, so the owner never
// converts a time zone.
func minutes(d time.Duration) string {
	if n := int(d / time.Minute); n != 1 {
		return strconv.Itoa(n) + " minutes"
	}
	return "1 minute"
}

// action is the screen for an asserted action link (slice s): the act,
// drawn by the enforcer from the signed policy, and the once-only challenge
// one tap signs for exactly that act on that device in that window. Like a
// proposal link, opening it changes nothing; only the tap does.
func (s *Server) action(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, v := range q {
		if (k != "d" && k != "a" && k != "r") || len(v) != 1 {
			http.Error(w, errMalformed.Error(), http.StatusBadRequest)
			return
		}
	}
	s.mu.Lock()
	ok := s.limit(&s.acts)
	s.mu.Unlock()
	if !ok {
		http.Error(w, errLimited.Error(), http.StatusTooManyRequests)
		return
	}
	a := action.Act(q.Get("a"))
	if _, known := actWords[a]; !known {
		http.Error(w, errMalformed.Error(), http.StatusBadRequest)
		return
	}
	s.cfg.Lock.Lock()
	cur := s.cfg.Policy.Current()
	s.cfg.Lock.Unlock()
	c, err := s.book.Issue(cur, q.Get("d"), a, q.Get("r"), s.nowMS())
	switch err {
	case nil:
	case action.ErrLimited:
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	line := actWords[a] + " " + ascii(c.Device) + ", " + classWords(c.Class)
	if c.Route != "" {
		line += ", on the route " + ascii(c.Route)
	}
	s.render(w, "action.html", map[string]any{
		"Name":        s.cfg.Name,
		"Line":        line,
		"Window":      minutes(action.Window),
		"Consequence": actConsequence(a),
		"ID":          c.ID,
		"Challenge":   chal(c.Msg),
	})
}

// unsureWhy is why an act may have run, for the log: the actuator's error
// quoted, so it stays one line.
func unsureWhy(err error) string {
	if errors.Is(err, action.ErrTimeout) {
		return "no answer in time"
	}
	return strconv.Quote(strings.TrimPrefix(err.Error(), action.ErrUnsure.Error()+": "))
}

// do takes the owner's tap on an action challenge: the book spends the
// challenge whether or not the tap verifies, checks it against the policy
// in force and carries the act out at once. The policy lock is held until
// the act is done, so no change to the device lands in between, and never
// longer than the book's timeout (Config.ActTimeout), so a hung actuator
// cannot hold back the channel's relocks.
func (s *Server) do(w http.ResponseWriter, r *http.Request) {
	var a assertion
	if err := readJSON(r, &a); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	sig, flags, _ := parseAssertion(a) // a nil sig is refused, and spends the challenge
	s.cfg.Lock.Lock()
	c, err := s.book.Redeem(s.cfg.Policy.Current(), a.ID, sig, s.nowMS())
	s.cfg.Lock.Unlock()
	if errors.Is(err, action.ErrTimeout) || errors.Is(err, action.ErrUnsure) {
		// The act may have run: the owner's history shows it (NET-2).
		s.cfg.Log(fmt.Sprintf("action: %s on %s may have run: %s", c.Act, ascii(c.Device), unsureWhy(err)))
	}
	switch {
	case err == action.ErrGone:
		fail(w, http.StatusGone, err)
		return
	case err == action.ErrNotOwner:
		fail(w, http.StatusForbidden, err)
		return
	case err == action.ErrMoved:
		fail(w, http.StatusConflict, err)
		return
	case err == action.ErrTimeout:
		fail(w, http.StatusGatewayTimeout, err)
		return
	case err != nil:
		fail(w, http.StatusBadGateway, action.ErrUnsure)
		return
	}
	s.mu.Lock()
	s.synced(flags)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}
