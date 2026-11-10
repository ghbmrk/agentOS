package page

import (
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Alerts is the enforcer's alert log as the page shows and clears it
// (alert.Alerts, slice h): every open alert, a silent core and the
// light's colour, and the owner's clear of one alert after a tap. The
// page is the record the core cannot drop or forge (NET-2 Texts and
// calls, KRN-12 Silence).
type Alerts interface {
	Status() Status
	Resolve(id uint64) error
}

// Status is what the page shows of the alerts (alert.Status).
type Status struct {
	Open     []Alert
	CoreDown bool
	Red      bool // the light: a trip at the enforcer is unresolved (D-254)
}

// Alert is one open alert: its fixed wording, when it was first raised,
// how often since, and whether the core took its text. Fixed is an alert
// only another step clears (a paused channel clears when it resumes).
// Revoke is one whose choice is to keep the core or revoke its key (the
// core's log forked from the copies: it may have been rolled back), so
// its card names that choice and leads to the revoke step.
type Alert struct {
	ID     uint64
	Text   string
	At     time.Time
	Count  int
	Sent   bool
	Fixed  bool
	Revoke bool
}

// Core is the core's channel sub-key as the page revokes it (heads
// ASSUMPTIONS ENF-h-1, KEY-7, STO-4's stolen core): the revocation
// reaches the enforcer at home, without the core.
type Core interface {
	// RevokeMsg is what owner's passkey signs to revoke the core's
	// sub-key: key.RootMsg(heads.SubKeyRoot(owner, sub)).
	RevokeMsg(owner key.PublicKey) []byte
	// Revoke revokes it on that signature; an error after which it is
	// revoked for this run only says so.
	Revoke(sig []byte) error
	// Revoked is whether the revocation is in force, and whether the
	// disk keeps it: one in force but not saved lasts only until the
	// enforcer restarts, so the page offers it again.
	Revoked() (revoked, saved bool)
}

// Caps is the byte caps' day when it does not read back (traffic
// ErrState, NET-2 Byte caps): every cap counts as spent, so nothing
// capped is reached, until the owner starts the day afresh. That forgets
// today's bytes, a loosening, so it waits policy.Wait like one and can be
// cancelled meanwhile (D-255).
type Caps interface {
	Day() CapsDay
	// Fresh approves a fresh day that starts policy.Wait after nowMS and
	// returns when; CancelFresh cancels one waiting. saved is false for a
	// step in force for this run that the disk has not yet confirmed: the
	// enforcer keeps saving it.
	Fresh(nowMS int64) (dueMS int64, saved bool, err error)
	CancelFresh() (saved bool, err error)
}

// CapsDay is the byte caps' day as the page shows it.
type CapsDay struct {
	Spent    bool  // the saved day did not read back: every cap counts as spent
	DueMS    int64 // a fresh day waits until then; 0: none waits
	Starting bool  // the wait is over: the fresh day is being saved and taken up
	Retrying bool  // the start's save failed and is tried again every second
	Unsaved  bool  // the owner's last approval or cancel is in force but not yet confirmed on disk
}

// Resolver is why the enforcer's resolver, its DNS and DHCP on every
// served network, is stopped: a served interface not as set up
// (ASSUMPTIONS ENF-l-21 at the daemon) or a policy in force it cannot
// serve (ENF-l-11). Every instance stops while either lasts, so home
// shows it (#5164 R1); the log alone would leave the owner a house
// without names or new addresses and no reason.
type Resolver interface {
	Stopped() ResolverStop
}

// ResolverStop is the resolver's state as the page shows it; the zero
// value is a resolver that runs.
type ResolverStop struct {
	// Stopped is whether no instance runs. The causes below are shown
	// only while it is, since a cause that has gone does not start the
	// instances: the load that does can still be refused.
	Stopped bool
	// Strays are the addresses on a served interface outside its
	// network, each with the interface: the resolver starts again at the
	// enforcer's next check after the last is gone.
	Strays []Stray
	// Unset is every other way the served interfaces are not as set up:
	// a setting that did not take, or addresses that could not be read.
	Unset []string
	// Policy is why the policy in force cannot be served; "" when it can.
	Policy string
	// Load is the last refused load's error, shown when no cause above
	// is: the instances stay as they were until a load is taken.
	Load string
}

// Stray is one address on a served interface outside its network.
type Stray struct {
	Iface string
	Addr  netip.Prefix // the address, with its prefix length
	Nets  string       // the network's prefixes it must lie in
}

// Edge is the edge box's cut (#5014, KRN-12): the edge past its daily
// byte cap reaches nothing through the enforcer until the owner lifts the
// cut here, after a tap.
type Edge interface {
	// Cut is whether the edge is cut, and why.
	Cut() (cut bool, reason string)
	// LiftEdge lifts it; an error leaves it cut.
	LiftEdge() error
}

// Page actions on the enforcer's own state, each after a tap of the
// passkey in force.
const (
	ActClear       = "clear"        // resolve one open alert (target: its ID)
	ActRevokeCore  = "revoke-core"  // revoke the core's channel sub-key
	ActFreshDay    = "fresh-day"    // approve a fresh byte-cap day, after the wait
	ActCancelFresh = "cancel-fresh" // cancel a fresh day waiting
	ActLiftEdge    = "lift-edge"    // lift the edge's cut
)

var (
	errNoAlert    = errors.New("no open alert with that number; open the home page again")
	errFixed      = errors.New("this alert clears when the channel resumes")
	errRevoked    = errors.New("the core's key is already revoked")
	errNotSpent   = errors.New("the byte caps' day reads back; there is nothing to start afresh")
	errFreshWaits = errors.New("a fresh day is already waiting")
	errNoFresh    = errors.New("no fresh day is waiting")
	errStarting   = errors.New("the fresh day is starting, so it can no longer be cancelled")
	errNotCut     = errors.New("the edge is not cut")
)

// stateChallenge checks that action can be drawn on the enforcer's state
// as it is now; ok is false for an action that is not one of these.
func (s *Server) stateChallenge(action, target string) (ok bool, code int, err error) {
	switch action {
	case ActClear:
		if s.cfg.Alerts == nil {
			return true, http.StatusNotFound, errMalformed
		}
		id, err := strconv.ParseUint(target, 10, 64)
		if err != nil {
			return true, http.StatusBadRequest, errMalformed
		}
		for _, a := range s.cfg.Alerts.Status().Open {
			if a.ID == id && a.Fixed {
				return true, http.StatusConflict, errFixed
			}
			if a.ID == id {
				return true, http.StatusOK, nil
			}
		}
		return true, http.StatusNotFound, errNoAlert
	case ActRevokeCore:
		if s.cfg.Core == nil || target != "" {
			return true, http.StatusNotFound, errMalformed
		}
		if revoked, saved := s.cfg.Core.Revoked(); revoked && saved {
			return true, http.StatusConflict, errRevoked
		}
		return true, http.StatusOK, nil
	case ActFreshDay, ActCancelFresh:
		if s.cfg.Caps == nil || target != "" {
			return true, http.StatusNotFound, errMalformed
		}
		day := s.cfg.Caps.Day()
		switch {
		case !day.Spent:
			return true, http.StatusConflict, errNotSpent
		case day.Starting:
			return true, http.StatusConflict, errStarting
		case action == ActFreshDay && day.DueMS != 0:
			return true, http.StatusConflict, errFreshWaits
		case action == ActCancelFresh && day.DueMS == 0:
			return true, http.StatusNotFound, errNoFresh
		}
		return true, http.StatusOK, nil
	case ActLiftEdge:
		if s.cfg.Edge == nil || target != "" {
			return true, http.StatusNotFound, errMalformed
		}
		if cut, _ := s.cfg.Edge.Cut(); !cut {
			return true, http.StatusConflict, errNotCut
		}
		return true, http.StatusOK, nil
	}
	return false, 0, nil
}

// stateAct does action after the owner's tap; res is the answer's extra
// fields.
func (s *Server) stateAct(c *challenge, sig []byte) (res map[string]any, err error) {
	switch c.kind {
	case ActClear:
		id, _ := strconv.ParseUint(c.target, 10, 64) // checked when drawn
		err = s.cfg.Alerts.Resolve(id)
	case ActRevokeCore:
		err = s.cfg.Core.Revoke(sig)
	case ActFreshDay:
		due, saved, ferr := s.cfg.Caps.Fresh(s.nowMS())
		if err = ferr; err == nil {
			res = map[string]any{"due": s.when(due), "saved": saved}
		}
	case ActCancelFresh:
		saved, cerr := s.cfg.Caps.CancelFresh()
		if err = cerr; err == nil {
			res = map[string]any{"saved": saved}
		}
	case ActLiftEdge:
		err = s.cfg.Edge.LiftEdge()
	}
	return res, err
}

// status is the home page's view of the enforcer's own state.
func (s *Server) status() map[string]any {
	out := map[string]any{}
	if s.cfg.Alerts != nil {
		st := s.cfg.Alerts.Status()
		out["Alerts"], out["CoreDown"], out["Red"], out["Shown"] = st.Open, st.CoreDown, st.Red, true
		out["Fork"] = slices.ContainsFunc(st.Open, func(a Alert) bool { return a.Revoke })
	}
	if s.cfg.Core != nil {
		revoked, saved := s.cfg.Core.Revoked()
		out["Core"], out["Revoked"], out["RevokeUnsaved"] = true, revoked && saved, revoked && !saved
	}
	if s.cfg.Edge != nil {
		if cut, why := s.cfg.Edge.Cut(); cut {
			out["EdgeCut"] = why
		}
	}
	if s.cfg.Caps != nil {
		if day := s.cfg.Caps.Day(); day.Spent {
			out["Caps"] = day
			if day.DueMS != 0 {
				out["FreshDue"] = s.when(day.DueMS)
			}
		}
	}
	if s.cfg.Resolver != nil {
		if r := s.cfg.Resolver.Stopped(); r.Stopped {
			out["Resolver"] = plainStop(r)
		}
	}
	return out
}

// plainStop is r in printable ASCII, as plain shows the core's names: a
// policy's error can quote a name the core chose.
func plainStop(r ResolverStop) ResolverStop {
	out := ResolverStop{Stopped: true, Policy: sentence(r.Policy), Load: sentence(r.Load)}
	for _, x := range r.Strays {
		out.Strays = append(out.Strays, Stray{Iface: ascii(x.Iface), Addr: x.Addr, Nets: sentence(x.Nets)})
	}
	for _, u := range r.Unset {
		if p := sentence(plainUnset(u)); !slices.Contains(out.Unset, p) {
			out.Unset = append(out.Unset, p)
		}
	}
	return out
}

// The served check's errors, as the enforcer's hold writes them
// (cmd/agentos-enforcer, network.go). A kernel interface name is at most
// 15 bytes with no slash, colon or space, so a name the pattern takes
// cannot carry the rest of the line.
var (
	unsetKey   = regexp.MustCompile(`^/proc/sys/net/(ipv4|ipv6)/conf/([^/:\s]{1,15})/(accept_redirects|accept_ra) not set to 0 \(reads `)
	unsetName  = regexp.MustCompile(`^served interface ("(?:[^"\\]|\\.)*"): not an interface name$`)
	unsetAddrs = regexp.MustCompile(`(?s)^served interface ([^/:\s]{1,15}): addresses: (.*)$`)
	madeAgain  = regexp.MustCompile(`^interface [^/:\s]{1,15} was made again while its addresses were read \(`)
)

// unsetSettings names each setting hold turns off as the owner reads it.
var unsetSettings = map[string]string{
	"ipv4 accept_redirects": "IPv4 redirects",
	"ipv6 accept_redirects": "IPv6 redirects",
	"ipv6 accept_ra":        "router advertisements",
}

// plainUnset is one served-check error in the owner's words: what did
// not happen, what it leaves open, and when it is tried again (#5280).
// An error it has no words for is one generic line, never the raw text,
// which reads as the kernel's and not the owner's.
func plainUnset(u string) string {
	if m := unsetKey.FindStringSubmatch(u); m != nil {
		what := unsetSettings[m[1]+" "+m[3]]
		switch iface := m[2]; {
		case what == "":
		case iface == "all":
			return "The enforcer could not turn off " + what + " for all interfaces at once, so a device on a home network could set a route the enforcer did not check. It tries again every 10 seconds."
		case iface == "default":
			return "The enforcer could not turn off " + what + " for interfaces made from now on, so a home network's interface made again could take a route or address the enforcer did not check. It tries again every 10 seconds."
		default:
			return "The enforcer could not turn off " + what + " on interface " + ascii(iface) + ", so a device on that network could set a route or address the enforcer did not check. It tries again every 10 seconds."
		}
	}
	if m := unsetName.FindStringSubmatch(u); m != nil {
		if name, err := strconv.Unquote(m[1]); err == nil {
			return "The enforcer's setup names " + ascii(name) + " as a home network's interface, and that is not an interface name. Names and addresses stay stopped until the setup is corrected."
		}
	}
	if m := unsetAddrs.FindStringSubmatch(u); m != nil {
		iface := ascii(m[1])
		if madeAgain.MatchString(m[2]) || m[2] == "the kernel's address dump was interrupted by a change" {
			return "The addresses on interface " + iface + " changed while the enforcer read them. It reads them again within 10 seconds."
		}
		return "The enforcer could not read the addresses on interface " + iface + ", so it cannot check that each lies in that network. It tries again every 10 seconds."
	}
	return "A home network's interface is not as set up, in a way this page has no words for; the enforcer's log has the detail. It checks again every 10 seconds."
}

// sentence is s with every character outside printable ASCII and the
// space escaped (U+202E reads \u202e), so no line it is in can read
// backwards or hide a word.
func sentence(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			q := strconv.QuoteRuneToASCII(c)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}
