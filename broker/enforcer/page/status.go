package page

import (
	"errors"
	"net/http"
	"net/netip"
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
// value is a resolver that runs and stays up.
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
	Unset []Unset
	// Policy is why the policy in force cannot be served; "" when it can.
	Policy string
	// Load is the last refused load's error, shown when no cause above
	// is: the instances stay as they were until a load is taken. LoadBy
	// is the step that refused it (#5164 R5 d).
	Load   string
	LoadBy LoadStep
	// Restarting is each instance that runs on the policy in force but
	// keeps exiting, shown while Stopped is false: a process that is up
	// between exits does not make it a resolver that runs (#5164 R5 b).
	Restarting []Restart
}

// LoadStep is the step of a load that refused it.
type LoadStep int

const (
	LoadUntyped  LoadStep = iota // a failure the load did not type
	LoadCompile                  // the enforcer could not make a ruleset of the policy
	LoadFirewall                 // the kernel's firewall refused the ruleset
)

// Restart is one resolver instance that has exited on its own Exits
// times in a row and has not stayed up since.
type Restart struct {
	Part  ResolverPart
	Iface string // PartListed: the one interface it answers on
	Exits int
}

// ResolverPart is what one resolver instance serves.
type ResolverPart int

const (
	PartUntyped ResolverPart = iota // an instance the daemon did not type
	PartListed                      // the listed names of the network on Iface
	PartPeople                      // any name on Owner, Household, Guests and admin
	PartDHCP                        // addresses on the networks set up for them
)

// Unset is one served-check failure other than a stray address, as the
// daemon's check typed it (#5284): the page words each kind, so a
// reworded log line cannot change what the owner reads. The zero value
// is a failure the check did not type, shown as one generic line.
type Unset struct {
	Kind UnsetKind
	// Iface is the interface: a served one, or for UnsetSetting also
	// "all" or "default"; for UnsetName, the setup's name that is not one.
	Iface string
	// Setting is the setting that was not turned off (UnsetSetting).
	Setting Setting
}

// UnsetKind is how a served interface is not as set up.
type UnsetKind int

const (
	UnsetUntyped UnsetKind = iota // a failure the check did not type
	UnsetSetting                  // a setting not turned off
	UnsetName                     // a setup name that is no interface name
	UnsetAddrs                    // addresses that could not be read
	UnsetChanged                  // addresses that changed while read
)

// Setting is a kernel setting the served check turns off.
type Setting int

const (
	SettingUntyped Setting = iota
	Redirects4             // ipv4 accept_redirects
	Redirects6             // ipv6 accept_redirects
	RouterAds              // ipv6 accept_ra
)

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
		} else if len(r.Restarting) > 0 {
			var lines []string
			for _, x := range r.Restarting {
				lines = append(lines, plainRestart(x))
			}
			out["Restarting"] = lines
		}
	}
	return out
}

// plainResolver is a stopped resolver as home shows it: every cause in
// printable ASCII, each Unset in the owner's words.
type plainResolver struct {
	Strays       []Stray
	Unset        []string
	Policy, Load string
	// The step that refused Load: compile, the firewall, or neither.
	Compile, Firewall bool
}

// plainStop is r in printable ASCII, as plain shows the core's names: a
// policy's error can quote a name the core chose.
func plainStop(r ResolverStop) plainResolver {
	out := plainResolver{Policy: sentence(r.Policy), Load: sentence(r.Load), Compile: r.LoadBy == LoadCompile, Firewall: r.LoadBy == LoadFirewall}
	for _, x := range r.Strays {
		out.Strays = append(out.Strays, Stray{Iface: ascii(x.Iface), Addr: x.Addr, Nets: sentence(x.Nets)})
	}
	for _, u := range r.Unset {
		if p := plainUnset(u); !slices.Contains(out.Unset, p) {
			out.Unset = append(out.Unset, p)
		}
	}
	return out
}

// unsetSettings names each setting the served check turns off as the
// owner reads it.
var unsetSettings = map[Setting]string{
	Redirects4: "IPv4 redirects",
	Redirects6: "IPv6 redirects",
	RouterAds:  "router advertisements",
}

// plainUnset is one served-check failure in the owner's words: what did
// not happen, what it leaves open, and when it is tried again (#5280),
// from its typed cause (#5284). Every name passes through ascii, or is
// quoted in ASCII, so none can read backwards or hide a word. A failure
// with no words (untyped, or a setting the page does not know) is one
// generic line pointing at the log.
func plainUnset(u Unset) string {
	iface := ascii(u.Iface)
	switch what := unsetSettings[u.Setting]; {
	case u.Kind == UnsetSetting && what != "" && u.Iface == "all":
		return "The enforcer could not turn off " + what + " for all interfaces at once, so a device on a home network could set a route the enforcer did not check. It tries again every 10 seconds."
	case u.Kind == UnsetSetting && what != "" && u.Iface == "default":
		return "The enforcer could not turn off " + what + " for interfaces made from now on, so a home network's interface made again could take a route or address the enforcer did not check. It tries again every 10 seconds."
	case u.Kind == UnsetSetting && what != "":
		return "The enforcer could not turn off " + what + " on interface " + iface + ", so a device on that network could set a route or address the enforcer did not check. It tries again every 10 seconds."
	case u.Kind == UnsetName:
		return "The enforcer's setup names " + strconv.QuoteToASCII(u.Iface) + " as a home network's interface, and that is not an interface name. Names and addresses stay stopped until the setup is corrected."
	case u.Kind == UnsetChanged:
		return "The addresses on interface " + iface + " changed while the enforcer read them. It reads them again within 10 seconds."
	case u.Kind == UnsetAddrs:
		return "The enforcer could not read the addresses on interface " + iface + ", so it cannot check that each lies in that network. It tries again every 10 seconds."
	}
	return "A home network's interface is not as set up, in a way this page has no words for; the enforcer's log has the detail. It checks again every 10 seconds."
}

// plainRestart is one instance that keeps exiting in the owner's words:
// what goes missing while it is down, how many times in a row, and that
// it is started again (dns/run backs off up to 30 seconds).
func plainRestart(r Restart) string {
	what := "Part of the enforcer's name and address service"
	switch r.Part {
	case PartListed:
		what = "The enforcer's name answers on interface " + ascii(r.Iface) + ", which only a listed name gets,"
	case PartPeople:
		what = "The enforcer's name answers on the Owner, Household and Guests networks"
	case PartDHCP:
		what = "The enforcer's address service, which hands out addresses on the home networks,"
	}
	times := ""
	if r.Exits > 1 {
		times = " " + strconv.Itoa(r.Exits) + " times in a row"
	}
	return what + " stopped on its own" + times + " and has not stayed up since. While it is down, that part of the house gets nothing from it. The enforcer starts it again each time, waiting longer after each stop, up to 30 seconds; its log has the detail."
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
