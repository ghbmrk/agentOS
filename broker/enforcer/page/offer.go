package page

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// errNoOffer: the home page's offer for a device is gone, because what
// the enforcer hears or the policy in force changed since it was drawn.
var errNoOffer = errors.New("nothing new is heard for this device now; open the home page again")

// offer is names the enforcer heard proved their own after a device's
// pair was signed, which the home page offers to add to that device in
// one change of their own (#4566): what a Devices-network device
// announces, or names heard on the Owner or Household network, held for
// one of its devices (#4411).
type offer struct {
	ID    string
	Names [][]string
	More  int // heard but left out of this offer (maxFill)
}

// Line is the offer as the home page asks it.
func (o offer) Line(cur policy.Document) string {
	var ns []string
	for _, n := range o.Names {
		ns = append(ns, ascii(policy.MDNSName(n)))
	}
	names := strings.Join(ns, ", ")
	if o.More > 0 {
		names += " and more"
	}
	if d := cur.Device(o.ID); d != nil && d.Network != policy.NetDevices {
		them := "them"
		if len(o.Names) == 1 && o.More == 0 {
			them = "it"
		}
		return "The " + d.Network + " network now announces " + names + ": hold " + them + " for " + ascii(o.ID) + ", so no paired device may announce " + them + "?"
	}
	return ascii(o.ID) + " now announces " + names + ": let it?"
}

// offers is what the home page offers under cur: for each device on a
// pair with a path, the names heard where it is heard (heardOn) that no
// device pins or holds, hosts first and at most maxFill. A person's
// network is offered once, on the first of its devices with such a pair,
// since its names are the network's.
func (s *Server) offers(cur policy.Document) []offer {
	var out []offer
	seen := map[string]bool{}
	for _, d := range cur.Devices {
		if !slices.ContainsFunc(cur.Pairs, func(p policy.Pair) bool {
			return (p.A == d.ID || p.B == d.ID) && cur.Linked(p.A) && cur.Linked(p.B)
		}) {
			continue
		}
		if d.Network != policy.NetDevices {
			if seen[d.Network] {
				continue
			}
			seen[d.Network] = true
		}
		if ns, more := fresh(cur, s.heardOn(cur, d)); len(ns) > 0 {
			out = append(out, offer{ID: d.ID, Names: ns, More: more})
		}
	}
	return out
}

// offered draws the change a home page offer asks for (GET /heard?d=ID):
// the policy in force with the names the enforcer offers for that device
// now added, on the confirm screen with its own passkey tap, as a link's
// change is. Nothing in it comes from the core. s.mu is held.
func (s *Server) offered(r *http.Request) (*challenge, []string, error) {
	q := r.URL.Query()
	if len(q) != 1 || len(q["d"]) != 1 {
		return nil, nil, errMalformed
	}
	s.cfg.Lock.Lock()
	cur, pend := s.cfg.Policy.Current(), s.cfg.Policy.Pending()
	s.cfg.Lock.Unlock()
	offs := s.offers(cur)
	i := slices.IndexFunc(offs, func(o offer) bool { return o.ID == q["d"][0] })
	if i < 0 {
		return nil, nil, errNoOffer
	}
	next := clone(cur)
	d := next.Device(offs[i].ID)
	d.MDNS = append(d.MDNS, offs[i].Names...)
	var notes []string
	if offs[i].More > 0 {
		notes = append(notes, leftLine(*d, offs[i].More))
	}
	return s.drawn(cur, pend, next, nil, notes)
}
