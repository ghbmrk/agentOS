package kernel_test

// REQ: KRN-12, DEV-2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/decoy"
	"github.com/ghbmrk/agentos/broker/hostiletext"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/ipform"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// The address corpus, differentially (#4910, #4037): for each decoy
// destination of one logged table, ipform.Forms, netguard's connect-time
// check given that table's matcher, and the kernel's plan check (destOf,
// on a bare address, an address and port, and a URL) each find the decoy
// in every form that carries it and in no near miss, and all of them agree
// on every entry. Catches one of the three checks reading an address form
// the others read differently, which is how #4037's zoned NAT64, 6to4 and
// ISATAP forms got through.
func TestDecoyChecksAgreeOnTheAddressCorpus(t *testing.T) {
	r := newRig(t)
	tb := r.decoys()
	m := tb.Matcher()
	guard := netguard.New(netguard.Config{
		Decoy: func(a netip.Addr) bool { _, ok := m.Dest(a); return ok },
		Connect: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no connect in this test")
		},
	})
	n := 0
	// plans is whether the kernel refuses a plan whose one step names text
	// as a decoy destination, in a fresh session so no earlier trip decides.
	plans := func(text string) bool {
		n++
		s, id := fmt.Sprintf("s%d", n), fmt.Sprintf("p%d", n)
		must(t, r.k.OpenTask(int64(n), s, 0))
		before := len(r.k.State().Trips())
		r.plan(id, r.serve(s), st(key.Organize, text))
		ts := r.k.State().Trips()
		return r.k.State().Plans[id].Reject == kernel.CTrip && len(ts) == before+1 && ts[before].Cause == kernel.CauseDest
	}
	wrap := func(text string) []string {
		a := netip.MustParseAddr(text)
		if a.Is4() {
			return []string{text, text + ":443", "http://" + text + "/"}
		}
		return []string{text, "[" + text + "]:443", "http://[" + strings.ReplaceAll(text, "%", "%25") + "]/latest/meta-data/"}
	}
	for _, target := range []netip.Addr{decoy.Metadata, entry(t, tb, decoy.PSandboxEnv).Dest} {
		views := map[string]func(string) bool{
			"ipform.Forms": func(text string) bool {
				return slices.Contains(ipform.Forms(netip.MustParseAddr(text)), target)
			},
			"netguard Check": func(text string) bool {
				var de *netguard.DeniedError
				err := guard.Check(context.Background(), netip.MustParseAddr(text), 443, "tcp")
				return errors.As(err, &de) && de.Reason == netguard.ReasonDecoy
			},
		}
		for i, how := range []string{"bare", "address and port", "URL"} {
			views["kernel plan, "+how] = func(text string) bool { return plans(wrap(text)[i]) }
		}
		names := slices.Sorted(func(yield func(string) bool) {
			for k := range views {
				if !yield(k) {
					return
				}
			}
		})
		got := map[string]map[string]bool{}
		for _, v := range names {
			got[v] = map[string]bool{}
			hostiletext.RunAddrs(t, target, func(text string) bool {
				got[v][text] = views[v](text)
				return got[v][text]
			})
		}
		for _, a := range hostiletext.Addrs(target) {
			var say []string
			for _, v := range names {
				say = append(say, fmt.Sprintf("%s=%t", v, got[v][a.Text]))
			}
			for _, v := range names[1:] {
				if got[v][a.Text] != got[names[0]][a.Text] {
					t.Errorf("%s %q (%s): the checks disagree: %s", target, a.Text, a.Name, strings.Join(say, ", "))
					break
				}
			}
		}
	}
}
