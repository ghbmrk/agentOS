package nft

// REQ: NET-3

import (
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

var (
	markSet  = regexp.MustCompile(` ct mark set 0x[0-9a-f]{8}`)
	markLine = regexp.MustCompile(`^(?:ct direction (original|reply) )?iifname ("[^"]+") oifname ("[^"]+") .*ct mark (?:set )?(0x[0-9a-f]{8}) `)
)

// chains splits a compiled ruleset into its chains' rule lines.
func chains(text string) map[string][]string {
	out := map[string][]string{}
	var cur string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "chain "):
			cur = strings.TrimSuffix(strings.TrimPrefix(l, "chain "), " {")
		case l == "}":
			cur = ""
		case cur != "" && l != "" && !strings.HasPrefix(l, "type "):
			out[cur] = append(out[cur], l)
		}
	}
	return out
}

// NET-3, NET-2 Device paths (#4286): every accept in the forward and people
// chains binds its connection to its own interface pair, and every live
// accept passes only a connection with that pair's mark, in both
// directions. The mark is one value per interface pair, never shared by
// two, and a load that keeps a path keeps its mark, so adding or removing
// another device neither cuts a kept connection nor hands its mark to
// another path. Catches an accept added without a binding, which would let
// a segment with the same exit forge a related packet into its connections.
func TestEveryAcceptBound(t *testing.T) {
	more := fixturePolicy()
	more.Devices = append(more.Devices[:2:2], more.Devices[3:]...) // the plug removed
	more.Devices = append(more.Devices, policy.Device{ID: "far", Network: policy.NetDevices, WiFi: "vlan4094", Allow: []string{"far.example"}, VendorCloud: true})
	byPair := map[string]string{} // mark -> "in out", across both documents
	lines := map[string]bool{}    // every TV line of the fixture
	for i, d := range []policy.Document{fixturePolicy(), more} {
		text, err := Compile(d, fixtureLayout())
		if err != nil {
			t.Fatal(err)
		}
		cs := chains(text)
		for _, chain := range []string{"forward", "people", "forward_live", "people_live"} {
			if len(cs[chain]) == 0 {
				t.Fatalf("no chain %s", chain)
			}
			for _, l := range cs[chain] {
				live := strings.HasSuffix(chain, "_live")
				accepts := (!live && strings.HasSuffix(l, " accept") && !strings.HasPrefix(l, "ct state ")) || (live && strings.HasSuffix(l, " return"))
				if !accepts {
					if strings.Contains(l, "ct mark") {
						t.Errorf("%s: a rule that does not accept touches the mark: %s", chain, l)
					}
					continue
				}
				m := markLine.FindStringSubmatch(l)
				if m == nil {
					t.Errorf("%s: an accept without its interface pair's mark: %s", chain, l)
					continue
				}
				in, out := m[2], m[3]
				if m[1] == "reply" {
					in, out = out, in
				}
				if live != strings.Contains(l, " ct mark 0x") || !live != strings.Contains(l, " ct mark set 0x") {
					t.Errorf("%s: wrong mark form: %s", chain, l)
				}
				pair := in + " " + out
				if was, ok := byPair[m[4]]; ok && was != pair {
					t.Errorf("mark %s is both %s and %s", m[4], was, pair)
				}
				byPair[m[4]] = pair
				if strings.Contains(l, `"ap0.101"`) {
					if i == 0 {
						lines[chain+": "+l] = true
					} else if !lines[chain+": "+l] {
						t.Errorf("adding and removing other devices changed the TV's rule: %s", l)
					}
				}
			}
		}
	}
	if len(lines) == 0 {
		t.Fatal("the fixture has no TV rule")
	}
	if len(byPair) == 0 {
		t.Fatal("no marks")
	}
}
