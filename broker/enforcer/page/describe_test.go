package page

// REQ: NET-4, NET-2, NET-3, NET-7

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// wantLines checks that lines hold each of want, in want's order, and none
// of never.
func wantLines(t *testing.T, name string, lines, want, never []string) {
	t.Helper()
	at := -1
	for _, w := range want {
		i := slices.Index(lines, w)
		if i < 0 {
			t.Errorf("%s: no line %q in:\n%s", name, w, strings.Join(lines, "\n"))
			continue
		}
		if i < at {
			t.Errorf("%s: %q out of order in:\n%s", name, w, strings.Join(lines, "\n"))
		}
		at = i
	}
	for _, n := range never {
		for _, l := range lines {
			if strings.Contains(l, n) {
				t.Errorf("%s: a line says %q: %q", name, n, l)
			}
		}
	}
}

// NET-4 Loosening: every kind of change the owner signs is said, in both
// directions, so a change that removes, cuts or revokes something is never
// signed unseen. Each case is old to next and the lines that must show.
func TestDescribeEveryDirection(t *testing.T) {
	pairs := func(ps ...policy.Pair) func(d *policy.Document) {
		return func(d *policy.Document) { d.Pairs = ps }
	}
	camTV, camLock := policy.Pair{A: "cam", B: "tv"}, policy.Pair{A: "cam", B: "lock"}
	rule := policy.StandingRule{ID: "visitor", Device: "lock", Action: "unlock", FromMS: 0, ToMS: 60_000}
	for _, c := range []struct {
		name      string
		old, next policy.Document
		want      []string
		never     []string
	}{
		{name: "destinations added, sorted",
			old: home(1), next: edit(2, func(d *policy.Document) { d.Destinations = []string{"models.example", "z.example", "b.example"} }),
			want: []string{"Let agentOS reach b.example.", "Let agentOS reach z.example."}},
		{name: "destination removed",
			old: home(1), next: edit(2, func(d *policy.Document) { d.Destinations = nil }),
			want: []string{"Stop agentOS reaching models.example."}},
		{name: "device removed",
			old: home(1), next: edit(2, func(d *policy.Document) { d.Devices = d.Devices[1:] }),
			want:  []string{"Remove the device cam: it loses all network access, its pairs and its standing rules."},
			never: []string{"Remove the device lock", "Remove the device tv"}},
		{name: "pair added beside one kept",
			old: edit(1, pairs(camLock)), next: edit(2, pairs(camLock, camTV)),
			want:  []string{"Let cam and tv talk to each other directly."},
			never: []string{"Let cam and lock talk", "Stop cam and lock talking"}},
		{name: "pair removed",
			old: edit(1, pairs(camLock, camTV)), next: edit(2, pairs(camLock)),
			want:  []string{"Stop cam and tv talking to each other directly."},
			never: []string{"cam and lock"}},
		// A new pair whose end gains its path in the same change is said
		// once, as new, never as a path that returns.
		{name: "new pair, end newly linked",
			old: edit(1, func(d *policy.Document) { dev(d, "tv").Isolated = true }), next: edit(2, pairs(camTV)),
			want:  []string{"End tv's isolation: its allow list and pairs apply again.", "Let cam and tv talk to each other directly."},
			never: []string{"talk to each other again"}},
		{name: "standing rule revoked",
			old: edit(1, func(d *policy.Document) { d.Standing = []policy.StandingRule{rule} }), next: home(2),
			want: []string{"Revoke the standing rule visitor (unlock on lock)."}},
		{name: "holds set",
			old: home(1), next: edit(2, func(d *policy.Document) {
				d.Holds = []policy.Hold{{Device: "cam", Kind: policy.HoldFix}, {Device: "tv", Kind: policy.HoldFirmware}}
			}),
			want: []string{"Hold back security fixes for cam: it stays open to the flaws they fix.", "Freeze tv's firmware: it gets no updates, security fixes included."}},
		{name: "holds lifted",
			old: edit(1, func(d *policy.Document) {
				d.Holds = []policy.Hold{{Device: "cam", Kind: policy.HoldFix}, {Device: "tv", Kind: policy.HoldFirmware}}
			}), next: home(2),
			want: []string{"Stop holding back security fixes for cam.", "Unfreeze tv's firmware."}},
		{name: "vendor cloud cut, isolation ended, safety list both ways",
			old: edit(1, func(d *policy.Document) { dev(d, "tv").Isolated = true }),
			next: edit(2, func(d *policy.Document) {
				dev(d, "cam").VendorCloud = false
				dev(d, "tv").Everyday = false
				dev(d, "lock").Everyday = true
			}),
			want: []string{
				"Cut cam off from its vendor's cloud: features and alerts that need the cloud stop.",
				"Take lock off the safety list: agentOS may then switch it without asking you.",
				"End tv's isolation: its allow list and pairs apply again.",
				"Put tv on the safety list: it acts only on your passkey here at home.",
			}},
		{name: "ports closed",
			old: edit(1, func(d *policy.Document) {
				dev(d, "cam").Control = []policy.Port{{Proto: policy.ProtoTCP, Num: 80}}
				dev(d, "cam").Stream = []policy.Port{{Proto: policy.ProtoUDP, Num: 5000}}
			}), next: home(2),
			want: []string{"Close cam's control port tcp 80.", "Stop agentOS receiving cam's video or audio on udp 5000."}},
		{name: "wired everyday device added",
			old: home(1), next: edit(2, func(d *policy.Document) {
				d.Devices = append(d.Devices, policy.Device{ID: "plug", Network: policy.NetDevices, Everyday: true})
			}),
			want: []string{"Add the device plug to the devices network, wired. It is an everyday device: agentOS may switch it without asking you."}},
		{name: "classes in words",
			old: home(1), next: edit(2, func(d *policy.Document) {
				d.Devices = append(d.Devices,
					policy.Device{ID: "door", Network: policy.NetDevices, WiFi: "vlan110", Class: policy.ClassGarageDoor},
					policy.Device{ID: "thing", Network: policy.NetDevices, WiFi: "vlan111"})
			}),
			want: []string{
				"Add the device door to the devices network, with its own Wi-Fi identity vlan110. It is on the safety list as a garage door: it acts only on your passkey here at home.",
				"Add the device thing to the devices network, with its own Wi-Fi identity vlan111. It is on the safety list as a device of unknown type: it acts only on your passkey here at home.",
			}},
	} {
		wantLines(t, c.name, Describe(c.old, c.next, zone), c.want, c.never)
	}
}

// NET-4: a name the core chose is shown quoted with escapes wherever it
// appears, in a device's, a pair's, a standing rule's and a hold's line, so
// none can reorder what the owner reads; and Describe never writes into
// the documents it is given.
func TestDescribeQuotesEveryName(t *testing.T) {
	const bad = "x\u202ey"
	q := strconv.QuoteToASCII(bad)
	mk := func() policy.Document {
		return edit(2, func(d *policy.Document) {
			d.Destinations = append(d.Destinations, "d\u202e")
			d.Devices = append(d.Devices, policy.Device{ID: bad, Network: policy.NetDevices, WiFi: "w\u202e", Allow: []string{"a\u202e"}, Class: "c\u202e", Secure: "s\u202e"})
			d.Pairs = []policy.Pair{{A: "cam", B: bad}}
			d.Standing = []policy.StandingRule{{ID: "r\u202e", Device: bad, Action: "on", ToMS: 60_000}}
			d.Holds = []policy.Hold{{Device: bad, Kind: policy.HoldFix}}
		})
	}
	next, before := mk(), mk()
	lines := Describe(home(1), next, zone)
	wantLines(t, "added", lines, []string{
		"Add the device " + q + " to the devices network, with its own Wi-Fi identity " + strconv.QuoteToASCII("w\u202e") +
			". It is on the safety list as a " + strconv.QuoteToASCII("c\u202e") + ": it acts only on your passkey here at home.",
		"Let " + q + "'s command " + strconv.QuoteToASCII("s\u202e") + " apply at once, with no passkey.",
		"Let cam and " + q + " talk to each other directly.",
		"Add the standing rule " + strconv.QuoteToASCII("r\u202e") + ": on on " + q + ", " + window(policy.StandingRule{ToMS: 60_000}, zone) + ". The enforcer applies it by itself in that window.",
		"Hold back security fixes for " + q + ": it stays open to the flaws they fix.",
	}, []string{"\u202e"})
	if !reflect.DeepEqual(next, before) {
		t.Errorf("Describe changed the document it was given:\n%+v\nwas\n%+v", next, before)
	}
	gone := Describe(next, home(3), zone)
	wantLines(t, "removed", gone, []string{
		"Stop agentOS reaching " + strconv.QuoteToASCII("d\u202e") + ".",
		"Remove the device " + q + ": it loses all network access, its pairs and its standing rules.",
		"Stop cam and " + q + " talking to each other directly.",
		"Revoke the standing rule " + strconv.QuoteToASCII("r\u202e") + " (on on " + q + ").",
		"Stop holding back security fixes for " + q + ".",
	}, []string{"\u202e"})
	if !reflect.DeepEqual(next, before) {
		t.Errorf("Describe changed the old document it was given:\n%+v\nwas\n%+v", next, before)
	}
}

// clone shares no slice with the document it copies, so plain and heard
// can write into the copy.
func TestCloneSharesNothing(t *testing.T) {
	mk := func() policy.Document {
		d := home(1)
		d.Pairs = []policy.Pair{{A: "cam", B: "tv"}}
		d.Standing = []policy.StandingRule{{ID: "r", Device: "lock", Action: "unlock"}}
		d.Holds = []policy.Hold{{Device: "cam", Kind: policy.HoldFix}}
		v := dev(&d, "cam")
		v.Control = []policy.Port{{Proto: policy.ProtoTCP, Num: 80}}
		v.Stream = []policy.Port{{Proto: policy.ProtoUDP, Num: 5000}}
		v.MDNS = [][]string{{"cam", "local"}}
		v.Safeguards = []string{policy.SafeguardPreCloseWarning}
		return d
	}
	d, was := mk(), mk()
	c := clone(d)
	c.Destinations[0] = "other"
	cv := &c.Devices[0]
	cv.ID, cv.Allow[0], cv.Control[0].Num, cv.Stream[0].Num, cv.MDNS[0], cv.Safeguards[0] = "x", "x", 1, 1, []string{"x"}, "x"
	c.Pairs[0].A, c.Standing[0].ID, c.Holds[0].Device = "x", "x", "x"
	if !reflect.DeepEqual(d, was) {
		t.Errorf("a write into the clone reached the original:\n%+v\nwas\n%+v", d, was)
	}
}
