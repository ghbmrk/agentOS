package page

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// Describe is the change from old to next in plain words, one line each,
// with what each line does to the home. It reads only the two documents,
// never anything agentOS says about them, so the core cannot show the owner
// a false diff (NET-4 Loosening). The lines, joined, are the diff a
// version's key commits to (policy.Proposal.Diff). Times are in zone, the
// owner's.
func Describe(old, next policy.Document, zone *time.Location) []string {
	old, next = plain(old), plain(next)
	var out []string
	add := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }

	for _, h := range minus(next.Destinations, old.Destinations) {
		add("Let agentOS reach %s.", h)
	}
	for _, h := range minus(old.Destinations, next.Destinations) {
		add("Stop agentOS reaching %s.", h)
	}
	for _, d := range next.Devices {
		o := old.Device(d.ID)
		if o == nil {
			add("Add the device %s to the %s network%s. %s", d.ID, d.Network, wifi(d.WiFi), safety(d))
			for _, h := range d.Allow {
				add("Let %s reach %s.", d.ID, h)
			}
			if d.VendorCloud {
				add("Let %s reach its vendor's cloud.", d.ID)
			}
			if d.Isolated {
				add("Keep %s isolated: it reaches nothing.", d.ID)
			}
			if d.Secure != "" {
				add("Let %s's command %s apply at once, with no passkey.", d.ID, d.Secure)
			}
			add("Label %s %s.", d.ID, labelWords(d.Label))
			describePorts(policy.Device{ID: d.ID}, d, add)
			continue
		}
		describeDevice(*o, d, add)
	}
	for _, d := range old.Devices {
		if next.Device(d.ID) == nil {
			add("Remove the device %s: it loses all network access, its pairs and its standing rules.", d.ID)
		}
	}
	for _, p := range pairsMinus(next.Pairs, old.Pairs) {
		add("Let %s and %s talk to each other directly.", p.A, p.B)
	}
	for _, p := range pairsMinus(old.Pairs, next.Pairs) {
		add("Stop %s and %s talking to each other directly.", p.A, p.B)
	}
	for _, r := range next.Standing {
		i := slices.IndexFunc(old.Standing, func(o policy.StandingRule) bool { return o.ID == r.ID })
		switch {
		case i < 0:
			add("Add the standing rule %s: %s on %s, %s. The enforcer applies it by itself in that window.", r.ID, r.Action, r.Device, window(r, zone))
		case old.Standing[i] != r:
			o := old.Standing[i]
			add("Change the standing rule %s from %s on %s, %s, to %s on %s, %s.", r.ID, o.Action, o.Device, window(o, zone), r.Action, r.Device, window(r, zone))
		}
	}
	for _, r := range old.Standing {
		if !slices.ContainsFunc(next.Standing, func(n policy.StandingRule) bool { return n.ID == r.ID }) {
			add("Revoke the standing rule %s (%s on %s).", r.ID, r.Action, r.Device)
		}
	}
	for _, h := range holdsMinus(next.Holds, old.Holds) {
		add("%s", holdWords(h, true))
	}
	for _, h := range holdsMinus(old.Holds, next.Holds) {
		add("%s", holdWords(h, false))
	}
	// NET-3, NET-7: a hold, an isolation or a lost Wi-Fi identity cuts a
	// signed pair's path without removing the pair, so say which pairs
	// stop, start again, or are signed without a path.
	for _, p := range next.Pairs {
		is := next.Linked(p.A) && next.Linked(p.B)
		if !slices.Contains(old.Pairs, p) {
			if !is {
				add("%s and %s cannot talk to each other while %s.", p.A, p.B, unlinked(next, p))
			}
			continue
		}
		switch was := old.Linked(p.A) && old.Linked(p.B); {
		case was && !is:
			add("%s and %s stop talking to each other while %s.", p.A, p.B, unlinked(next, p))
		case !was && is:
			add("%s and %s talk to each other again.", p.A, p.B)
		}
	}
	// NET-7: a lock or an alarm is held only on a screen that names the
	// risk; the policy refuses a diff without one line per such hold.
	for _, h := range policy.RiskHolds(old, next) {
		add("Risk of holding back %s's updates: %s", h.Device, policy.Risk(next.Device(h.Device).Class))
	}
	if old.Drone != next.Drone {
		switch {
		case next.Drone == "":
			add("Remove the drone flight policy: the drone stays docked.")
		default:
			add("Use the drone flight policy %s.", next.Drone)
		}
	}
	if len(out) == 0 {
		add(noChange)
	}
	return out
}

// plain is d with every name the core chose shown in printable ASCII: one
// with any other character, such as a right-to-left override that would
// make a line read backwards, is shown quoted with escapes. The mapping is
// one to one, so equal names stay equal.
func plain(d policy.Document) policy.Document {
	d = clone(d)
	d.Drone = ascii(d.Drone)
	for i := range d.Destinations {
		d.Destinations[i] = ascii(d.Destinations[i])
	}
	for i := range d.Devices {
		v := &d.Devices[i]
		v.ID, v.WiFi, v.Class, v.Secure = ascii(v.ID), ascii(v.WiFi), ascii(v.Class), ascii(v.Secure)
		for j := range v.Allow {
			v.Allow[j] = ascii(v.Allow[j])
		}
	}
	for i := range d.Pairs {
		d.Pairs[i].A, d.Pairs[i].B = ascii(d.Pairs[i].A), ascii(d.Pairs[i].B)
	}
	for i := range d.Standing {
		r := &d.Standing[i]
		r.ID, r.Device, r.Action = ascii(r.ID), ascii(r.Device), ascii(r.Action)
	}
	for i := range d.Holds {
		d.Holds[i].Device = ascii(d.Holds[i].Device)
	}
	return d
}

func clone(d policy.Document) policy.Document {
	d.Destinations = slices.Clone(d.Destinations)
	d.Devices = slices.Clone(d.Devices)
	for i := range d.Devices {
		d.Devices[i].Allow = slices.Clone(d.Devices[i].Allow)
		d.Devices[i].Control = slices.Clone(d.Devices[i].Control)
		d.Devices[i].Stream = slices.Clone(d.Devices[i].Stream)
	}
	d.Pairs = slices.Clone(d.Pairs)
	d.Standing = slices.Clone(d.Standing)
	d.Holds = slices.Clone(d.Holds)
	return d
}

func ascii(s string) string {
	for _, c := range s {
		if c < 0x21 || c > 0x7e || c == '"' {
			return strconv.QuoteToASCII(s)
		}
	}
	return s
}

func describeDevice(o, d policy.Device, add func(string, ...any)) {
	if o.Network != d.Network {
		add("Move %s from the %s network to the %s network.", d.ID, o.Network, d.Network)
	}
	if o.WiFi != d.WiFi {
		add("Change %s's Wi-Fi identity from %s to %s.", d.ID, none(o.WiFi), none(d.WiFi))
	}
	for _, h := range minus(d.Allow, o.Allow) {
		add("Let %s reach %s.", d.ID, h)
	}
	for _, h := range minus(o.Allow, d.Allow) {
		add("Stop %s reaching %s.", d.ID, h)
	}
	switch {
	case d.VendorCloud && !o.VendorCloud:
		add("Let %s reach its vendor's cloud: the vendor can then reach it.", d.ID)
	case !d.VendorCloud && o.VendorCloud:
		add("Cut %s off from its vendor's cloud: features and alerts that need the cloud stop.", d.ID)
	}
	switch {
	case d.Isolated && !o.Isolated:
		add("Isolate %s: it reaches nothing, its pairs included.", d.ID)
	case !d.Isolated && o.Isolated:
		add("End %s's isolation: its allow list and pairs apply again.", d.ID)
	}
	if o.Everyday != d.Everyday {
		if d.Everyday {
			add("Take %s off the safety list: agentOS may then switch it without asking you.", d.ID)
		} else {
			add("Put %s on the safety list: it acts only on your passkey here at home.", d.ID)
		}
	}
	// An everyday device has no class, so the safety-list line above
	// already says what it is.
	switch {
	case o.Class == d.Class || d.Everyday:
	case o.Everyday:
		add("Record %s as %s.", d.ID, classWords(d.Class))
	default:
		add("Record %s as %s, not %s.", d.ID, classWords(d.Class), classWords(o.Class))
	}
	if o.Secure != d.Secure {
		add("Change %s's one secure command from %s to %s.", d.ID, none(o.Secure), none(d.Secure))
	}
	if o.Label != d.Label {
		add("Label %s %s, not %s.", d.ID, labelWords(d.Label), labelWords(o.Label))
	}
	describePorts(o, d, add)
}

// describePorts is each control and stream port d opens or closes against
// o (NET-2 Device paths, Cameras and microphones).
func describePorts(o, d policy.Device, add func(string, ...any)) {
	for _, p := range portsMinus(d.Control, o.Control) {
		add("Open %s's control port %s: agentOS may reach it there while it is an everyday device.", d.ID, portWords(p))
	}
	for _, p := range portsMinus(o.Control, d.Control) {
		add("Close %s's control port %s.", d.ID, portWords(p))
	}
	for _, p := range portsMinus(d.Stream, o.Stream) {
		add("Let agentOS receive %s's video or audio on %s, while it has no vendor cloud.", d.ID, portWords(p))
	}
	for _, p := range portsMinus(o.Stream, d.Stream) {
		add("Stop agentOS receiving %s's video or audio on %s.", d.ID, portWords(p))
	}
}

func portsMinus(a, b []policy.Port) []policy.Port {
	var out []policy.Port
	for _, p := range a {
		if !slices.Contains(b, p) {
			out = append(out, p)
		}
	}
	return out
}

func portWords(p policy.Port) string { return p.Proto + " " + strconv.Itoa(int(p.Num)) }

func none(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func wifi(id string) string {
	if id == "" {
		return ", wired"
	}
	return fmt.Sprintf(", with its own Wi-Fi identity %s", id)
}

func safety(d policy.Device) string {
	if d.Everyday {
		return "It is an everyday device: agentOS may switch it without asking you."
	}
	return fmt.Sprintf("It is on the safety list as %s: it acts only on your passkey here at home.", classWords(d.Class))
}

// classWords is a NET-2 safety class in the page's words. A device without
// one is of unknown type.
func classWords(c string) string {
	switch c {
	case "":
		return "a device of unknown type"
	case policy.ClassFeedValve:
		return "a valve that feeds sprinklers, heating or a medical supply"
	case policy.ClassPrimaryHeating:
		return "primary heating"
	case policy.ClassGarageDoor:
		return "a garage door"
	case policy.ClassAlarm, policy.ClassOven:
		return "an " + c
	}
	return "a " + c
}

// labelWords is a NET-1 label in the page's words. A device without one is
// not containable.
func labelWords(l string) string {
	switch l {
	case policy.LabelContained:
		return "contained"
	case policy.LabelExceptRadio:
		return "contained except radio"
	}
	return "not containable"
}

func holdWords(h policy.Hold, on bool) string {
	switch {
	case h.Kind == policy.HoldFix && on:
		return fmt.Sprintf("Hold back security fixes for %s: it stays open to the flaws they fix.", h.Device)
	case h.Kind == policy.HoldFix:
		return fmt.Sprintf("Stop holding back security fixes for %s.", h.Device)
	case on:
		return fmt.Sprintf("Freeze %s's firmware: it gets no updates, security fixes included.", h.Device)
	}
	return fmt.Sprintf("Unfreeze %s's firmware.", h.Device)
}

// unlinked is why the pair p has no path in d: each end that is not
// policy.Document.Linked, and why.
func unlinked(d policy.Document, p policy.Pair) string {
	var why []string
	for _, id := range []string{p.A, p.B} {
		dev := d.Device(id)
		switch {
		case dev == nil || d.Linked(id):
			continue
		case dev.Network != policy.NetDevices:
			why = append(why, fmt.Sprintf("%s is on the %s network", id, dev.Network))
			continue
		}
		if dev.WiFi == "" {
			why = append(why, fmt.Sprintf("%s has no Wi-Fi identity", id))
		}
		if dev.Isolated {
			why = append(why, fmt.Sprintf("%s is isolated", id))
		}
		if d.Unpatched(id) {
			why = append(why, fmt.Sprintf("%s's updates are held back", id))
		}
	}
	return strings.Join(why, " and ")
}

func window(r policy.StandingRule, zone *time.Location) string {
	return fmt.Sprintf("from %s to %s", clock(r.FromMS, zone), clock(r.ToMS, zone))
}

func minus(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out
}

func pairsMinus(a, b []policy.Pair) []policy.Pair {
	var out []policy.Pair
	for _, p := range a {
		if !slices.Contains(b, p) {
			out = append(out, p)
		}
	}
	return out
}

func holdsMinus(a, b []policy.Hold) []policy.Hold {
	var out []policy.Hold
	for _, h := range a {
		if !slices.Contains(b, h) {
			out = append(out, h)
		}
	}
	return out
}

const noChange = "No change."

// What the change does once approved, by its class (NET-4).
func consequence(c policy.Class) string {
	switch {
	case c.Tightening && c.Owner:
		return "This closes something on a safety-list device. It applies as soon as you approve."
	case c.Tightening:
		return "This only closes something. It applies as soon as you approve."
	}
	return "This opens something. It applies 10 minutes after you approve, and you can cancel it on this page until then."
}

// diffText is the rendered diff a version's key commits to: the
// consequence, then each line.
func diffText(c policy.Class, lines []string) []byte {
	return []byte(consequence(c) + "\n" + strings.Join(lines, "\n") + "\n")
}

// Limits is NET-1's list of what the enforcer cannot do, in SPEC's words
// (page::TestLimitsWordingAndLabels holds it to SPEC.md).
var Limits = []string{
	"Encrypted traffic is blocked or allowed by destination only (address, and the TLS server name while visible), never by content. Encrypted Client Hello (RFC 9849) hides the server name, and allowing by name over-permits where names share a CDN address.",
	"A cloud-only device loses the function its cloud provides when that cloud is blocked, unless it gets a DEV-12 declaration or is replaced; qualification (DEV-1) records which functions need the cloud.",
	"Some devices cannot be controlled without replacing them. Cellular devices, Amazon Sidewalk, and Thread, Zigbee or Bluetooth links that do not pass through the enforcer's radios are outside network reach, and Bluetooth going straight from a device to a phone app stays outside the system.",
	"A device on the ISP router's own Wi-Fi or LAN is outside NET and at the floor (Rule 0). Setup checks that the router's Wi-Fi is off, and no enforcer segment reaches the router's admin or LAN addresses.",
	"Each device carries a label the page shows: contained, contained except radio, or not containable, from qualification and the enforcer's observation, never from what the device reports.",
}
