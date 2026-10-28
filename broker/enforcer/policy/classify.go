package policy

import (
	"bytes"
	"slices"
)

// Tightening kinds: the closed list (NET-4 Tightening, Standing rules).
// Anything else is a loosening.
const (
	RemoveDestination = "remove-destination" // one host from one device's allow list
	CutVendorCloud    = "cut-vendor-cloud"   // one device's vendor cloud
	RemovePair        = "remove-pair"        // one device-to-device path
	IsolateDevice     = "isolate-device"     // one device
	RemoveDevice      = "remove-device"      // one device, with its pairs, rules and holds
	NarrowRule        = "narrow-rule"        // one standing rule's window, inside the old one
	RevokeRule        = "revoke-rule"        // one standing rule
)

// Op is one closed-list tightening.
type Op struct {
	Kind   string `json:"kind"`
	Device string `json:"device,omitempty"`
	Host   string `json:"host,omitempty"` // RemoveDestination
	Pair   Pair   `json:"pair,omitzero"`  // RemovePair
	Rule   string `json:"rule,omitempty"` // NarrowRule, RevokeRule
	FromMS int64  `json:"from_ms,omitempty"`
	ToMS   int64  `json:"to_ms,omitempty"` // NarrowRule: the new window
}

// Class is what Classify found.
type Class struct {
	// Tightening is set only when the change is exactly one closed-list
	// tightening, Op.
	Tightening bool
	Op         Op
	// Owner is set for a tightening that touches a safety-list device: it
	// can stop the device's alerts, so it needs the owner's assertion like
	// a loosening (NET-4 Tightening), though it applies at once. Narrowing
	// or revoking a standing rule only takes back what the rule granted, so
	// it never sets Owner (ASSUMPTIONS ENF-a-3).
	Owner bool
}

// Classify reports whether next is exactly one closed-list tightening of
// old (NET-4). Versions are ignored. A change that is no change, that mixes
// a tightening with anything else, or that two tightenings make, is a
// loosening: next counts as a tightening only when applying one op to old
// gives next. Every path that applies a change goes through here.
func Classify(old, next Document) Class {
	o, n := old.normal(), next.normal()
	o.Version, n.Version = 0, 0
	if o.check() != nil || n.check() != nil {
		return Class{}
	}
	want, _ := Encode(n)
	for _, op := range candidates(o, n) {
		got, ok := Apply(o, op)
		if !ok {
			continue
		}
		if b, err := Encode(got); err == nil && bytes.Equal(b, want) {
			return Class{Tightening: true, Op: op, Owner: safety(o, op)}
		}
	}
	return Class{}
}

// candidates is every closed-list op on o, plus the narrowings next shows.
func candidates(o, n Document) []Op {
	var ops []Op
	for _, dev := range o.Devices {
		ops = append(ops, Op{Kind: RemoveDevice, Device: dev.ID})
		if !dev.Isolated {
			ops = append(ops, Op{Kind: IsolateDevice, Device: dev.ID})
		}
		if dev.VendorCloud {
			ops = append(ops, Op{Kind: CutVendorCloud, Device: dev.ID})
		}
		for _, h := range dev.Allow {
			ops = append(ops, Op{Kind: RemoveDestination, Device: dev.ID, Host: h})
		}
	}
	for _, p := range o.Pairs {
		ops = append(ops, Op{Kind: RemovePair, Pair: p})
	}
	for _, r := range o.Standing {
		ops = append(ops, Op{Kind: RevokeRule, Device: r.Device, Rule: r.ID})
		for _, nr := range n.Standing {
			if nr.ID == r.ID {
				ops = append(ops, Op{Kind: NarrowRule, Device: r.Device, Rule: r.ID, FromMS: nr.FromMS, ToMS: nr.ToMS})
			}
		}
	}
	return ops
}

// Apply is d with op applied, and whether op applies to d: its device,
// host, pair or rule exists and the op changes something. A narrowing must
// stay inside the old window and shrink it.
func Apply(d Document, op Op) (Document, bool) {
	d = d.normal() // a copy: d's lists are never written
	switch op.Kind {
	case RemoveDestination, CutVendorCloud, IsolateDevice:
		dev := d.Device(op.Device)
		if dev == nil {
			return d, false
		}
		switch op.Kind {
		case RemoveDestination:
			i := slices.Index(dev.Allow, op.Host)
			if i < 0 {
				return d, false
			}
			dev.Allow = slices.Delete(dev.Allow, i, i+1)
		case CutVendorCloud:
			if !dev.VendorCloud {
				return d, false
			}
			dev.VendorCloud = false
		case IsolateDevice:
			if dev.Isolated {
				return d, false
			}
			dev.Isolated = true
		}
	case RemoveDevice:
		n := len(d.Devices)
		d.Devices = slices.DeleteFunc(d.Devices, func(x Device) bool { return x.ID == op.Device })
		if len(d.Devices) == n {
			return d, false
		}
		d.Pairs = slices.DeleteFunc(d.Pairs, func(p Pair) bool { return p.A == op.Device || p.B == op.Device })
		d.Standing = slices.DeleteFunc(d.Standing, func(r StandingRule) bool { return r.Device == op.Device })
		d.Holds = slices.DeleteFunc(d.Holds, func(h Hold) bool { return h.Device == op.Device })
	case RemovePair:
		p := op.Pair
		if p.B < p.A {
			p.A, p.B = p.B, p.A
		}
		i := slices.Index(d.Pairs, p)
		if i < 0 {
			return d, false
		}
		d.Pairs = slices.Delete(d.Pairs, i, i+1)
	case RevokeRule, NarrowRule:
		i := slices.IndexFunc(d.Standing, func(r StandingRule) bool { return r.ID == op.Rule })
		if i < 0 || d.Standing[i].Device != op.Device {
			return d, false
		}
		if op.Kind == RevokeRule {
			d.Standing = slices.Delete(d.Standing, i, i+1)
			break
		}
		r := &d.Standing[i]
		if op.FromMS < r.FromMS || op.ToMS > r.ToMS || op.FromMS >= op.ToMS ||
			(op.FromMS == r.FromMS && op.ToMS == r.ToMS) {
			return d, false
		}
		r.FromMS, r.ToMS = op.FromMS, op.ToMS
	default:
		return d, false
	}
	return d, true
}

// safety reports whether op touches a device on o's safety list, other
// than by narrowing or revoking a standing rule.
func safety(o Document, op Op) bool {
	if op.Kind == NarrowRule || op.Kind == RevokeRule {
		return false
	}
	for _, id := range []string{op.Device, op.Pair.A, op.Pair.B} {
		if dev := o.Device(id); dev != nil && dev.Secure != "" {
			return true
		}
	}
	return false
}
