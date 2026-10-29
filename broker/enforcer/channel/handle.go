package channel

import (
	"errors"
	"fmt"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// Secure-direction names: the closed list of commands the owner can name a
// safety-list device safe for (NET-2 Safety devices, DEV-5), as the signed
// policy spells them in Device.Secure. A lock's lock and relock, a valve's
// shut, a heater's, oven's, plug's or relay's off, a garage door's close,
// and a drone's return to dock.
const (
	SecureLock   = "lock"
	SecureShut   = "shut"
	SecureOff    = "off"
	SecureClose  = "close"
	SecureReturn = "return-to-dock"
)

var secureVerb = map[string]wire.Verb{
	SecureLock:   wire.VerbLock,
	SecureShut:   wire.VerbShut,
	SecureOff:    wire.VerbOff,
	SecureClose:  wire.VerbClose,
	SecureReturn: wire.VerbReturnToDock,
}

// everyday is what a device off the safety list takes: NET-2's everyday
// commands.
var everyday = map[wire.Verb]bool{wire.VerbOn: true, wire.VerbOff: true, wire.VerbLevel: true, wire.VerbLock: true}

// Nameable reports whether secure is a secure direction the channel can
// carry. A safety-list device named anything else takes reads only. The
// signed policy refuses a name its device's class does not allow
// (policy.Nameable).
func Nameable(secure string) bool { _, ok := secureVerb[secure]; return ok }

// Allowed is the safety-list table (NET-2 Safety devices, Drones): whether
// the channel carries verb v to dev. Off the list, the everyday commands;
// on it, only the one secure direction the signed policy names and dev's
// class allows, and nothing for a device it names nothing for (a camera,
// microphone, alarm, siren, sensor, primary heating, a feeding valve, a
// device of unknown type, or one not yet named).
func Allowed(dev policy.Device, v wire.Verb) bool {
	if dev.Everyday {
		return everyday[v]
	}
	want, ok := secureVerb[dev.Secure]
	return ok && v == want && policy.Nameable(dev.Class, dev.Secure)
}

// texts reports whether verb v on dev, carried out, texts the owner: a
// heater turned off or a valve shut (NET-2 Safety devices).
func texts(dev policy.Device, v wire.Verb) bool {
	return !dev.Everyday && (dev.Class == policy.ClassHeater && v == wire.VerbOff || dev.Class == policy.ClassValve && v == wire.VerbShut)
}

var verbWords = map[wire.Verb]string{
	wire.VerbOn: "on", wire.VerbOff: "off", wire.VerbLevel: "level", wire.VerbLock: "lock",
	wire.VerbShut: "shut", wire.VerbClose: "close", wire.VerbReturnToDock: "return to dock",
}

var tightenKinds = map[wire.TightenKind]string{
	wire.RemoveDestination: policy.RemoveDestination,
	wire.CutVendorCloud:    policy.CutVendorCloud,
	wire.RemovePair:        policy.RemovePair,
	wire.IsolateDevice:     policy.IsolateDevice,
	wire.RemoveDevice:      policy.RemoveDevice,
	wire.NarrowRule:        policy.NarrowRule,
	wire.RevokeRule:        policy.RevokeRule,
}

var readWords = map[wire.ReadWhat]string{
	wire.ReadState: "state", wire.ReadExport: "policy export", wire.ReadFingerprint: "secret fingerprint", wire.ReadTraffic: "traffic",
}

// handle acts on one decoded message and returns the reply.
func (c *Channel) handle(m wire.Msg) wire.Msg {
	c.mu.Lock()
	defer c.release()
	now := c.cfg.Now()
	ev := Event{At: now}
	var reply wire.Msg
	var code wire.Code
	switch m := m.(type) {
	case wire.Command:
		ev.Kind, ev.ID, ev.Device, ev.What = KindCommand, m.ID, m.Device, verbWords[m.Verb]
		if m.Verb == wire.VerbLevel {
			ev.What = fmt.Sprintf("level %d", m.Level)
		}
		code, ev.Reason = c.gate(KindCommand, func() (wire.Code, string) { return c.command(m, now.UnixMilli()) })
	case wire.Tighten:
		ev.Kind, ev.ID, ev.Device, ev.What = KindTighten, m.ID, m.Device, tightenKinds[m.Kind]
		if m.Kind == wire.RemovePair {
			ev.Device = m.A + "," + m.B
		}
		code, ev.Reason = c.gate(KindTighten, func() (wire.Code, string) { return c.tighten(m, now.UnixMilli()) })
	case wire.Read:
		ev.Kind, ev.ID, ev.Device, ev.What = KindRead, m.ID, m.Device, readWords[m.What]
		var body []byte
		code, ev.Reason = c.gate(KindRead, func() (wire.Code, string) {
			var code wire.Code
			var why string
			body, code, why = c.read(m)
			return code, why
		})
		if code == wire.OK {
			reply = wire.ReadReply{ID: m.ID, Body: body}
		}
	case wire.Announce:
		ev.Kind, ev.ID, ev.What = KindAnnounce, m.ID, "proposal link"
		code, ev.Reason = c.gate(KindAnnounce, func() (wire.Code, string) { return wire.OK, "counted" })
	case wire.Head:
		ev.Kind, ev.ID, ev.What = KindHead, m.ID, "log head"
		code, ev.Reason = c.gate(KindHead, func() (wire.Code, string) {
			if c.cfg.Heads == nil || c.cfg.Heads.Head(m) != nil {
				return wire.Refused, "head not kept"
			}
			return wire.OK, "kept"
		})
	case wire.Entry:
		ev.Kind, ev.ID, ev.What = KindHead, m.ID, "log entry"
		code, ev.Reason = c.gate(KindHead, func() (wire.Code, string) {
			if c.cfg.Heads == nil || c.cfg.Heads.Entry(m) != nil {
				return wire.Refused, "entry not kept"
			}
			return wire.OK, "kept"
		})
	case wire.Challenge:
		ev.Kind, ev.ID, ev.What = KindAnswer, m.ID, "challenge answer"
		code, ev.Reason = c.gate(KindAnswer, func() (wire.Code, string) {
			if !c.outstanding[m.ID] || c.cfg.Answer == nil {
				return wire.Refused, "no challenge outstanding with this id"
			}
			delete(c.outstanding, m.ID)
			id, data := m.ID, m.Data
			c.queued = append(c.queued, func() { c.cfg.Answer(id, data) })
			return wire.OK, "answer passed to the device"
		})
	default:
		// wire.Decode on ToEnforcer yields only the types above and the
		// hello, which Serve takes once.
		code, ev.Reason = wire.Refused, "not a request"
	}
	ev.Code = code
	c.cfg.Log(ev)
	if code != wire.OK && code != wire.NeedsOwner {
		c.count(KindRefused)
	}
	if reply != nil {
		return reply
	}
	return wire.Result{ID: ev.ID, Code: code}
}

// gate runs act unless the channel is paused, after counting k; a kind
// over its rate pauses the channel and act does not run.
func (c *Channel) gate(k Kind, act func() (wire.Code, string)) (wire.Code, string) {
	if c.paused {
		return wire.Paused, "the channel is paused until the owner resumes it on the page"
	}
	if !c.count(k) {
		return wire.Paused, "burst: the channel is paused until the owner resumes it on the page"
	}
	return act()
}

// count takes one from k's bucket and pauses the channel if it was empty.
// It reports whether the channel is still open. The caller holds c.mu.
func (c *Channel) count(k Kind) bool {
	if c.paused {
		return false
	}
	now := c.cfg.Now()
	if c.buckets[k].take(now) {
		return true
	}
	c.paused = true
	c.cfg.Log(Event{At: now, Kind: KindPause, Reason: "burst of " + string(k) + ": paused until the owner resumes it on the page"})
	c.queued = append(c.queued, c.cfg.Alerts.Paused)
	return false
}

// command checks m against the signed policy and the safety-list table and
// sends it through the radio host.
func (c *Channel) command(m wire.Command, nowMS int64) (wire.Code, string) {
	dev := c.cfg.Policy.Current().Device(m.Device)
	if dev == nil {
		return wire.Refused, "no such device in the signed policy"
	}
	if !Allowed(*dev, m.Verb) {
		if dev.Everyday {
			return wire.Refused, "not an everyday command"
		}
		return wire.Refused, "a safety-list device takes reads and only the secure direction the owner named"
	}
	if !dev.Everyday {
		// The named secure direction: counted against the device's
		// tightening limit (NET-4 Tightening).
		switch err := c.cfg.Policy.Secure(dev.ID, dev.Secure, nowMS); {
		case errors.Is(err, policy.ErrRateLimited):
			return wire.RateLimited, "the device's tightening limit"
		case err != nil:
			return wire.Refused, "not the device's secure direction"
		}
	}
	if err := c.cfg.Radio.Do(dev.ID, m.Verb, m.Level); err != nil {
		return wire.Failed, "the radio host did not do it"
	}
	if texts(*dev, m.Verb) {
		id, v := dev.ID, m.Verb
		c.queued = append(c.queued, func() { c.cfg.Alerts.SafetyOff(id, v) })
	}
	return wire.OK, "done"
}

// tighten applies one closed-list tightening through the policy engine,
// which classifies it, refuses a safety-list device's (that needs the
// owner's passkey on a link, NET-4) and rate-limits each device.
func (c *Channel) tighten(m wire.Tighten, nowMS int64) (wire.Code, string) {
	op := policy.Op{Kind: tightenKinds[m.Kind], Device: m.Device, Host: m.Host,
		Pair: policy.Pair{A: m.A, B: m.B}, Rule: m.Rule, FromMS: m.FromMS, ToMS: m.ToMS}
	switch err := c.cfg.Policy.Tighten(op, nowMS); {
	case err == nil:
		return wire.OK, "applied"
	case errors.Is(err, policy.ErrNeedsOwner):
		return wire.NeedsOwner, "a safety-list device's tightening needs the owner's passkey on a link"
	case errors.Is(err, policy.ErrRateLimited):
		return wire.RateLimited, "the device's tightening limit"
	case errors.Is(err, policy.ErrNotTightening):
		return wire.Refused, "not a closed-list tightening of the policy in force"
	case errors.Is(err, policy.ErrPending):
		return wire.Refused, "would not carry over the loosening that is waiting"
	default:
		return wire.Failed, "the policy store did not take it"
	}
}

// read answers a read from the enforcer's own sources.
func (c *Channel) read(m wire.Read) ([]byte, wire.Code, string) {
	var body []byte
	var err error
	if m.What != wire.ReadExport {
		dev := c.cfg.Policy.Current().Device(m.Device)
		if dev == nil {
			return nil, wire.Refused, "no such device in the signed policy"
		}
		if m.What == wire.ReadFingerprint && dev.Everyday {
			return nil, wire.Refused, "only a safety-list device's secret lives on the enforcer"
		}
	}
	switch m.What {
	case wire.ReadState:
		body, err = c.cfg.Radio.State(m.Device)
	case wire.ReadExport:
		body, err = c.cfg.Policy.Export()
	case wire.ReadFingerprint:
		if c.cfg.Fingerprint == nil {
			return nil, wire.Refused, "no secret store"
		}
		fp, ok := c.cfg.Fingerprint(m.Device)
		if !ok {
			return nil, wire.Refused, "no secret held for the device"
		}
		body = fp[:]
	case wire.ReadTraffic:
		if c.cfg.Traffic == nil {
			return nil, wire.Refused, "no traffic summaries"
		}
		body, err = c.cfg.Traffic(m.Device)
	}
	if err != nil || len(body) > wire.MaxReply {
		return nil, wire.Failed, "the source did not answer within the reply cap"
	}
	return body, wire.OK, "read"
}
