package channel

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

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
// device of unknown type, one not yet named, or a garage door missing a
// safeguard its class needs: policy.Device.Named, #3872).
func Allowed(dev policy.Device, v wire.Verb) bool {
	if dev.Everyday {
		return everyday[v]
	}
	want, ok := secureVerb[dev.Secure]
	return ok && v == want && dev.Named()
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

// summaryRead are the reads that are traffic summaries, which resume at the
// "core reflashed" step (D-262).
var summaryRead = map[wire.ReadWhat]bool{wire.ReadTraffic: true, wire.ReadCounts: true}

var readWords = map[wire.ReadWhat]string{
	wire.ReadState: "state", wire.ReadExport: "policy export", wire.ReadFingerprint: "secret fingerprint", wire.ReadTraffic: "traffic", wire.ReadCounts: "byte counts",
}

// handle acts on one decoded message from session s and returns the
// reply. A message on a connection a later hello replaced neither acts nor
// counts: it ends its connection with ErrSuperseded (ENF-d-9).
func (c *Channel) handle(s *session, m wire.Msg) (wire.Msg, error) {
	c.mu.Lock()
	defer c.release()
	now := c.cfg.Now()
	if c.session != s {
		c.log(Event{At: now, Kind: KindFrame, Reason: "a later connection replaced this one: request not counted, connection ended"})
		return nil, ErrSuperseded
	}
	rk := wire.RateKindOf(m.Type())
	ev := Event{At: now}
	// The requests that name a device take one copy of the policy, and
	// read names from it for the log before act runs, so a removed device
	// is still logged by its name; command and read check against the same
	// copy (#4066).
	var reply wire.Msg
	var code wire.Code
	switch m := m.(type) {
	case wire.Command:
		cur := c.cfg.Policy.Current()
		ev.Kind, ev.ID, ev.Device, ev.What = KindCommand, m.ID, logName(cur, m.Device), verbWords[m.Verb]
		if m.Verb == wire.VerbLevel {
			ev.What = fmt.Sprintf("level %d", m.Level)
		}
		code, ev.Reason = c.gate(rk, false, func() (wire.Code, string) { return c.command(cur, m, now.UnixMilli()) })
	case wire.Tighten:
		cur := c.cfg.Policy.Current()
		ev.Kind, ev.ID, ev.Device, ev.What = KindTighten, m.ID, logName(cur, m.Device), tightenKinds[m.Kind]
		if m.Kind == wire.RemovePair {
			ev.Device, ev.Other = logName(cur, m.A), logName(cur, m.B)
		}
		code, ev.Reason = c.gate(rk, false, func() (wire.Code, string) { return c.tighten(m, now.UnixMilli()) })
	case wire.Read:
		var cur policy.Document // an export or a count read names no device
		if m.Device != "" {
			cur = c.cfg.Policy.Current()
		}
		ev.Kind, ev.ID, ev.Device, ev.What = KindRead, m.ID, logName(cur, m.Device), readWords[m.What]
		var body []byte
		code, ev.Reason = c.gate(rk, summaryRead[m.What], func() (wire.Code, string) {
			var code wire.Code
			var why string
			body, code, why = c.read(cur, m)
			return code, why
		})
		if code == wire.OK {
			reply = wire.ReadReply{ID: m.ID, Body: body}
		}
	case wire.Announce:
		ev.Kind, ev.ID, ev.What = KindAnnounce, m.ID, "proposal link"
		code, ev.Reason = c.gate(rk, false, func() (wire.Code, string) { return wire.OK, "counted" })
	case wire.Head:
		ev.Kind, ev.ID, ev.What = KindHead, m.ID, "log head"
		code, ev.Reason = c.gate(rk, false, func() (wire.Code, string) {
			if c.cfg.Heads == nil || c.cfg.Heads.Head(m) != nil {
				return wire.Refused, "head not kept"
			}
			return wire.OK, "kept"
		})
	case wire.Entry:
		ev.Kind, ev.ID, ev.What = KindHead, m.ID, "log entry"
		code, ev.Reason = c.gate(rk, false, func() (wire.Code, string) {
			if c.cfg.Heads == nil || c.cfg.Heads.Entry(m) != nil {
				return wire.Refused, "entry not kept"
			}
			return wire.OK, "kept"
		})
	case wire.Challenge:
		ev.Kind, ev.ID, ev.What = KindAnswer, m.ID, "challenge answer"
		code, ev.Reason = c.gate(rk, false, func() (wire.Code, string) {
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
	c.log(ev)
	// A Paused answer is not a refusal: a kernel learns of a trip or a
	// pause only from one, so counting it would pause the summaries the
	// Reflashed stage reopens.
	if code != wire.OK && code != wire.NeedsOwner && code != wire.Paused {
		c.countRefused()
	}
	if reply != nil {
		return reply, nil
	}
	return wire.Result{ID: ev.ID, Code: code}, nil
}

// logName is how the log names a device the core sent: its ID if the
// signed policy names it, else unknownWord and the SHA-256 of the name, so
// every name in the log is one the owner signed and the core cannot write
// words into the owner's record (#3758). A signed ID holds no space and is
// never the word itself (policy.name, #4185), so the two forms never meet.
func logName(d policy.Document, s string) string {
	if s == "" || d.Device(s) != nil {
		return s
	}
	h := sha256.Sum256([]byte(s))
	return unknownWord + hex.EncodeToString(h[:])
}

const (
	unknownWord = policy.Unknown + " "
	// shortHex is how many hex digits of an unknown name's hash the
	// owner's line shows: enough to tell repeated unknown names apart.
	shortHex = 12
)

// Short is a logged name as the owner's log line shows it: a signed ID as
// itself, an unknown name as "unknown" and the first 12 hex digits of its
// hash. The Event keeps the full hash for the detail view (#4066). Neither
// form shows any of the core's words.
func Short(logged string) string {
	if len(logged) == len(unknownWord)+2*sha256.Size && logged[:len(unknownWord)] == unknownWord {
		return logged[:len(unknownWord)+shortHex]
	}
	return logged
}

var codeWords = map[wire.Code]string{
	wire.Refused: "refused", wire.NeedsOwner: "needs the owner", wire.RateLimited: "rate-limited",
	wire.Paused: "paused", wire.Failed: "failed",
}

// Line is e as the owner's log line shows it: every name through Short,
// and a removed pair's two members both, so a renderer that takes it can
// neither drop the second member nor print a full hash (#4185). Each name
// is one token, or "unknown" and its digits, and the members are split by
// " / ", which no signed ID holds. It carries no time: the renderer shows
// e.At in the owner's zone, as the page shows every time (NET-4).
func (e Event) Line() string { return e.render(Short) }

// Detail is e as the detail view shows it: Line with each unknown name's
// full hash.
func (e Event) Detail() string { return e.render(func(s string) string { return s }) }

func (e Event) render(show func(string) string) string {
	var b strings.Builder
	b.WriteString(string(e.Kind))
	if e.ID != 0 {
		fmt.Fprintf(&b, " #%d", e.ID)
	}
	if e.What != "" {
		b.WriteString(" " + e.What)
	}
	if e.Device != "" {
		b.WriteString(" " + show(e.Device))
	}
	if e.Other != "" {
		b.WriteString(" / " + show(e.Other))
	}
	b.WriteString(":")
	if w := codeWords[e.Code]; w != "" {
		b.WriteString(" " + w + ",")
	}
	b.WriteString(" " + e.Reason)
	return b.String()
}

// gate counts k and runs act unless the request may not act now. While a
// trip is in force every request is answered Paused and logged; it still
// takes its kind's rate, but a paused request past the rate trips nothing
// more, so a paused core's retries never send a Reflashed stage back to
// Tripped. At the Reflashed stage a traffic summary (summary set) acts
// again and the rest wait for the passkey restore (D-260, D-262). A request
// that may act and is past its kind's rate trips the core (count). Past
// the refusal rate every request waits, RateLimited, until it refills.
func (c *Channel) gate(k wire.RateKind, summary bool, act func() (wire.Code, string)) (wire.Code, string) {
	var paused string
	switch c.cfg.Cut.Stage() {
	case Open:
	case Reflashed:
		if !summary {
			paused = "the core tripped: paused until the owner's passkey restore"
		}
	default: // Tripped, or a stage this code does not know
		paused = "the core tripped: paused until the owner's passkey restore"
		if summary {
			paused = "the core tripped: summaries paused until the core reflashed step"
		}
	}
	if paused != "" {
		c.buckets[k].Take(c.cfg.Now())
		return wire.Paused, paused
	}
	if !c.count(k) {
		return wire.Paused, "burst of " + string(rated[k]) + ": tripped the core"
	}
	if !c.refused.Has(c.cfg.Now()) {
		return wire.RateLimited, refusalWait
	}
	return act()
}

// refusalWait is the reason a request past the refusal rate is refused.
// Counting it takes nothing from the empty bucket, so the rate refills
// while the core keeps asking.
const refusalWait = "too many refusals: refused until the refusal rate refills"

// count takes one from rated kind k's bucket. An empty bucket is a burst
// past the rate, a core trip. It reports whether the request is inside
// the rate. The caller holds c.mu.
func (c *Channel) count(k wire.RateKind) bool {
	now := c.cfg.Now()
	if c.buckets[k].Take(now) {
		return true
	}
	reason := "burst of " + string(rated[k]) + " past the rate: tripped the core"
	c.log(Event{At: now, Kind: KindTrip, What: string(rated[k]), Reason: reason})
	c.queueTrip(reason)
	return false
}

// countRefused takes one from the refusal bucket, which never trips: past
// it requests only wait (gate). The caller holds c.mu.
func (c *Channel) countRefused() { c.refused.Take(c.cfg.Now()) }

// command checks m against cur, the signed policy handle copied, and the
// safety-list table, and sends it through the radio host.
func (c *Channel) command(cur policy.Document, m wire.Command, nowMS int64) (wire.Code, string) {
	dev := cur.Device(m.Device)
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

// read answers a read from the enforcer's own sources, checking the device
// against cur, the signed policy handle copied.
func (c *Channel) read(cur policy.Document, m wire.Read) ([]byte, wire.Code, string) {
	var body []byte
	var err error
	if m.Device != "" {
		dev := cur.Device(m.Device)
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
	case wire.ReadCounts:
		if c.cfg.Counts == nil {
			return nil, wire.Refused, "no byte-cap counts"
		}
		var cs wire.Counts
		if cs, err = c.cfg.Counts(); err == nil {
			body, err = wire.EncodeCounts(cs)
		}
	}
	if err != nil || len(body) > wire.MaxReply {
		return nil, wire.Failed, "the source did not answer within the reply cap"
	}
	return body, wire.OK, "read"
}
