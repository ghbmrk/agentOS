package wire

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Msg is one decoded message: one of the types below.
type Msg interface {
	// Type is the frame type the message travels in.
	Type() Type
	put(b []byte) []byte
}

// Verb is a device command. The list is closed: it holds NET-2's everyday
// commands (on, off, level, lock) and the secure directions a safety-list
// device may be named for (shut, close, a drone's return to dock). There
// is no unlock, disarm, arm, open or turn-on, so none can be sent.
type Verb byte

const (
	VerbOn           Verb = 1
	VerbOff          Verb = 2
	VerbLevel        Verb = 3 // Level 0 to 100
	VerbLock         Verb = 4 // lock and relock
	VerbShut         Verb = 5 // a valve
	VerbClose        Verb = 6 // a garage door
	VerbReturnToDock Verb = 7 // a drone
)

// MaxLevel is VerbLevel's highest level.
const MaxLevel = 100

// TightenKind is one kind on NET-4's closed tightening list, as
// broker/enforcer/policy names them.
type TightenKind byte

const (
	RemoveDestination TightenKind = 1 // Device, Host
	CutVendorCloud    TightenKind = 2 // Device
	RemovePair        TightenKind = 3 // A, B
	IsolateDevice     TightenKind = 4 // Device
	RemoveDevice      TightenKind = 5 // Device
	NarrowRule        TightenKind = 6 // Device, Rule, FromMS, ToMS
	RevokeRule        TightenKind = 7 // Device, Rule
)

// ReadWhat is what a read asks for.
type ReadWhat byte

const (
	// ReadState is a device's state as its radio or driver reports it.
	ReadState ReadWhat = 1
	// ReadExport is the policy export for the core's backup (NET-2
	// Recovery); it names no device.
	ReadExport ReadWhat = 2
	// ReadFingerprint is a safety-list device's secret's fingerprint,
	// never the secret (STO-4, brief decision 10).
	ReadFingerprint ReadWhat = 3
	// ReadTraffic is a device's traffic summary (NET-5).
	ReadTraffic ReadWhat = 4
	// ReadCounts is the enforcer's byte-cap counts, the traffic summary
	// the kernel's check reads once each SummaryInterval (NET-2 Byte caps;
	// its body is Counts); it names no device.
	ReadCounts ReadWhat = 5
)

// SummaryInterval is the interval between traffic summaries that this
// format definition fixes (NET-2 The channel, D-255): the core asks for
// one each interval, and the kernel takes a byte-cap count as fresh only
// while it is no older than twice this, so one lost summary does not make
// it stale (NET-2 Byte caps, broker/kernel/capgate). The enforcer and the
// kernel both read it here, never a copy (ASSUMPTIONS ENF-d-w5).
const SummaryInterval = time.Minute

// PastCap is whether a byte count is past its cap: the count the enforcer
// drops and trips on, and the one the kernel's check stops short of
// (NET-2 Byte caps, D-255). A count at the cap is not past it. Both sides
// call this one test, so they cannot disagree on the edge.
func PastCap(count, cap uint64) bool { return count > cap }

// Code is the enforcer's verdict on a request.
type Code byte

const (
	OK          Code = 0
	Refused     Code = 1 // not allowed on the channel, or names nothing
	NeedsOwner  Code = 2 // a safety-list device's tightening: a link the owner signs
	RateLimited Code = 3 // the device's tightening limit (NET-4)
	Paused      Code = 4 // the channel is paused until the owner resumes it
	Failed      Code = 5 // allowed, but the device or store did not do it
)

// Role is which end sent a hello.
type Role byte

const (
	RoleCore     Role = 1
	RoleEnforcer Role = 2
)

// AlertKind is how the owner line delivers an alert (NET-2 Texts and
// calls).
type AlertKind byte

const (
	AlertText AlertKind = 1
	AlertCall AlertKind = 2
)

// Hello opens a connection. Sig is the sender's signature over HelloMsg:
// its role and the TLS exporter of this connection, so a hello is good on
// one connection, for one role, only.
type Hello struct {
	Role Role
	Key  [KeyLen]byte
	Sig  [SigLen]byte
}

// Command is a device command.
type Command struct {
	ID     uint64
	Device string
	Verb   Verb
	Level  uint8 // VerbLevel only; zero otherwise
}

// Tighten is one closed-list tightening. A field its kind does not use is
// empty or zero.
type Tighten struct {
	ID     uint64
	Kind   TightenKind
	Device string
	Host   string
	A, B   string // RemovePair
	Rule   string
	FromMS int64
	ToMS   int64
}

// Read asks for a read. Device is empty for ReadExport and ReadCounts and
// names a device otherwise.
type Read struct {
	ID     uint64
	What   ReadWhat
	Device string
}

// Announce counts one proposal link the core texted to the owner, by its
// hash: the channel never carries the link or the change (NET-2).
type Announce struct {
	ID   uint64
	Link [HashLen]byte
}

// Head is one kernel log head, signed by the kernel's sub-key under the
// head domain (STO-1, LOG-2).
type Head struct {
	ID   uint64
	Seq  uint64
	Hash [HashLen]byte
	Sig  [SigLen]byte
}

// Entry is one key-change or erase entry, as the kernel's log encodes it
// (STO-1, KEY-7). The enforcer's head-copy store (slice h) reads it.
type Entry struct {
	ID   uint64
	Body []byte
}

// Challenge is a device's challenge or the core's answer: the fixed
// challenge frame. Its type is TChallenge from the enforcer and TAnswer
// from the core; the frame is the same.
type Challenge struct {
	Answer bool // TAnswer when set, TChallenge otherwise
	ID     uint64
	Data   []byte // at most ChallengeData
}

// Result is the enforcer's verdict on request ID.
type Result struct {
	ID   uint64
	Code Code
}

// ReadReply is what read ID returned.
type ReadReply struct {
	ID   uint64
	Body []byte
}

// Alert is a text or call the enforcer composed in its own fixed words.
type Alert struct {
	Kind AlertKind
	Text string
}

func (Hello) Type() Type     { return THello }
func (Command) Type() Type   { return TCommand }
func (Tighten) Type() Type   { return TTighten }
func (Read) Type() Type      { return TRead }
func (Announce) Type() Type  { return TAnnounce }
func (Head) Type() Type      { return THead }
func (Entry) Type() Type     { return TEntry }
func (Result) Type() Type    { return TResult }
func (ReadReply) Type() Type { return TReadReply }
func (Alert) Type() Type     { return TAlert }

func (c Challenge) Type() Type {
	if c.Answer {
		return TAnswer
	}
	return TChallenge
}

func (m Hello) put(b []byte) []byte {
	b = append(b, byte(m.Role))
	b = append(b, m.Key[:]...)
	return append(b, m.Sig[:]...)
}

func (m Command) put(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, m.ID)
	b = append(b, byte(m.Verb), m.Level)
	return putName(b, m.Device)
}

func (m Tighten) put(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, m.ID)
	b = append(b, byte(m.Kind))
	for _, s := range []string{m.Device, m.Host, m.A, m.B, m.Rule} {
		b = putName(b, s)
	}
	b = binary.BigEndian.AppendUint64(b, uint64(m.FromMS))
	return binary.BigEndian.AppendUint64(b, uint64(m.ToMS))
}

func (m Read) put(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, m.ID)
	b = append(b, byte(m.What))
	return putName(b, m.Device)
}

func (m Announce) put(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, m.ID)
	return append(b, m.Link[:]...)
}

func (m Head) put(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, m.ID)
	b = binary.BigEndian.AppendUint64(b, m.Seq)
	b = append(b, m.Hash[:]...)
	return append(b, m.Sig[:]...)
}

func (m Entry) put(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, m.ID)
	return append(b, m.Body...)
}

func (m Challenge) put(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, m.ID)
	if len(m.Data) > ChallengeData {
		return append(b, 0xff) // refused by decode
	}
	b = append(b, byte(len(m.Data)))
	b = append(b, m.Data...)
	return append(b, make([]byte, ChallengeData-len(m.Data))...)
}

func (m Result) put(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, m.ID)
	return append(b, byte(m.Code))
}

func (m ReadReply) put(b []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, m.ID)
	return append(b, m.Body...)
}

func (m Alert) put(b []byte) []byte {
	b = append(b, byte(m.Kind))
	return append(b, m.Text...)
}

// putName appends s with a 1-byte length. A name too long for the byte is
// written with a length decode refuses.
func putName(b []byte, s string) []byte {
	if len(s) > MaxName {
		return append(b, 0xff)
	}
	b = append(b, byte(len(s)))
	return append(b, s...)
}

// Encode is m's frame. It refuses any message Decode would refuse: it
// encodes, then decodes what it wrote, so the two ends hold one rule set.
func Encode(d Direction, m Msg) (Frame, error) {
	f := Frame{Type: m.Type(), Payload: m.put(nil)}
	if _, err := Decode(d, f); err != nil {
		return Frame{}, err
	}
	return f, nil
}

// Decode parses f as it arrives on direction d. It is the only path from
// bytes to a message: a type not allowed on d, a length out of bounds, a
// value outside its closed list, a field the kind does not use that is not
// empty, a name that is not a token, nonzero padding and trailing bytes are
// all ErrType, ErrLength or ErrPayload.
func Decode(d Direction, f Frame) (Msg, error) {
	if uint64(len(f.Payload)) > 1<<32-1 {
		return nil, ErrLength
	}
	if err := checkHeader(d, f.Type, uint32(len(f.Payload))); err != nil {
		return nil, err
	}
	r := &reader{b: f.Payload}
	var m Msg
	switch f.Type {
	case THello:
		h := Hello{Role: Role(r.u8())}
		copy(h.Key[:], r.take(KeyLen))
		copy(h.Sig[:], r.take(SigLen))
		want := RoleCore
		if d == ToCore {
			want = RoleEnforcer
		}
		if h.Role != want {
			r.fail()
		}
		m = h
	case TCommand:
		c := Command{ID: r.u64(), Verb: Verb(r.u8()), Level: r.u8(), Device: r.name()}
		if c.Verb < VerbOn || c.Verb > VerbReturnToDock || c.Device == "" ||
			(c.Verb == VerbLevel && c.Level > MaxLevel) || (c.Verb != VerbLevel && c.Level != 0) {
			r.fail()
		}
		m = c
	case TTighten:
		t := Tighten{ID: r.u64(), Kind: TightenKind(r.u8()),
			Device: r.name(), Host: r.name(), A: r.name(), B: r.name(), Rule: r.name(),
			FromMS: int64(r.u64()), ToMS: int64(r.u64())}
		if !t.fields() {
			r.fail()
		}
		m = t
	case TRead:
		rd := Read{ID: r.u64(), What: ReadWhat(r.u8()), Device: r.name()}
		if rd.What < ReadState || rd.What > ReadCounts || (rd.What == ReadExport || rd.What == ReadCounts) != (rd.Device == "") {
			r.fail()
		}
		m = rd
	case TAnnounce:
		a := Announce{ID: r.u64()}
		copy(a.Link[:], r.take(HashLen))
		m = a
	case THead:
		h := Head{ID: r.u64(), Seq: r.u64()}
		copy(h.Hash[:], r.take(HashLen))
		copy(h.Sig[:], r.take(SigLen))
		m = h
	case TEntry:
		e := Entry{ID: r.u64()}
		e.Body = append([]byte{}, r.rest()...)
		if len(e.Body) == 0 {
			r.fail()
		}
		m = e
	case TAnswer, TChallenge:
		c := Challenge{Answer: f.Type == TAnswer, ID: r.u64()}
		n := int(r.u8())
		area := r.take(ChallengeData)
		if n > ChallengeData || r.bad {
			r.fail()
			break
		}
		for _, x := range area[n:] {
			if x != 0 {
				r.fail()
			}
		}
		c.Data = append([]byte{}, area[:n]...)
		m = c
	case TResult:
		res := Result{ID: r.u64(), Code: Code(r.u8())}
		if res.Code > Failed {
			r.fail()
		}
		m = res
	case TReadReply:
		m = ReadReply{ID: r.u64(), Body: append([]byte{}, r.rest()...)}
	case TAlert:
		a := Alert{Kind: AlertKind(r.u8())}
		a.Text = string(r.rest())
		if (a.Kind != AlertText && a.Kind != AlertCall) || !printable(a.Text) {
			r.fail()
		}
		m = a
	default:
		return nil, ErrType
	}
	if r.bad || len(r.b) != 0 {
		return nil, ErrPayload
	}
	return m, nil
}

// fields reports whether t uses exactly the fields its kind names, each a
// token, and leaves the others empty or zero.
func (t Tighten) fields() bool {
	set := func(s string) bool { return s != "" }
	var dev, host, pair, rule, window bool
	switch t.Kind {
	case RemoveDestination:
		dev, host = true, true
	case CutVendorCloud, IsolateDevice, RemoveDevice:
		dev = true
	case RemovePair:
		pair = true
	case RevokeRule:
		dev, rule = true, true
	case NarrowRule:
		dev, rule, window = true, true, true
	default:
		return false
	}
	if set(t.Device) != dev || set(t.Host) != host || set(t.A) != pair || set(t.B) != pair || set(t.Rule) != rule {
		return false
	}
	if pair && t.A == t.B {
		return false
	}
	if window {
		return t.FromMS >= 0 && t.FromMS < t.ToMS
	}
	return t.FromMS == 0 && t.ToMS == 0
}

// reader takes fields off a payload. The first short read marks it bad and
// every later take returns zeros, so Decode checks once at the end.
type reader struct {
	b   []byte
	bad bool
}

func (r *reader) fail() { r.bad = true }

func (r *reader) take(n int) []byte {
	if r.bad || len(r.b) < n {
		r.bad = true
		return make([]byte, n)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() byte    { return r.take(1)[0] }
func (r *reader) u64() uint64 { return binary.BigEndian.Uint64(r.take(8)) }

func (r *reader) rest() []byte {
	out := r.b
	r.b = nil
	return out
}

// name reads a 1-byte length and that many bytes. Empty is allowed here;
// whether a field may be empty is the message's rule.
func (r *reader) name() string {
	n := int(r.u8())
	if n > MaxName {
		r.bad = true
		return ""
	}
	s := string(r.take(n))
	if s != "" && !Name(s) {
		r.bad = true
	}
	return s
}

// Name reports whether s is a token the channel carries as a device, host
// or rule name: 1 to MaxName bytes of UTF-8 with no space, slash, control,
// format (bidi, zero-width, tag), filler or variation selector character,
// as broker/enforcer/policy names them (#3901), and that is not "unknown"
// in any case, the word policy.Unknown reserves (#4185). wire imports only
// the standard library, so channel's TestReservedWord ties the two (#4249).
func Name(s string) bool {
	if s == "" || len(s) > MaxName || !utf8.ValidString(s) || strings.EqualFold(s, "unknown") {
		return false
	}
	for _, c := range s {
		if c == ' ' || c == '/' || !unicode.IsPrint(c) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, c) || unicode.Is(unicode.Variation_Selector, c) {
			return false
		}
	}
	return true
}

// printable is non-empty UTF-8 with no control character, so an alert
// renders as one line of words.
func printable(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c < ' ' || (c >= 0x7f && c < 0xa0) {
			return false
		}
	}
	return true
}

// Hello signatures.
const (
	// DomainHello separates a hello's signature from every other use of
	// the same key.
	DomainHello = "agentos.enforcer.channel.hello.v1\x00"
	// ExporterLabel is the TLS exporter label each end takes ExporterLen
	// bytes under (RFC 5705, RFC 8446 §7.5) to bind its hello to the
	// connection.
	ExporterLabel = "EXPORTER-agentos-enforcer-channel-v1"
	ExporterLen   = 32
)

// ErrHello is any failed hello check: which one is the forger's
// information, not the peer's.
var ErrHello = errors.New("wire: hello does not verify")

// HelloMsg is what a hello's signature covers.
func HelloMsg(role Role, exporter []byte) []byte {
	b := append([]byte(DomainHello), byte(role))
	return append(b, exporter...)
}

// SignHello is role's hello on the connection whose exporter is exporter.
func SignHello(role Role, priv ed25519.PrivateKey, exporter []byte) (Hello, error) {
	if len(priv) != ed25519.PrivateKeySize || len(exporter) != ExporterLen {
		return Hello{}, ErrHello
	}
	h := Hello{Role: role}
	copy(h.Key[:], priv.Public().(ed25519.PublicKey))
	copy(h.Sig[:], ed25519.Sign(priv, HelloMsg(role, exporter)))
	return h, nil
}

// Verify checks h as the hello of role on the connection whose exporter is
// exporter, from exactly the pinned key.
func (h Hello) Verify(role Role, pinned ed25519.PublicKey, exporter []byte) error {
	if h.Role != role || len(pinned) != KeyLen || len(exporter) != ExporterLen ||
		string(h.Key[:]) != string(pinned) ||
		!ed25519.Verify(pinned, HelloMsg(role, exporter), h.Sig[:]) {
		return ErrHello
	}
	return nil
}
