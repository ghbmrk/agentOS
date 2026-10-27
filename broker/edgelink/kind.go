package edgelink

// Kind is a frame's kind: a closed set (HW-15 "framed only by kind, origin
// and length").
type Kind uint8

const (
	KindFetch   Kind = 1 // core to edge: the URL to fetch
	KindFetched Kind = 2 // edge to core: the URL it answers
	KindText    Kind = 3 // edge to core: a second-line text, from the sender's number
	KindCall    Kind = 4 // edge to core: second-line call audio, from the caller's number
	KindDevice  Kind = 5 // both: a relayed device's state or command, by its declared name
	KindHello   Kind = 6 // edge to core, hello mode only: an unknown edge's key proof
)

// Stream is one direction of one connection mode. A frame is read and
// written for exactly one stream, and a kind not allowed on it is refused.
type Stream uint8

const (
	ToEdge   Stream = 1 // the core's frames on a served connection
	FromEdge Stream = 2 // the live edge's frames on a served connection
	Hello    Stream = 3 // the one frame an edge that is not live sends
)

func (s Stream) bit() uint8 {
	if s < ToEdge || s > Hello {
		return 0
	}
	return 1 << s
}

// Label is what the core treats an item from the edge as (PLN-3, CLK-8,
// NET-2). It comes from the kind alone.
type Label string

const (
	LabelOutbound   Label = "outbound"              // the core's own frames; never received
	LabelPublic     Label = "public"                // fetched web content (PLN-3 (1))
	LabelSecondLine Label = "untrusted-second-line" // second-line texts and calls (CLK-8)
	LabelDevice     Label = "untrusted-device"      // relayed device state (NET-2)
	LabelNever      Label = "never-delivered"       // the hello is read, never delivered
)

const (
	kib = 1 << 10
	mib = 1 << 20
)

type kindSpec struct {
	streams uint8  // Stream bits it may travel on
	cap     uint64 // the body's upper bound
	exact   bool   // the body is exactly cap bytes
	label   Label
}

// kinds is the table of decision 6 in briefs/EDGE-link-core.md.
var kinds = map[Kind]kindSpec{
	KindFetch:   {streams: ToEdge.bit(), cap: 64 * kib, label: LabelOutbound},
	KindFetched: {streams: FromEdge.bit(), cap: 16 * mib, label: LabelPublic},
	KindText:    {streams: FromEdge.bit(), cap: 64 * kib, label: LabelSecondLine},
	KindCall:    {streams: FromEdge.bit(), cap: 64 * kib, label: LabelSecondLine},
	KindDevice:  {streams: ToEdge.bit() | FromEdge.bit(), cap: 64 * kib, label: LabelDevice},
	KindHello:   {streams: Hello.bit(), cap: HelloLen, exact: true, label: LabelNever},
}

// Label is k's label at the core; an unknown kind has none.
func (k Kind) Label() Label { return kinds[k].label }

// MaxBody is k's body cap; an unknown kind's is 0.
func (k Kind) MaxBody() uint64 { return kinds[k].cap }
