package wire

import (
	"encoding/binary"
	"errors"
)

// Counts is the body of a ReadCounts reply: the enforcer's own byte-cap
// count on its own day (NET-2 Byte caps, D-255, #4174), as the kernel's
// check (broker/kernel/capgate) reads it. Every capped core destination is
// in exactly one group; a group is the destinations that share an address
// that day, each with its own cap, and the IP bytes the core sent them,
// acknowledgements and retransmissions included. The edge's segment has
// one cap and one count. A count is past its cap by PastCap.
type Counts struct {
	Day       uint32 // whole days since the Unix epoch, UTC, on the enforcer's clock
	Groups    []CountGroup
	EdgeCap   uint64
	EdgeCount uint64
}

// CountGroup is one cap group. Its cap is the sum of its destinations'.
type CountGroup struct {
	Dests []CountDest
	Count uint64
}

// CountDest is one destination, by its name on the signed list, and its
// own daily cap.
type CountDest struct {
	Name string
	Cap  uint64
}

// ErrCounts is a counts body outside its one canonical form.
var ErrCounts = errors.New("wire: byte-cap counts malformed or not canonical")

// EncodeCounts is c's one encoding: day (4 bytes), edge cap and count (8
// each), the number of groups (4), and each group's count (8), number of
// destinations (2) and each destination's name (1-byte length) and cap
// (8), all big-endian. Destinations are sorted within a group and groups
// by their first destination, so one count has one body. It refuses what
// DecodeCounts refuses.
func EncodeCounts(c Counts) ([]byte, error) {
	b := binary.BigEndian.AppendUint32(nil, c.Day)
	b = binary.BigEndian.AppendUint64(b, c.EdgeCap)
	b = binary.BigEndian.AppendUint64(b, c.EdgeCount)
	b = binary.BigEndian.AppendUint32(b, uint32(len(c.Groups)))
	for _, g := range c.Groups {
		if len(g.Dests) > 0xffff {
			return nil, ErrCounts
		}
		b = binary.BigEndian.AppendUint64(b, g.Count)
		b = binary.BigEndian.AppendUint16(b, uint16(len(g.Dests)))
		for _, d := range g.Dests {
			b = putName(b, d.Name)
			b = binary.BigEndian.AppendUint64(b, d.Cap)
		}
	}
	if _, err := DecodeCounts(b); err != nil {
		return nil, err
	}
	return b, nil
}

// DecodeCounts parses a ReadCounts reply body. A body over MaxReply, a
// group with no destination, a name that is not a token, a destination
// named twice, a group's destinations out of order, groups out of order,
// a group cap that overflows and trailing bytes are all ErrCounts.
func DecodeCounts(b []byte) (Counts, error) {
	if len(b) > MaxReply {
		return Counts{}, ErrCounts
	}
	r := &reader{b: b}
	c := Counts{Day: binary.BigEndian.Uint32(r.take(4)), EdgeCap: r.u64(), EdgeCount: r.u64()}
	n := binary.BigEndian.Uint32(r.take(4))
	seen := map[string]bool{}
	for i := uint32(0); i < n && !r.bad; i++ {
		g := CountGroup{Count: r.u64()}
		m := int(binary.BigEndian.Uint16(r.take(2)))
		var sum uint64
		for j := 0; j < m && !r.bad; j++ {
			d := CountDest{Name: r.name(), Cap: r.u64()}
			if d.Name == "" || seen[d.Name] || (j > 0 && d.Name <= g.Dests[j-1].Name) || sum+d.Cap < sum {
				r.fail()
				break
			}
			seen[d.Name], sum = true, sum+d.Cap
			g.Dests = append(g.Dests, d)
		}
		if m == 0 || (len(c.Groups) > 0 && !r.bad && g.Dests[0].Name <= c.Groups[len(c.Groups)-1].Dests[0].Name) {
			r.fail()
		}
		c.Groups = append(c.Groups, g)
	}
	if r.bad || len(r.b) != 0 {
		return Counts{}, ErrCounts
	}
	return c, nil
}

// Cap is g's one cap, the sum of its destinations' caps; DecodeCounts
// refuses a group whose sum overflows.
func (g CountGroup) Cap() uint64 {
	var sum uint64
	for _, d := range g.Dests {
		sum += d.Cap
	}
	return sum
}

// Names is g's destinations' names, in order.
func (g CountGroup) Names() []string {
	out := make([]string, len(g.Dests))
	for i, d := range g.Dests {
		out[i] = d.Name
	}
	return out
}
