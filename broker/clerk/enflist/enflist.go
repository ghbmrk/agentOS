// Package enflist is the core's half of sizing the enforcer's byte caps
// (SPEC NET-2 Byte caps, CLK-14, KRN-12; #4578). When the owner signs the
// core's destination list, each destination's daily cap is the figure its
// source states: the daily bytes its declaration states, the signed
// image's figure for the kernel's own destinations, or a backup target's
// next full backup's size (backup.Size); the edge's one cap is its
// declared total. No margin is added and no default is invented: a
// destination that states no daily bytes is refused, with its name, so a
// cap never trips the core on a figure nobody stated. Propose writes the
// next policy document, with each cap's basis signed beside it, and Link
// is the proposal link the owner opens on the enforcer's page, which draws
// the cap lines from that signed document, never from the link's text.
//
// The seam is frozen for its one caller, cmd/agentosd: Basis, Dest,
// Inputs, Figure, Propose, Next.Link, Next.Figures and ErrNoDailyBytes. It
// imports the standard library and broker/enforcer/policy only
// (broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package enflist

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// Basis is the figure a cap is sized from, from the policy's closed list.
type Basis string

const (
	Declared Basis = policy.BasisDeclared // the daily bytes its declaration states (CLK-14)
	Image    Basis = policy.BasisImage    // the signed image's figure, for the kernel's own destinations
	Backup   Basis = policy.BasisBackup   // a backup target's next full backup's size
)

// Dest is one of the core's internet destinations and its daily figure.
type Dest struct {
	Host       string
	Basis      Basis
	DailyBytes uint64
}

// Inputs is the core's whole destination list and the edge's declared
// daily fetch total. A destination left out is dropped from the list.
type Inputs struct {
	Dests             []Dest
	EdgeDeclaredBytes uint64
}

// Figure is one cap as signed and the figure it came from, for the
// caller's own page lines. Host is empty for the edge's segment.
type Figure struct {
	Host  string
	Bytes uint64
	Basis Basis
}

var (
	// ErrNoDailyBytes: a destination, or the edge, states no daily bytes.
	// errors.As gives the *NoDailyBytes that names it.
	ErrNoDailyBytes = errors.New("enflist: no daily bytes stated")
	ErrInput        = errors.New("enflist: not a destination list")
)

// NoDailyBytes names the destination that states no daily bytes; Host is
// empty for the edge.
type NoDailyBytes struct{ Host string }

// Error is the owner's wording, with the name in printable ASCII.
func (e *NoDailyBytes) Error() string {
	if e.Host == "" {
		return "The edge states no daily total, so agentOS cannot size its cap; declare the edge's daily total, then sign."
	}
	return fmt.Sprintf("%s states no daily bytes, so agentOS cannot size its cap; declare its daily bytes, then sign.", strconv.QuoteToASCII(e.Host))
}

func (e *NoDailyBytes) Is(target error) bool { return target == ErrNoDailyBytes }

// Next is a proposed document with its caps sized.
type Next struct {
	doc  []byte // canonical
	figs []Figure
}

// Propose is cur with its destination list, caps, bases and edge cap
// replaced by in's, each cap equal to its stated figure. A destination or
// edge with no daily bytes is *NoDailyBytes; a host listed twice, a basis
// off the list, or a document the policy refuses (an invalid name, caps
// summing past 2^64-1) is ErrInput. It reads nothing else and keeps
// everything else in cur.
func Propose(cur policy.Document, in Inputs) (Next, error) {
	d := cur
	d.Destinations, d.Caps, d.Basis = nil, map[string]uint64{}, map[string]string{}
	var figs []Figure
	for _, x := range in.Dests {
		switch {
		case x.Basis != Declared && x.Basis != Image && x.Basis != Backup:
			return Next{}, fmt.Errorf("%w: %s has basis %q", ErrInput, strconv.QuoteToASCII(x.Host), x.Basis)
		case slices.Contains(d.Destinations, x.Host):
			return Next{}, fmt.Errorf("%w: %s is listed twice", ErrInput, strconv.QuoteToASCII(x.Host))
		case x.DailyBytes == 0:
			return Next{}, &NoDailyBytes{Host: x.Host}
		}
		d.Destinations = append(d.Destinations, x.Host)
		d.Caps[x.Host], d.Basis[x.Host] = x.DailyBytes, string(x.Basis)
		figs = append(figs, Figure{x.Host, x.DailyBytes, x.Basis})
	}
	if in.EdgeDeclaredBytes == 0 {
		return Next{}, &NoDailyBytes{}
	}
	d.EdgeCap = in.EdgeDeclaredBytes
	b, err := policy.Encode(d)
	if err != nil {
		return Next{}, fmt.Errorf("%w: %w", ErrInput, err)
	}
	slices.SortFunc(figs, func(a, b Figure) int { return strings.Compare(a.Host, b.Host) })
	return Next{doc: b, figs: append(figs, Figure{"", d.EdgeCap, Declared})}, nil
}

// Link is the proposal link for n on the enforcer page named name, as
// action.TighteningLink draws one: https://<name>/p?d=<canonical document>.
func (n Next) Link(name string) (string, error) {
	if n.doc == nil || name == "" || strings.ContainsAny(name, "/?#@: ") {
		return "", ErrInput
	}
	return "https://" + name + "/p?d=" + base64.RawURLEncoding.EncodeToString(n.doc), nil
}

// Figures is each cap n signs, by host, then the edge's.
func (n Next) Figures() []Figure { return slices.Clone(n.figs) }
