// Package imagedest is the signed image's statement of the kernel's own
// internet destinations and the daily bytes the core sends each (SPEC
// NET-2 Byte caps, D-248; #6432): the hosts the core reaches for itself,
// not for an account, such as its time sources. Each figure is the
// `Basis Image` input to enflist: a cap is "sized ... for the kernel's own
// destinations [from what] the signed image states".
//
// The statement is dests.json, embedded in the binary, which the signed
// image carries, so it changes only with a signed release. Load refuses a
// destination with a missing or zero figure, a host that is not a bare
// lower-case name, or one listed twice; Join refuses a host that is both
// the kernel's own and an account's (Basis Declared), so no host is capped
// from two sources. It imports the standard library and clerk/enflist
// only, and does no I/O. Its assumptions are in ASSUMPTIONS.md.
package imagedest

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/clerk/enflist"
)

//go:embed dests.json
var shipped []byte

var (
	// ErrTable: the statement is not a valid destination list.
	ErrTable = errors.New("imagedest: not a valid destination list")
	// ErrShared: a host is both the kernel's own and declared by an
	// account. errors.As gives the *Shared that names it.
	ErrShared = errors.New("imagedest: a host is both the kernel's own and an account's")
)

// Shared names the host stated both here and in an account declaration.
type Shared struct{ Host string }

func (e *Shared) Error() string {
	return fmt.Sprintf("%s is both one of the kernel's own destinations and an account's, so agentOS cannot say which figure caps it.", strconv.QuoteToASCII(e.Host))
}

func (e *Shared) Is(target error) bool { return target == ErrShared }

// Table is the kernel's own destinations, in the statement's order.
type Table struct{ dests []enflist.Dest }

type entry struct {
	Host       string `json:"host"`
	DailyBytes uint64 `json:"daily_bytes"`
}

// Shipped is the statement the image carries.
func Shipped() (*Table, error) { return Load(shipped) }

// Load decodes and validates a statement: {"destinations": [{"host",
// "daily_bytes"}, ...]}, with no other field and nothing after it.
func Load(b []byte) (*Table, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var f struct {
		Destinations []entry `json:"destinations"`
	}
	if err := d.Decode(&f); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTable, err)
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: data after the list", ErrTable)
	}
	if len(f.Destinations) == 0 {
		return nil, fmt.Errorf("%w: no destinations", ErrTable)
	}
	t := &Table{}
	for _, e := range f.Destinations {
		switch {
		case !hostname(e.Host):
			return nil, fmt.Errorf("%w: %s is not a bare lower-case host name", ErrTable, strconv.QuoteToASCII(e.Host))
		case e.DailyBytes == 0:
			return nil, &enflist.NoDailyBytes{Host: e.Host}
		case slices.ContainsFunc(t.dests, func(x enflist.Dest) bool { return x.Host == e.Host }):
			return nil, fmt.Errorf("%w: %s is listed twice", ErrTable, strconv.QuoteToASCII(e.Host))
		}
		t.dests = append(t.dests, enflist.Dest{Host: e.Host, Basis: enflist.Image, DailyBytes: e.DailyBytes})
	}
	return t, nil
}

// Dests is each of the kernel's own destinations with Basis Image and
// its stated figure, in the statement's order.
func (t *Table) Dests() []enflist.Dest { return slices.Clone(t.dests) }

// Hosts is the stated hosts, in order.
func (t *Table) Hosts() []string {
	hs := make([]string, len(t.dests))
	for i, d := range t.dests {
		hs[i] = d.Host
	}
	return hs
}

// Join is the core's destination list for enflist.Inputs: the kernel's
// own destinations, then declared, the accounts' (each Basis Declared or
// Backup). A declared host the kernel also states is *Shared; a declared
// destination claiming Basis Image is ErrTable, since only this statement
// gives that basis.
func (t *Table) Join(declared []enflist.Dest) ([]enflist.Dest, error) {
	out := t.Dests()
	for _, x := range declared {
		if x.Basis == enflist.Image {
			return nil, fmt.Errorf("%w: %s claims the image's basis", ErrTable, strconv.QuoteToASCII(x.Host))
		}
		if slices.Contains(t.Hosts(), x.Host) {
			return nil, &Shared{Host: x.Host}
		}
		out = append(out, x)
	}
	return out, nil
}

var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// hostname reports whether h is a lower-case A-label host name of two
// labels or more: no scheme, path, port, user info or trailing dot.
func hostname(h string) bool {
	ls := strings.Split(h, ".")
	if len(h) > 253 || len(ls) < 2 || !strings.ContainsAny(ls[len(ls)-1], "abcdefghijklmnopqrstuvwxyz") {
		return false // an address literal is not a name the enforcer resolves
	}
	for _, l := range ls {
		if !label.MatchString(l) {
			return false
		}
	}
	return true
}
