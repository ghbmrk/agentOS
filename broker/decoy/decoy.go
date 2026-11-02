// Package decoy is the box's one decoy table (KRN-12 One table, D-232): the
// values an intruder finds where it looks first, and the destinations their
// use would reach. The table is made once, at first boot, by generators that
// follow each kind's published format; it is kept in the sealed store
// (STO-2), never in the image or the repository; and it reaches the kernel
// as one logged event (KRN-1), so replaying the log gives the same table and
// the same trips (KRN-6). Its matcher is broker/decoy/match.
//
// The package holds no decoy value and does no I/O of its own: the table
// moves only as the bytes the kernel puts in the sealed store and logs
// (store.go). Placing the values is DECOY-e's, tripping on them DECOY-b's.
package decoy

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"

	"github.com/ghbmrk/agentos/broker/decoy/match"
)

// Kind is a decoy's format, from a closed list.
type Kind string

// The kinds this package generates, each in its published format.
const (
	KGitHub     Kind = "github"      // classic personal access token
	KAWSKeyID   Kind = "aws-key-id"  // access key ID
	KAWSSecret  Kind = "aws-secret"  // secret access key
	KAnthropic  Kind = "anthropic"   // API key
	KOpenAI     Kind = "openai"      // project key
	KSSH        Kind = "ssh-ed25519" // OpenSSH private key
	KRecovery   Kind = "recovery"    // an account recovery code
	KMetadata   Kind = "metadata"    // the cloud metadata address: a destination, no value
	KHoneyKey   Kind = "honey-key"   // a key signed by no root (KEY-1), made by the caller
	KStoreEntry Kind = "store-entry" // a sealed-store root or recovery entry, made by the caller
)

// The kinds whose values come from the box's own generators, which this
// package does not link: the caller hands them in (Own), so a decoy of the
// box's own formats is made by the very code that makes the real ones.
var ownKinds = []Kind{KHoneyKey, KStoreEntry}

var gens = map[Kind]func(io.Reader) (string, error){
	KGitHub:    gitHub,
	KAWSKeyID:  awsKeyID,
	KAWSSecret: awsSecret,
	KAnthropic: anthropic,
	KOpenAI:    openAI,
	KSSH:       sshKey,
	KRecovery:  recoveryCode,
}

// Place is where a decoy goes, from a closed list, in the order an intruder
// searches (KRN-12 Placement).
type Place string

const (
	PSandboxEnv  Place = "sandbox.env"
	PHostEnv     Place = "host.env"
	PHostDotfile Place = "host.dotfile"
	PHostJackpot Place = "host.jackpot"
	PEdgeDotfile Place = "edge.dotfile"
	PEdgeJackpot Place = "edge.jackpot"
	PMetadata    Place = "metadata"
	PPlannerView Place = "planner.view"
	PSealedStore Place = "sealed.store"
)

// plan is what Generate makes: one entry per row, each value fresh, so a
// trip names the place its value leaked from.
var plan = []struct {
	kind  Kind
	place Place
}{
	{KAnthropic, PSandboxEnv}, {KOpenAI, PSandboxEnv}, {KGitHub, PSandboxEnv},
	{KAWSKeyID, PSandboxEnv}, {KAWSSecret, PSandboxEnv},
	{KAnthropic, PHostEnv}, {KOpenAI, PHostEnv},
	{KSSH, PHostDotfile}, {KGitHub, PHostDotfile}, {KAWSKeyID, PHostDotfile},
	{KAWSSecret, PHostDotfile}, {KAnthropic, PHostDotfile},
	{KRecovery, PHostJackpot}, {KRecovery, PHostJackpot},
	{KSSH, PEdgeDotfile}, {KGitHub, PEdgeDotfile}, {KAWSKeyID, PEdgeDotfile},
	{KAWSSecret, PEdgeDotfile},
	{KRecovery, PEdgeJackpot},
	{KMetadata, PMetadata},
}

// Metadata is the cloud metadata address (KRN-12 Placement).
var Metadata = netip.MustParseAddr("169.254.169.254")

// Entry is one decoy: its value (empty for a destination-only kind), kind,
// destination and placement. Every credential-shaped decoy names a
// destination in the enforcer's decoy range.
type Entry struct {
	Value string
	Kind  Kind
	Dest  netip.Addr
	Place Place
}

// String names the entry without its value, so a log line or error that
// prints one leaks nothing.
func (e Entry) String() string {
	return fmt.Sprintf("decoy %s at %s to %s", e.Kind, e.Place, e.Dest)
}

// GoString is String, for %#v.
func (e Entry) GoString() string { return e.String() }

// MarshalJSON is String, for JSON and slog's JSON handler (#3876).
func (e Entry) MarshalJSON() ([]byte, error) { return json.Marshal(e.String()) }

// Table is the box's one decoy table. The zero Table is empty.
type Table struct{ entries []Entry }

// Entries returns a copy of the table's entries; an entry's index is the ID
// a trip names it by.
func (t Table) Entries() []Entry { return slices.Clone(t.entries) }

// Len is the number of entries.
func (t Table) Len() int { return len(t.entries) }

// String counts the entries and shows none, so printing a table leaks
// nothing.
func (t Table) String() string { return fmt.Sprintf("decoy table (%d entries)", len(t.entries)) }

// GoString is String, for %#v.
func (t Table) GoString() string { return t.String() }

// Equal reports whether two tables hold the same entries in the same order.
func (t Table) Equal(u Table) bool { return slices.Equal(t.entries, u.entries) }

// Own is a caller's generator for one of the box's own kinds (KHoneyKey,
// KStoreEntry): the function that makes the real ones, run on the table's
// randomness.
type Own struct {
	Kind  Kind
	Place Place
	Make  func(io.Reader) (string, error)
}

var (
	// ErrNoRange: Generate was given no decoy-range address to point
	// credential-shaped decoys at.
	ErrNoRange = errors.New("decoy: no decoy-range address")
	// ErrBadTable: a stored or logged table that does not parse or breaks
	// a rule (an unknown kind or place, a value too long, a credential with
	// no decoy-range destination).
	ErrBadTable = errors.New("decoy: the table is damaged")
	// ErrTooMany: more decoy-range addresses than MaxRange, or an alphabet
	// too large to sample.
	ErrTooMany = errors.New("decoy: too many decoy-range addresses")
)

// MaxRange bounds the decoy-range addresses Generate takes: one /16's worth.
const MaxRange = 1 << 16

// MinValue is the shortest value a table holds (a recovery code's length),
// so no value is short enough to turn up in ordinary traffic and trip.
const MinValue = 10

// Generate makes a table from r, which must be a cryptographic source in
// production; the same bytes give the same table. dests are the enforcer's
// decoy-range addresses (decision 4), shipped in its image; each
// credential-shaped entry points at one of them. own adds entries of the
// box's own kinds.
func Generate(r io.Reader, dests []netip.Addr, own ...Own) (Table, error) {
	if len(dests) == 0 {
		return Table{}, ErrNoRange
	}
	if len(dests) > MaxRange {
		return Table{}, ErrTooMany
	}
	pick := func() (netip.Addr, error) {
		i, err := uniform(r, len(dests))
		if err != nil {
			return netip.Addr{}, err
		}
		return dests[i], nil
	}
	var t Table
	add := func(k Kind, p Place, mk func(io.Reader) (string, error)) error {
		if k == KMetadata {
			t.entries = append(t.entries, Entry{Kind: k, Dest: Metadata, Place: p})
			return nil
		}
		v, err := mk(r)
		if err != nil {
			return err
		}
		d, err := pick()
		if err != nil {
			return err
		}
		t.entries = append(t.entries, Entry{Value: v, Kind: k, Dest: d, Place: p})
		return nil
	}
	for _, row := range plan {
		if err := add(row.kind, row.place, gens[row.kind]); err != nil {
			return Table{}, err
		}
	}
	for _, o := range own {
		if !slices.Contains(ownKinds, o.Kind) || o.Make == nil {
			return Table{}, fmt.Errorf("decoy: %q is not a kind the caller makes", o.Kind)
		}
		if err := add(o.Kind, o.Place, o.Make); err != nil {
			return Table{}, err
		}
	}
	if err := t.check(dests); err != nil {
		return Table{}, err
	}
	return t, nil
}

func knownKind(k Kind) bool {
	_, ok := gens[k]
	return ok || k == KMetadata || slices.Contains(ownKinds, k)
}

func knownPlace(p Place) bool {
	switch p {
	case PSandboxEnv, PHostEnv, PHostDotfile, PHostJackpot, PEdgeDotfile,
		PEdgeJackpot, PMetadata, PPlannerView, PSealedStore:
		return true
	}
	return false
}

// check holds a table to the rules: known kinds and places, values from
// MinValue to match.MaxValue bytes, the metadata entry valueless at the metadata address, and
// every other entry a value to a decoy-range address (in range, when range
// is given). A table read back gets the same check, minus the range.
func (t Table) check(rng []netip.Addr) error {
	if len(t.entries) == 0 {
		return ErrBadTable
	}
	for _, e := range t.entries {
		if !knownKind(e.Kind) || !knownPlace(e.Place) || len(e.Value) > match.MaxValue {
			return ErrBadTable
		}
		if e.Kind != KMetadata && len(e.Value) < MinValue {
			return ErrBadTable
		}
		if e.Kind == KMetadata {
			if e.Value != "" || e.Dest != Metadata {
				return ErrBadTable
			}
			continue
		}
		if e.Value == "" || !e.Dest.IsValid() || e.Dest == Metadata ||
			(rng != nil && !slices.Contains(rng, e.Dest)) {
			return ErrBadTable
		}
	}
	return nil
}

// Matcher is the table's matcher: its values, each ID'd by its index, and
// its destinations, with CLK-4's patterns (broker/decoy/match).
func (t Table) Matcher() *match.Matcher {
	var vs []match.Value
	ds := map[netip.Addr]int{}
	for i, e := range t.entries {
		vs = append(vs, match.Value{ID: i, Bytes: []byte(e.Value)})
		if _, ok := ds[e.Dest]; !ok {
			ds[e.Dest] = i
		}
	}
	return match.New(vs, ds)
}

// The table's wire form, in the sealed store and the log alike.
type wireEntry struct {
	V string     `json:"v,omitempty"`
	K Kind       `json:"k"`
	D netip.Addr `json:"d"`
	P Place      `json:"p"`
}

func (t Table) encode() []byte {
	w := make([]wireEntry, len(t.entries))
	for i, e := range t.entries {
		w[i] = wireEntry{e.Value, e.Kind, e.Dest, e.Place}
	}
	b, _ := json.Marshal(w)
	return b
}

func decode(b []byte) (Table, error) {
	var w []wireEntry
	if err := json.Unmarshal(b, &w); err != nil {
		return Table{}, ErrBadTable
	}
	t := Table{entries: make([]Entry, len(w))}
	for i, e := range w {
		t.entries[i] = Entry{e.V, e.K, e.D, e.P}
	}
	if err := t.check(nil); err != nil {
		return Table{}, err
	}
	return t, nil
}

// Digest is SHA-256 of the table's wire form: a name for the table that
// shows none of it.
func (t Table) Digest() [32]byte { return sha256.Sum256(t.encode()) }
