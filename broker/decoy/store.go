package decoy

import (
	"encoding/json"
	"errors"
)

// The table in the sealed store (STO-2): one entry, which the kernel, a core
// package, writes and reads itself, so this package is handed no write path
// of the store. It is readable only by a process that has unlocked the
// store. At first boot the kernel reads StoreEntry; if the store holds it,
// Load gives the table, and otherwise it Generates one and Puts its Stored
// form before logging Event. A boot cut short between that Put and the log
// write therefore logs the same table the store holds, never a second one.

// StoreEntry is the table's name in the sealed store.
const StoreEntry = "decoy/table"

// MaxStored bounds the table's stored form: one sealed-store entry
// (seal.MaxEntry).
const MaxStored = 4 << 10

// ErrTooBig: the table does not fit one sealed-store entry.
var ErrTooBig = errors.New("decoy: the table does not fit one sealed-store entry")

// Stored is the table's sealed-store form.
func Stored(t Table) ([]byte, error) {
	b := t.encode()
	if len(b) > MaxStored {
		return nil, ErrTooBig
	}
	return b, nil
}

// Load reads the table back from its sealed-store form.
func Load(b []byte) (Table, error) {
	if len(b) > MaxStored {
		return Table{}, ErrBadTable
	}
	return decode(b)
}

// The kernel's table event (KRN-1): one log entry, at first boot, whose body
// is the whole table. Replaying the log rebuilds the table from it, never
// from the store or a generator, so the same log gives the same trips
// whatever code the replay runs (KRN-6).
const (
	EventType    = "decoy.table"
	EventVersion = 1
)

// Event is the table event's body.
func Event(t Table) json.RawMessage { return t.encode() }

// FromEvent rebuilds the table from a logged table event.
func FromEvent(v int, body json.RawMessage) (Table, error) {
	if v != EventVersion {
		return Table{}, ErrBadTable
	}
	return decode(body)
}
