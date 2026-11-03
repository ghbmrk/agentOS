package channel

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// CheckSink reports whether a log sink keeps every Event field. keep stores
// e as the sink stores Config.Log's lines and returns the Event it reads
// back, which the owner's log renders (Line, Detail). Each field is set on
// its own and then all at once, found by reflection, so every sink's test
// that calls CheckSink covers a field added to Event later without a change
// to it. A sink that loses a field fails, such as one that drops Dropped,
// which breaks the record's sum: the logged lines plus the sum of Dropped
// are everything the cut core sent (ENF-d-4, #4709). At must come back to
// the same instant, to the nanosecond.
func CheckSink(keep func(Event) (Event, error)) error {
	samples, err := eventSamples()
	if err != nil {
		return err
	}
	for _, s := range samples {
		got, err := keep(s.e)
		if err != nil {
			return fmt.Errorf("channel: the sink failed to keep %s: %w", s.field, err)
		}
		if !sameEvent(got, s.e) {
			return fmt.Errorf("channel: the sink lost %s: stored %+v, read back %+v", s.field, s.e, got)
		}
	}
	return nil
}

type sample struct {
	field string // the field set, or "every field"
	e     Event
}

// eventSamples is one Event per value of fieldValues with only that field
// set, then, for each j, one with every field set to its j-th value (the
// last value where a field has fewer). A field of a kind fieldValues cannot
// set is an error, so a new field of a new kind fails every sink's check
// until it is taught there.
func eventSamples() ([]sample, error) {
	typ := reflect.TypeFor[Event]()
	vals := make([][]reflect.Value, typ.NumField())
	most := 0
	for i := range typ.NumField() {
		vs, err := fieldValues(typ.Field(i).Type)
		if err != nil {
			return nil, fmt.Errorf("channel: Event.%s: %w", typ.Field(i).Name, err)
		}
		vals[i], most = vs, max(most, len(vs))
	}
	var out []sample
	for i, vs := range vals {
		for _, v := range vs {
			var e Event
			reflect.ValueOf(&e).Elem().Field(i).Set(v)
			out = append(out, sample{"Event." + typ.Field(i).Name, e})
		}
	}
	for j := range most {
		var all Event
		for i, vs := range vals {
			reflect.ValueOf(&all).Elem().Field(i).Set(vs[min(j, len(vs)-1)])
		}
		out = append(out, sample{"every field", all})
	}
	return out, nil
}

// fieldValues are the values a sink must keep in a field of type t, none
// of them its zero, each one a sink may meet in a real line, so a sink
// that narrows a field or writes a constant into it gets one back changed
// (#4791 L3, Security): an integer at both ends of its type (a Dropped
// past 2^31, an ID past 2^53), a name of wire.MaxName bytes with
// separators and characters outside ASCII, two kinds and two codes, and times off UTC
// with nanoseconds at both ends of the years a line can carry.
func fieldValues(t reflect.Type) ([]reflect.Value, error) {
	of := func(xs ...any) []reflect.Value {
		vs := make([]reflect.Value, len(xs))
		for i, x := range xs {
			vs[i] = reflect.ValueOf(x).Convert(t)
		}
		return vs
	}
	switch t {
	case reflect.TypeFor[time.Time]():
		return of(
			time.Date(2026, 11, 2, 21, 58, 11, 123456789, time.FixedZone("", -5*3600)),
			time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.FixedZone("", 14*3600)),
		), nil
	case reflect.TypeFor[Kind]():
		return of(KindPaused, KindTrip), nil
	case reflect.TypeFor[wire.Code]():
		return of(wire.Paused, wire.Failed), nil
	}
	switch k := t.Kind(); {
	case k == reflect.String:
		return of("x", longName), nil
	case k >= reflect.Int && k <= reflect.Int64:
		bits := uint(t.Bits())
		return of(int64(7), int64(1)<<(bits-1)-1, -int64(1)<<(bits-1)), nil
	case k >= reflect.Uint && k <= reflect.Uint64:
		return of(uint64(7), ^uint64(0)>>(64-uint(t.Bits()))), nil
	}
	return nil, fmt.Errorf("a field of kind %s: teach fieldValues to set it", t.Kind())
}

// longName is a name as long as wire.Name takes, every byte printable,
// with the separators a sink might join fields with and characters outside
// ASCII of two, three and four bytes, so a sink that splits, cuts or
// re-encodes a string gets one back changed (#4791 Security).
var longName = func() string {
	const unit = "a|b,c / d;e:f=g\u00e9\u2014\U0001d11e"
	var b strings.Builder
	for b.Len()+len(unit) <= wire.MaxName {
		b.WriteString(unit)
	}
	b.WriteString(strings.Repeat("z", wire.MaxName-b.Len()))
	return b.String()
}()

// sameEvent is a == b with At compared as an instant, since a sink may
// keep the offset without the zone's name.
func sameEvent(a, b Event) bool {
	if !a.At.Equal(b.At) {
		return false
	}
	a.At, b.At = time.Time{}, time.Time{}
	return a == b
}
