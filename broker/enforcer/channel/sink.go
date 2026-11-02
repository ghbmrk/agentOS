package channel

import (
	"fmt"
	"reflect"
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

// eventSamples is one Event per field with only that field set, then one
// with every field set. A field of a kind it cannot set is an error, so a
// new field of a new kind fails every sink's check until it is taught here.
func eventSamples() ([]sample, error) {
	var out []sample
	var all Event
	typ := reflect.TypeOf(all)
	for i := range typ.NumField() {
		var e Event
		for _, ev := range []*Event{&e, &all} {
			if err := setField(reflect.ValueOf(ev).Elem().Field(i)); err != nil {
				return nil, fmt.Errorf("channel: Event.%s: %w", typ.Field(i).Name, err)
			}
		}
		out = append(out, sample{"Event." + typ.Field(i).Name, e})
	}
	return append(out, sample{"every field", all}), nil
}

// setField sets v to a value other than its zero, one a sink may meet in a
// real line: a known kind and code, a time off UTC with nanoseconds.
func setField(v reflect.Value) error {
	switch v.Type() {
	case reflect.TypeFor[time.Time]():
		v.Set(reflect.ValueOf(time.Date(2026, 11, 2, 21, 58, 11, 123456789, time.FixedZone("", -5*3600))))
	case reflect.TypeFor[Kind]():
		v.Set(reflect.ValueOf(KindPaused))
	case reflect.TypeFor[wire.Code]():
		v.Set(reflect.ValueOf(wire.Paused))
	default:
		switch {
		case v.Kind() == reflect.String:
			v.SetString("x")
		case v.CanInt():
			v.SetInt(7)
		case v.CanUint():
			v.SetUint(7)
		default:
			return fmt.Errorf("a field of kind %s: teach setField to set it", v.Kind())
		}
	}
	return nil
}

// sameEvent is a == b with At compared as an instant, since a sink may
// keep the offset without the zone's name.
func sameEvent(a, b Event) bool {
	if !a.At.Equal(b.At) {
		return false
	}
	a.At, b.At = time.Time{}, time.Time{}
	return a == b
}
