package digestnotes_test

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	dn "github.com/ghbmrk/agentos/broker/digestnotes"
)

// REQ: OP-1, CH-15
func TestInvalidUTCNormalizationCannotPoisonDurableSource(t *testing.T) {
	for _, ordered := range []bool{false, true} {
		for _, at := range []time.Time{
			time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 3600)),
			time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("west", -3600)),
		} {
			st := &change.FileStore{Path: filepath.Join(t.TempDir(), "notes.json")}
			s := source(t, st)
			put := func(id uint64, e dn.Event) error {
				if ordered {
					return s.RecordOnce(id, e)
				}
				return s.Record(e)
			}
			if err := put(1, dn.Event{Dropped: true}); err != nil {
				t.Fatal(err)
			}
			before := peek(t, s)
			if err := put(2, dn.Event{WrongAt: at}); !errors.Is(err, dn.ErrInvalid) {
				t.Errorf("ordered=%v time=%v: committed unrepresentable UTC instant: %v", ordered, at, err)
			}
			if s.Health() != nil {
				t.Fatal("input refusal quarantined a healthy source")
			}
			s = source(t, st)
			if !reflect.DeepEqual(before, peek(t, s)) {
				t.Fatal("input refusal changed durable receipt")
			}
			if err := s.Ack(t.Context(), *before); err != nil {
				t.Fatal(err)
			}
			if peek(t, s) != nil {
				t.Fatal("invalid instant survived acknowledgment")
			}
		}
	}
}

func TestValidUTCBoundariesRemainRecordable(t *testing.T) {
	for _, ordered := range []bool{false, true} {
		st := &change.FileStore{Path: filepath.Join(t.TempDir(), "notes.json")}
		s := source(t, st)
		for i, at := range []time.Time{
			// The exact Go zero time is the absent WrongAt sentinel.
			time.Date(1, 1, 1, 0, 0, 0, 1, time.UTC),
			time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		} {
			var err error
			if ordered {
				err = s.RecordOnce(uint64(i+1), dn.Event{WrongAt: at})
			} else {
				err = s.Record(dn.Event{WrongAt: at})
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		s = source(t, st)
		a := peek(t, s)
		if a == nil || len(a.Wrong) != 2 {
			t.Fatal(a)
		}
		if err := s.Ack(t.Context(), *a); err != nil {
			t.Fatal(err)
		}
	}
}
