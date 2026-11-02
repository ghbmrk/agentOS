package devslot_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture/fake"
)

// REQ: DEV-4

// An operation declares how many frames one run of it writes (#3506).
func TestCheckMaxWrites(t *testing.T) {
	cases := map[string]func(o *devslot.Operation){
		"negative":             func(o *devslot.Operation) { o.MaxWrites = -1 },
		"past the cap":         func(o *devslot.Operation) { o.MaxWrites = devslot.CapWrites + 1 },
		"shapes and no writes": func(o *devslot.Operation) { o.MaxWrites = 0 },
		"writes and no shapes": func(o *devslot.Operation) { o.Shapes, o.MaxWrites = nil, 1 },
	}
	for name, edit := range cases {
		d := fixture.Declaration()
		edit(&d.Operations[0])
		if err := devslot.Check(d, gattPin); !errors.Is(err, devslot.ErrDeclaration) {
			t.Errorf("%s: Check = %v, want ErrDeclaration", name, err)
		}
	}
	controls := map[string]func(o *devslot.Operation){
		"one write":            func(o *devslot.Operation) { o.MaxWrites = 1 },
		"the cap":              func(o *devslot.Operation) { o.MaxWrites = devslot.CapWrites },
		"no shapes, no writes": func(o *devslot.Operation) { o.Shapes, o.MaxWrites = nil, 0 },
	}
	for name, edit := range controls {
		d := fixture.Declaration()
		edit(&d.Operations[0])
		if err := devslot.Check(d, gattPin); err != nil {
			t.Errorf("%s: Check = %v, want nil", name, err)
		}
	}
}

// failWrites is a device that takes no write.
type failWrites struct{ n int }

func (f *failWrites) Write(context.Context, devslot.Target, []byte) error {
	f.n++
	return errors.New("transport: write failed")
}

func (f *failWrites) Read(context.Context) (devslot.Target, []byte, error) {
	return devslot.Target{}, nil, errors.New("transport: nothing to read")
}

// A driver that repeats a declared frame gets MaxWrites of them sent, and
// the operation fails: one approval covers what the operation declares.
func TestSlotWritesAtMostMaxWrites(t *testing.T) {
	repeat := func(n int, errs *[]error) fn {
		return fn{d: fixture.Declaration(), run: func(ctx context.Context, _ string, l devslot.Link, _ devslot.Secrets) ([]devslot.Reading, error) {
			for range n {
				*errs = append(*errs, l.Write(ctx, "control", []byte{fixture.OpGet}))
			}
			return []devslot.Reading{{Kind: "temperature", Value: 1}}, nil
		}}
	}
	max := fixture.Declaration().Operations[0].MaxWrites
	t.Run("past MaxWrites", func(t *testing.T) {
		var r record
		var errs []error
		tr := newTransport(&fake.Device{})
		s, err := devslot.New(repeat(max+2, &errs), env(t, tr, "device/fixture-1", &r))
		if err != nil {
			t.Fatal(err)
		}
		if n, err := s.Do(context.Background(), "read-temperature"); !errors.Is(err, devslot.ErrWrites) || n != 0 {
			t.Fatalf("Do: %d, %v; want ErrWrites", n, err)
		}
		if len(tr.writes) != max || len(r.events) != 0 {
			t.Fatalf("%d frames sent, %d events; want %d frames and none", len(tr.writes), len(r.events), max)
		}
		for i, err := range errs {
			if (i < max) != (err == nil) || (i >= max && !errors.Is(err, devslot.ErrWrites)) {
				t.Errorf("write %d: %v", i, err)
			}
		}
	})
	t.Run("a failed write counts", func(t *testing.T) {
		var r record
		var errs []error
		tr := &failWrites{}
		s, err := devslot.New(repeat(max+1, &errs), env(t, tr, "device/fixture-1", &r))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Do(context.Background(), "read-temperature"); !errors.Is(err, devslot.ErrWrites) || tr.n != max {
			t.Fatalf("Do: %v, %d writes reached the transport; want ErrWrites after %d", err, tr.n, max)
		}
	})
	t.Run("control: MaxWrites writes, and each operation its own", func(t *testing.T) {
		var r record
		var errs []error
		tr := newTransport(&fake.Device{})
		s, err := devslot.New(repeat(max, &errs), env(t, tr, "device/fixture-1", &r))
		if err != nil {
			t.Fatal(err)
		}
		for i := range 2 {
			if n, err := s.Do(context.Background(), "read-temperature"); err != nil || n != 1 {
				t.Fatalf("operation %d: %d, %v", i, n, err)
			}
		}
		if len(tr.writes) != 2*max {
			t.Fatalf("%d frames sent, want %d", len(tr.writes), 2*max)
		}
	})
}
