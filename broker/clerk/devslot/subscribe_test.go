package devslot_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: DEV-8, DEV-4, DEV-2

// withWatch is the fixture with a subscription.
func withWatch() devslot.Declaration {
	d := fixture.Declaration()
	d.Operations = append(d.Operations, devslot.Operation{Name: "watch", Verb: key.Read, Shapes: []string{"get"}, Subscribe: true})
	return d
}

// runDriver is a driver whose Run is run.
type runDriver struct {
	d   devslot.Declaration
	run func(l devslot.Link) ([]devslot.Reading, error)
}

func (r runDriver) Declare() devslot.Declaration { return r.d }

func (r runDriver) Run(_ context.Context, _ string, l devslot.Link, _ devslot.Secrets) ([]devslot.Reading, error) {
	return r.run(l)
}

// silent is a device with nothing to say.
type silent struct{}

func (silent) Write(context.Context, devslot.Target, []byte) error { return nil }

func (silent) Read(context.Context) (devslot.Target, []byte, error) {
	return devslot.Target{}, nil, errors.New("silent")
}

func temp(v int64) devslot.Reading {
	return devslot.Reading{Kind: "temperature", Value: v, Exp: -2, Time: time.Unix(0x65000000, 0).In(time.FixedZone("Europe/Paris", 3600))}
}

func TestSlotSubscriptionReportsEachReading(t *testing.T) {
	var events []devslot.Event
	var seen []int // how many events were out at each Report's return
	drv := runDriver{d: withWatch(), run: func(l devslot.Link) ([]devslot.Reading, error) {
		for v := range int64(3) {
			if err := l.Report(temp(v)); err != nil {
				return nil, err
			}
			seen = append(seen, len(events))
		}
		return nil, nil
	}}
	s, err := devslot.New(drv, devslot.Env{Pin: gattPin, Transport: silent{},
		Emit: func(e devslot.Event) error { events = append(events, e); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.Do(context.Background(), "watch"); n != 3 || err != nil {
		t.Fatalf("Do: %d, %v", n, err)
	}
	if fmt.Sprint(seen) != "[1 2 3]" {
		t.Fatalf("events out at each report: %v, want each at once", seen)
	}
	for _, e := range events {
		if e.Op != "watch" || e.Label != devslot.Label || !e.Unverified || e.Reading.Time.Location() != time.UTC {
			t.Fatalf("event %+v", e)
		}
	}
}

func TestSlotRefusesReportOutsideSubscription(t *testing.T) {
	cases := map[string]struct {
		op  string
		run func(l devslot.Link) ([]devslot.Reading, error)
		n   int
	}{
		"report in a one-shot operation": {"read-temperature", func(l devslot.Link) ([]devslot.Reading, error) {
			l.Report(temp(1))
			return nil, nil
		}, 0},
		"readings returned by a subscription": {"watch", func(l devslot.Link) ([]devslot.Reading, error) {
			return []devslot.Reading{temp(1)}, nil
		}, 0},
		"undeclared kind, after one reading": {"watch", func(l devslot.Link) ([]devslot.Reading, error) {
			l.Report(temp(1))
			l.Report(devslot.Reading{Kind: "humidity"})
			l.Report(temp(2))
			return nil, nil
		}, 1},
		"exponent out of range": {"watch", func(l devslot.Link) ([]devslot.Reading, error) {
			l.Report(devslot.Reading{Kind: "temperature", Exp: 19})
			return nil, nil
		}, 0},
	}
	for name, c := range cases {
		var events []devslot.Event
		s, err := devslot.New(runDriver{d: withWatch(), run: c.run}, devslot.Env{Pin: gattPin, Transport: silent{},
			Emit: func(e devslot.Event) error { events = append(events, e); return nil }})
		if err != nil {
			t.Fatal(err)
		}
		n, err := s.Do(context.Background(), c.op)
		if !errors.Is(err, devslot.ErrReading) || n != c.n || len(events) != c.n {
			t.Errorf("%s: %d, %v, %d events; want ErrReading and %d", name, n, err, len(events), c.n)
		}
	}
	// A kept link reports nothing once its operation has ended.
	var kept devslot.Link
	s, _ := devslot.New(runDriver{d: withWatch(), run: func(l devslot.Link) ([]devslot.Reading, error) {
		kept = l
		return nil, nil
	}}, devslot.Env{Pin: gattPin, Transport: silent{}, Emit: func(devslot.Event) error { return nil }})
	s.Do(context.Background(), "watch")
	if err := kept.Report(temp(1)); !errors.Is(err, devslot.ErrClosed) {
		t.Fatalf("Report after the subscription ended: %v", err)
	}
}

func TestCheckSubscriptions(t *testing.T) {
	if err := devslot.Check(withWatch(), gattPin); err != nil {
		t.Fatalf("a read subscription was refused: %v", err)
	}
	d := withWatch()
	d.Operations[1].Verb = key.Actuate
	if err := devslot.Check(d, gattPin); err == nil {
		t.Errorf("an actuate subscription was accepted")
	}
	d = fixture.Declaration()
	for i := range devslot.CapKinds {
		d.Readings = append(d.Readings, fmt.Sprintf("kind-%d", i))
	}
	if err := devslot.Check(d, gattPin); err == nil {
		t.Errorf("%d reading kinds were accepted, over the cap of %d", len(d.Readings), devslot.CapKinds)
	}
	// A declaration with no subscription keeps its canonical bytes.
	b, _ := devslot.Canonical(fixture.Declaration())
	if want := `"Subscribe"`; bytes.Contains(b, []byte(want)) {
		t.Errorf("canonical form of a one-shot declaration names %s: %s", want, b)
	}
}

// TestHomeRefusesTranslatedPrefixes: a home /56 or a pin inside a prefix
// that carries IPv4 addresses would reach the IPv4 internet (L3 6450413836
// point 1 on #3480).
func TestHomeRefusesTranslatedPrefixes(t *testing.T) {
	cases := []struct{ host, home string }{
		{"64:ff9b::808:808", "64:ff9b::/56"},
		{"64:ff9b::c0a8:101", "64:ff9b::/56"},
		{"64:ff9b:1::808:808", "64:ff9b:1::/56"},
		{"2002:808:808::1", "2002:808:808::/56"},
		{"2001:0:4136:e378::1", "2001:0:4136:e300::/56"},
	}
	for _, c := range cases {
		p := devslot.Pin{Host: netip.MustParseAddr(c.host), Key: [32]byte{9}}
		if err := devslot.Check(tcpDecl(), p, netip.MustParsePrefix(c.home)); err == nil {
			t.Errorf("%s in home %s was accepted", c.host, c.home)
		}
	}
	// A real home /56 next to them still holds home addresses.
	p := devslot.Pin{Host: netip.MustParseAddr("2a02:1234:5678:abcd::5"), Key: [32]byte{9}}
	if err := devslot.Check(tcpDecl(), p, netip.MustParsePrefix("2a02:1234:5678:ab00::/56")); err != nil {
		t.Fatalf("a global home address was refused: %v", err)
	}
}
