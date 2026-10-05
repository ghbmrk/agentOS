package at_test

// REQ: TIM-1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/atsim"
)

func TestTIM1NetworkTimeBothVendors(t *testing.T) {
	ctx := context.Background()
	want := time.Date(2026, 10, 5, 4, 10, 22, 0, time.UTC)
	for _, v := range vendors {
		for _, zone := range []int{0, 8, -20, 22} { // UTC, +2h, -5h, +5:30
			r := newRig(t, v, at.KeysInBand, func(d *atsim.Device) { d.SetNetworkTime(want, zone) })
			got, err := r.m.NetworkTime(ctx)
			if err != nil {
				t.Fatalf("%s zone %d: %v", v.prof.Name, zone, err)
			}
			if d := got.Sub(want); d < 0 || d > 5*time.Second {
				t.Fatalf("%s zone %d: got %v, want %v", v.prof.Name, zone, got, want)
			}
		}
	}
}

func TestTIM1NoNetworkTime(t *testing.T) {
	// Quectel answers "" until the network sends a time; SIMCom's clock
	// still holds its power-up date, which must not count as carrier time.
	for _, v := range vendors {
		r := newRig(t, v, at.KeysInBand, nil)
		if _, err := r.m.NetworkTime(context.Background()); !errors.Is(err, at.ErrNoNetworkTime) {
			t.Fatalf("%s: err = %v, want ErrNoNetworkTime", v.prof.Name, err)
		}
	}
}

func TestTIM1ModemIsTheGuardsCarrier(t *testing.T) {
	// End to end: a box clock three hours fast against the simulated
	// network restricts time-sensitive checks.
	for _, v := range vendors {
		net := time.Now().UTC()
		r := newRig(t, v, at.KeysInBand, func(d *atsim.Device) { d.SetNetworkTime(net, 4) })
		var texts []string
		g, err := clock.New(clock.Config{
			Synced:  func() (bool, error) { return true, nil },
			Carrier: r.m.NetworkTime,
			Now:     func() time.Time { return time.Now().Add(3 * time.Hour) },
			Notify:  func(s string) { texts = append(texts, s) },
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Now(context.Background()); !errors.Is(err, clock.ErrRestricted) {
			t.Fatalf("%s: err = %v", v.prof.Name, err)
		}
		g.Flush()
		if len(texts) != 1 {
			t.Fatalf("%s: texts = %q", v.prof.Name, texts)
		}
	}
}

func TestTIM1RefusedCTZUStillOpens(t *testing.T) {
	// CTZU is best effort: a SIMCom module that refuses it still texts and
	// calls (security C3 on #68).
	for _, c := range at.SIMCom.Init {
		if c == at.SIMCom.NetTimeOn {
			t.Fatalf("%s is in Init, where a refusal aborts Open", c)
		}
	}
	r := newRig(t, vendor{at.SIMCom, "SIMCOM_SIM7600G-H"}, at.KeysInBand, func(d *atsim.Device) { d.RefuseCTZU() })
	if _, err := r.m.NetworkTime(context.Background()); !errors.Is(err, at.ErrNoNetworkTime) {
		t.Fatalf("err = %v", err)
	}
}
