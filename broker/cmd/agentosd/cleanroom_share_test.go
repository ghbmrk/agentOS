package main

import (
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/cleanroom"
	"github.com/ghbmrk/agentos/broker/loopbuild"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: LOOP-2, LOOP-5
//
// W5c-ps2: spare shares name eval, builder, and clean-room Max.

func TestW5cPS2SpareSharesIncludeCleanRoom(t *testing.T) {
	shares := []meter.Share{
		{Prefix: vm.EvalPrefix, Reserve: loops.EvalReserve},
		builderShare(),
		cleanroomShare(),
	}
	if shares[2].Prefix != cleanroom.Prefix || shares[2].Max != cleanroom.SpareShareMax {
		t.Fatalf("cleanroom share %+v", shares[2])
	}
	if shares[1].Prefix != loopbuild.Prefix || shares[1].Max != builderShareMax {
		t.Fatalf("builder share %+v", shares[1])
	}
	m, err := meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "spare.json"),
		MachineCap: meter.DefaultMachineCap,
		OverallCap: loops.SpareLimits(loops.DefaultSpareCalls),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetShares(shares); err != nil {
		t.Fatal(err)
	}
}
