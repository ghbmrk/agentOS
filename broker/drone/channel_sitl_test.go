//go:build sitl

package drone

import (
	"bufio"
	"bytes"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
)

// REQ: NET-2, A18
// TestCoreGetsOnlyReturnToDock (brief acceptance test 8, P5): mid-flight,
// the core-side socket gets a waypoint, a mode change, a parameter write and
// a raw signed MAVLink frame; each is refused and logged, and the aircraft's
// mission, mode and parameters are unchanged; then return_to_dock is taken
// and the aircraft lands at the dock and disarms.
func TestCoreGetsOnlyReturnToDock(t *testing.T) {
	r, obs := flightRig(t)
	sock := t.TempDir() + "/core.sock"
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r.h.ServeCore(c)
			c.Close()
		}
	}()
	core, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	answers := bufio.NewReader(core)
	say := func(line string) string {
		t.Helper()
		if _, err := core.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
		core.SetReadDeadline(time.Now().Add(30 * time.Second))
		a, err := answers.ReadString('\n')
		if err != nil {
			t.Fatalf("no answer to %q: %v", line, err)
		}
		return strings.TrimSpace(a)
	}

	if err := r.h.Fly(signFlight(t, newFlight(t, "north"), r.owner)); err != nil {
		t.Fatalf("starting the flight: %v\nlog:\n%s", err, r.logs)
	}
	airborne(t, obs)
	type state struct {
		Mission []Item
		Params  map[string]float32
	}
	read := func() state {
		t.Helper()
		m, err := obs.Download(MissionMission)
		if err != nil {
			t.Fatal(err)
		}
		s := state{Mission: m[1:], Params: map[string]float32{}} // item 0 is home
		for _, n := range Derive(r.h.Policy()).ReadBackNames() {
			v, err := obs.GetParam(n)
			if err != nil {
				t.Fatal(err)
			}
			s.Params[n] = v
		}
		return s
	}
	before := read()

	// A raw MAVLink frame on the core side: a DO_SET_MODE to GUIDED.
	var raw bytes.Buffer
	send(t, newSender(t, &raw, nil, 0), long(common.MAV_CMD_DO_SET_MODE, 1, ModeGuided))
	attempts := []string{
		"waypoint -35.362 149.166 30",
		"mode GUIDED",
		"set_mode 4",
		"param FENCE_ENABLE 0",
		"FENCE_ENABLE=0",
		"return_to_dock now",
		string(bytes.ReplaceAll(raw.Bytes(), []byte("\n"), nil)),
	}
	for _, a := range attempts {
		mark := len(r.logs.String())
		if got := say(a); got != "refused" {
			t.Errorf("%q answered %q", a, got)
		}
		if !r.logged(mark, "core side refused") {
			t.Errorf("%q: the refusal was not logged", a)
		}
	}
	if hb := heartbeat(t, obs); !hb.Armed || hb.CustomMode != ModeAuto {
		t.Fatalf("after the refused lines the aircraft is in mode %d (armed %v), want AUTO", hb.CustomMode, hb.Armed)
	}
	if after := read(); !reflect.DeepEqual(before, after) {
		t.Fatalf("the refused lines changed the aircraft:\nbefore %+v\nafter  %+v", before, after)
	}

	mark := len(r.logs.String())
	if got := say(returnToDock); got != "ok" {
		t.Fatalf("return_to_dock answered %q\nlog:\n%s", got, r.logs)
	}
	if !r.logged(mark, "return to dock: the core side asked") {
		t.Error("the return was not logged")
	}
	if hb := heartbeat(t, obs); hb.CustomMode != ModeRTL {
		t.Errorf("after return_to_dock the mode is %d, want RTL", hb.CustomMode)
	}
	requireLandedAtDock(t, obs, "return_to_dock")
}
