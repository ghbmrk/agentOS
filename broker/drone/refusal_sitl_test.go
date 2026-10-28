//go:build sitl

package drone

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
	"github.com/bluenviron/gomavlib/v3/pkg/frame"
	"github.com/bluenviron/gomavlib/v3/pkg/message"
)

// Copter custom modes.
const (
	modeStabilize = 0
	modeAuto      = 3
	modeGuided    = 4
	modeLand      = 9
)

type attack struct {
	name string
	msgs []message.Message
}

func long(cmd common.MAV_CMD, p ...float32) *common.MessageCommandLong {
	m := &common.MessageCommandLong{TargetSystem: targetSysID, TargetComponent: targetCompID, Command: cmd}
	ps := []*float32{&m.Param1, &m.Param2, &m.Param3, &m.Param4, &m.Param5, &m.Param6, &m.Param7}
	for i, v := range p {
		*ps[i] = v
	}
	return m
}

func paramSet(name string, v float32) *common.MessageParamSet {
	return &common.MessageParamSet{TargetSystem: targetSysID, TargetComponent: targetCompID, ParamId: name,
		ParamValue: v, ParamType: common.MAV_PARAM_TYPE_REAL32}
}

func count(kind common.MAV_MISSION_TYPE, n uint16) *common.MessageMissionCount {
	return &common.MessageMissionCount{TargetSystem: targetSysID, TargetComponent: targetCompID, Count: n, MissionType: kind}
}

// attacks is every way to change the aircraft over MAVLink the brief names:
// commands, a parameter write, mission, fence and rally uploads and clears,
// a MAVLink FTP write, a re-key, a reboot and an RC override.
func attacks() []attack {
	home := itemMsg(MissionMission, 0, Item{Command: uint16(common.MAV_CMD_NAV_WAYPOINT), Lat: e7(testDock.Lat), Lon: e7(testDock.Lon)})
	far := itemMsg(MissionMission, 1, Item{Command: uint16(common.MAV_CMD_NAV_WAYPOINT), Lat: e7(at(500, 500).Lat), Lon: e7(at(500, 500).Lon), AltM: 100})
	fenceVertex := itemMsg(MissionFence, 0, Item{Command: cmdFenceInclusion, Param1: 3, Lat: e7(at(5000, 0).Lat), Lon: e7(at(5000, 0).Lon)})
	rally := itemMsg(MissionRally, 0, Item{Command: cmdRallyPoint, Lat: e7(at(300, 300).Lat), Lon: e7(at(300, 300).Lon), AltM: 50})
	var badKey [32]uint8
	copy(badKey[:], "ATTACKER-KEY-not-the-holders-key")
	override := &common.MessageRcChannelsOverride{TargetSystem: targetSysID, TargetComponent: targetCompID,
		Chan1Raw: 1500, Chan2Raw: 1500, Chan3Raw: 1000, Chan4Raw: 2000, Chan5Raw: 1295, Chan6Raw: 1500, Chan7Raw: 1500, Chan8Raw: 1500}
	return []attack{
		{"arm (forced)", []message.Message{long(common.MAV_CMD_COMPONENT_ARM_DISARM, 1, 21196)}},
		{"mode change (DO_SET_MODE guided)", []message.Message{long(common.MAV_CMD_DO_SET_MODE, 1, modeGuided)}},
		{"mode change (SET_MODE auto)", []message.Message{&common.MessageSetMode{TargetSystem: targetSysID, BaseMode: 1, CustomMode: modeAuto}}},
		{"fence off (DO_FENCE_ENABLE 0)", []message.Message{long(common.MAV_CMD_DO_FENCE_ENABLE, 0)}},
		{"parameter write FENCE_ENABLE 0", []message.Message{paramSet("FENCE_ENABLE", 0)}},
		{"parameter write SCR_ENABLE 1", []message.Message{paramSet("SCR_ENABLE", 1)}},
		{"parameter write MAV1_OPTIONS 1 (signing off)", []message.Message{paramSet("MAV1_OPTIONS", 1)}},
		{"mission upload", []message.Message{count(MissionMission, 2), home, far}},
		{"fence upload (one far vertex)", []message.Message{count(MissionFence, 1), fenceVertex}},
		{"fence clear (count 0)", []message.Message{count(MissionFence, 0)}},
		{"fence and rally clear (CLEAR_ALL)", []message.Message{
			&common.MessageMissionClearAll{TargetSystem: targetSysID, TargetComponent: targetCompID, MissionType: MissionFence},
			&common.MessageMissionClearAll{TargetSystem: targetSysID, TargetComponent: targetCompID, MissionType: MissionRally}}},
		{"rally upload", []message.Message{count(MissionRally, 1), rally}},
		{"MAVLink FTP write", []message.Message{ftp(1, 0, ftpCreateFile, 0, []byte("/canary.lua")),
			ftp(2, 0, ftpWriteFile, 0, []byte("-- canary")), ftp(3, 0, ftpTerminate, 0, nil)}},
		{"re-key (SETUP_SIGNING)", []message.Message{&common.MessageSetupSigning{TargetSystem: targetSysID,
			TargetComponent: targetCompID, SecretKey: badKey, InitialTimestamp: 1}}},
		{"reboot", []message.Message{long(common.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN, 1)}},
		{"RC override (arm stick, mode switch)", []message.Message{override, override, override}},
	}
}

// REQ: NET-2, A18
// TestUnsignedFramesChangeNothing (brief acceptance test 1, P1): each attack,
// sent unsigned and signed with a wrong key on every serial port SITL exposes
// (the port the key-holder had first included, so channel 0 too), leaves the
// parameters, fences, mission and mode as they were and the aircraft disarmed.
func TestUnsignedFramesChangeNothing(t *testing.T) {
	r := newRig(t, true)
	ports := r.sim.Ports()
	wrong := frame.NewV2Key([]byte("WRONG-KEY-for-the-refusal-tests!"))
	// The FTP check's positive control: the same requests, signed with the
	// key, do create the file, so its absence below means a refusal.
	ctl := r.sim.Dial(ports[1])
	send(t, newSender(t, ctl, r.key.s(), 9), ftp(1, 0, ftpCreateFile, 0, []byte("/canary-control.lua")), ftp(2, 0, ftpTerminate, 0, nil))
	time.Sleep(time.Second)
	ctl.Close()
	if len(canaryFiles(t, r.sim.Dir)) != 1 {
		t.Fatalf("a signed FTP create made %v; the FTP check cannot see a write", canaryFiles(t, r.sim.Dir))
	}
	control := canaryFiles(t, r.sim.Dir)[0]
	before := r.snapshot()
	if before.Armed || len(before.Fence) == 0 || len(before.Rally) != 1 {
		t.Fatalf("baseline is not the loaded policy: %+v", before)
	}
	run := func(port int) {
		for _, a := range attacks() {
			for _, mode := range []struct {
				name string
				key  *frame.V2Key
			}{{"unsigned", nil}, {"wrong key", wrong}} {
				what := fmt.Sprintf("%s, %s, port %d", a.name, mode.name, port)
				c := r.sim.Dial(port)
				send(t, newSender(t, c, mode.key, 3), a.msgs...)
				time.Sleep(1500 * time.Millisecond)
				c.Close()
				time.Sleep(300 * time.Millisecond)
				r.requireSame(before, what)
				if got := canaryFiles(t, r.sim.Dir); len(got) != 1 || got[0] != control {
					t.Errorf("%s: FTP files %v", what, got)
				}
			}
		}
	}
	for _, p := range ports[1:] {
		run(p)
	}
	// Now from the port the key-holder held (SERIAL0, MAVLink channel 0 on stock firmware).
	r.moveTo(ports[1])
	run(ports[0])
	if err := r.h.ReadBack(); err != nil {
		t.Errorf("after the attacks: %v", err)
	}
}

// REQ: NET-2
// TestReplayedSignedFrameIsRefused (brief acceptance test 2): a captured
// signed parameter write, replayed after a later signed frame on its stream,
// is refused on its own port, on another port and on a fresh connection.
func TestReplayedSignedFrameIsRefused(t *testing.T) {
	r := newRig(t, true)
	ports := r.sim.Ports()
	var captured bytes.Buffer
	newSender(t, &captured, r.key.s(), 7).WriteMessage(paramSet("FENCE_ALT_MAX", 50))
	frameBytes := append([]byte(nil), captured.Bytes()...)

	c := r.sim.Dial(ports[1])
	defer c.Close()
	w := newSender(t, c, r.key.s(), 7)
	// The captured frame is valid: sent first, it takes effect.
	c.Write(frameBytes)
	if v := waitParam(t, r, "FENCE_ALT_MAX", 50); v != 50 {
		t.Fatalf("the captured signed frame did not take effect (FENCE_ALT_MAX %v); the replay check would be vacuous", v)
	}
	// A later signed frame on the same stream restores the limit.
	time.Sleep(20 * time.Millisecond)
	send(t, w, paramSet("FENCE_ALT_MAX", 60))
	if v := waitParam(t, r, "FENCE_ALT_MAX", 60); v != 60 {
		t.Fatalf("the later signed frame did not take effect: %v", v)
	}
	replays := []struct {
		name string
		conn func() net.Conn
	}{
		{"same connection", func() net.Conn { return c }},
		{"other port", func() net.Conn { return r.sim.Dial(ports[2]) }},
	}
	for _, rp := range replays {
		conn := rp.conn()
		conn.Write(frameBytes)
		time.Sleep(1500 * time.Millisecond)
		if v, err := r.link.GetParam("FENCE_ALT_MAX"); err != nil || v != 60 {
			t.Errorf("replay on %s: FENCE_ALT_MAX is %v (%v), want 60", rp.name, v, err)
		}
	}
	c.Close()
	time.Sleep(500 * time.Millisecond)
	fresh := r.sim.Dial(ports[1])
	defer fresh.Close()
	fresh.Write(frameBytes)
	time.Sleep(1500 * time.Millisecond)
	if v, err := r.link.GetParam("FENCE_ALT_MAX"); err != nil || v != 60 {
		t.Errorf("replay on a fresh connection: FENCE_ALT_MAX is %v (%v), want 60", v, err)
	}
	if err := r.h.ReadBack(); err != nil {
		t.Errorf("after the replays: %v", err)
	}
}

func waitParam(t *testing.T, r *rig, name string, want float32) float32 {
	t.Helper()
	var v float32
	for i := 0; i < 20; i++ {
		var err error
		if v, err = r.link.GetParam(name); err == nil && v == want {
			return v
		}
		time.Sleep(250 * time.Millisecond)
	}
	return v
}

// rcPacket is SITL's UDP RC input: 16 little-endian PWM values.
func rcPacket(ch5, throttle, yaw uint16) []byte {
	pwm := [16]uint16{1500, 1500, throttle, yaw, ch5, 1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500, 1500}
	b := make([]byte, 32)
	for i, v := range pwm {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}

func sendRC(t *testing.T, port int, pkt []byte, d time.Duration) {
	t.Helper()
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		c.Write(pkt)
	}
}

// REQ: NET-2
// TestScriptingAndRCAreOff (brief acceptance test 6): SCR_ENABLE reads back
// 0, and with the policy loaded no RC input (the simulator's RC port, or an
// unsigned RC override) changes the mode or arms; before the policy, the same
// RC input does change the mode, so the check can see one.
func TestScriptingAndRCAreOff(t *testing.T) {
	r := newRig(t, false)
	// Positive control on stock RC settings: switch position 2 is LAND (copter.parm FLTMODE2).
	sendRC(t, r.sim.RCPort(), rcPacket(1295, 1000, 1500), 3*time.Second)
	if hb, err := r.link.WaitHeartbeat(time.Now(), 5*time.Second); err != nil || hb.CustomMode != modeLand {
		t.Fatalf("before the policy, RC did not change the mode (mode %d, %v); the RC check would be vacuous", hb.CustomMode, err)
	}
	if err := r.h.Load(signPolicy(t, testPolicy(), r.owner)); err != nil {
		t.Fatalf("loading the policy: %v\n%s", err, r.logs)
	}
	if v, err := r.link.GetParam("SCR_ENABLE"); err != nil || v != 0 {
		t.Errorf("SCR_ENABLE reads back %v (%v), want 0", v, err)
	}
	before := r.snapshot()
	for _, pos := range []uint16{1165, 1425, 1555, 1685, 1815} {
		sendRC(t, r.sim.RCPort(), rcPacket(pos, 1000, 1500), 2*time.Second)
	}
	// Throttle low, yaw right: the stick arming gesture, held past its 2 s.
	sendRC(t, r.sim.RCPort(), rcPacket(1295, 1000, 2000), 4*time.Second)
	r.requireSame(before, "RC input on the simulator's RC port")
	c := r.sim.Dial(r.sim.Ports()[1])
	defer c.Close()
	w := newSender(t, c, nil, 4)
	for i := 0; i < 40; i++ {
		send(t, w, &common.MessageRcChannelsOverride{TargetSystem: targetSysID, TargetComponent: targetCompID,
			Chan1Raw: 1500, Chan2Raw: 1500, Chan3Raw: 1000, Chan4Raw: 2000, Chan5Raw: 1815, Chan6Raw: 1500, Chan7Raw: 1500, Chan8Raw: 1500})
	}
	r.requireSame(before, "an unsigned RC override")
}
