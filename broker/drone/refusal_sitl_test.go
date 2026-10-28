//go:build sitl

package drone

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
	"github.com/bluenviron/gomavlib/v3/pkg/frame"
	"github.com/bluenviron/gomavlib/v3/pkg/message"
)

// Copter custom modes.
const (
	modeAuto   = 3
	modeGuided = 4
	modeLand   = 9
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
// a MAVLink FTP write, a re-key and a reboot. Each one, sent signed with the
// key, changes what snapshot reads or breaks the link (re-key, reboot); the
// rows whose change is not plain from a parameter (fence off, fence upload,
// FTP) get that positive control in TestUnsignedFramesChangeNothing.
//
// RC_CHANNELS_OVERRIDE is not a row: once the policy is loaded the aircraft
// ignores it even signed, so no snapshot could tell a refusal from an
// acceptance. RC input is covered by TestScriptingAndRCAreOff.
func attacks() []attack {
	home := itemMsg(MissionMission, 0, Item{Command: uint16(common.MAV_CMD_NAV_WAYPOINT), Lat: e7(testDock.Lat), Lon: e7(testDock.Lon)})
	far := itemMsg(MissionMission, 1, Item{Command: uint16(common.MAV_CMD_NAV_WAYPOINT), Lat: e7(at(500, 500).Lat), Lon: e7(at(500, 500).Lon), AltM: 100})
	var fence []message.Message
	for i, p := range []Point{at(5000, 0), at(-2500, 4000), at(-2500, -4000)} {
		fence = append(fence, itemMsg(MissionFence, uint16(i), Item{Command: cmdFenceInclusion, Param1: 3, Lat: e7(p.Lat), Lon: e7(p.Lon)}))
	}
	rally := itemMsg(MissionRally, 0, Item{Command: cmdRallyPoint, Lat: e7(at(300, 300).Lat), Lon: e7(at(300, 300).Lon), AltM: 50})
	var badKey [32]uint8
	copy(badKey[:], "ATTACKER-KEY-not-the-holders-key")
	return []attack{
		{"arm (forced)", []message.Message{long(common.MAV_CMD_COMPONENT_ARM_DISARM, 1, 21196)}},
		{"mode change (DO_SET_MODE guided)", []message.Message{long(common.MAV_CMD_DO_SET_MODE, 1, modeGuided)}},
		{"mode change (SET_MODE auto)", []message.Message{&common.MessageSetMode{TargetSystem: targetSysID, BaseMode: 1, CustomMode: modeAuto}}},
		{fenceOff, []message.Message{long(common.MAV_CMD_DO_FENCE_ENABLE, 0)}},
		{"parameter write FENCE_ENABLE 0", []message.Message{paramSet("FENCE_ENABLE", 0)}},
		{"parameter write SCR_ENABLE 1", []message.Message{paramSet("SCR_ENABLE", 1)}},
		{"parameter write MAV1_OPTIONS 1 (signing off)", []message.Message{paramSet("MAV1_OPTIONS", 1)}},
		{"mission upload", []message.Message{count(MissionMission, 2), home, far}},
		{fenceUpload, append([]message.Message{count(MissionFence, 3)}, fence...)},
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
	}
}

const (
	fenceOff    = "fence off (DO_FENCE_ENABLE 0)"
	fenceUpload = "fence upload (a far triangle)"
)

func attackNamed(name string) attack {
	for _, a := range attacks() {
		if a.name == name {
			return a
		}
	}
	panic("no attack " + name)
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
	if before.Armed || !before.FenceOn || len(before.Fence) == 0 || len(before.Rally) != 1 {
		t.Fatalf("baseline is not the loaded policy: %+v", before)
	}
	// The fence rows' positive controls: signed with the key, each changes
	// what the snapshot reads; the signed link then restores it.
	ctl = r.sim.Dial(ports[1])
	send(t, newSender(t, ctl, r.key.s(), 9), attackNamed(fenceOff).msgs...)
	time.Sleep(time.Second)
	if r.snapshot().FenceOn {
		t.Fatal("a signed DO_FENCE_ENABLE 0 left the fence on; the fence-off check cannot see a change")
	}
	send(t, newSender(t, ctl, r.key.s(), 9), long(common.MAV_CMD_DO_FENCE_ENABLE, 1))
	send(t, newSender(t, ctl, r.key.s(), 9), attackNamed(fenceUpload).msgs...)
	time.Sleep(1500 * time.Millisecond)
	ctl.Close()
	if got := r.snapshot(); reflect.DeepEqual(got.Fence, before.Fence) {
		t.Fatalf("a signed fence upload left the fence %+v; the fence-upload check cannot see a change", got.Fence)
	}
	if err := r.link.Upload(MissionFence, Derive(r.h.Policy()).Fence); err != nil {
		t.Fatal(err)
	}
	r.requireSame(before, "restoring after the positive controls")
	if t.Failed() {
		t.FailNow()
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
// 0, and RC changes nothing. RC_PROTOCOLS 0 does not stop a protocol the
// aircraft already decodes, so RC that reached it before the policy (the
// positive control, which changes the mode) makes the load fail its
// read-back until the aircraft reboots; after the reboot the same RC input
// changes nothing and the aircraft reads back equal. Arming by stick and
// RC_CHANNELS_OVERRIDE are not tried: neither has a positive control (the
// stick gesture fails the stock arming checks, and the aircraft ignores an
// override once the policy is loaded even signed), and both need RC input.
func TestScriptingAndRCAreOff(t *testing.T) {
	r := newRig(t, false)
	ports := r.sim.Ports()
	// Positive control on stock RC settings: switch position 2 is LAND (copter.parm FLTMODE2).
	sendRC(t, r.sim.RCPort(), rcPacket(1295, 1000, 1500), 3*time.Second)
	if hb, err := r.link.WaitHeartbeat(time.Now(), 5*time.Second); err != nil || hb.CustomMode != modeLand {
		t.Fatalf("before the policy, RC did not change the mode (mode %d, %v); the RC check would be vacuous", hb.CustomMode, err)
	}
	if err := r.h.Load(signPolicy(t, testPolicy(), r.owner)); !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "RC input") {
		t.Fatalf("a policy loaded on an aircraft that has had RC input read back as %v, want the RC refusal\n%s", err, r.logs)
	}
	r.link.Close()
	r.sim.Restart()
	r.attach(ports[0], r.sim.Dial(ports[0]))
	if err := r.h.ArmCheck(); err != nil {
		t.Fatalf("after a reboot with no RC input: %v", err)
	}
	if v, err := r.link.GetParam("SCR_ENABLE"); err != nil || v != 0 {
		t.Errorf("SCR_ENABLE reads back %v (%v), want 0", v, err)
	}
	before := r.snapshot()
	for _, pos := range []uint16{1165, 1425, 1555, 1685, 1815} {
		sendRC(t, r.sim.RCPort(), rcPacket(pos, 1000, 1500), 2*time.Second)
	}
	r.requireSame(before, "RC input on the simulator's RC port")
	if err := r.h.ArmCheck(); err != nil {
		t.Errorf("RC input sent after the policy was in force from boot: %v", err)
	}
}
