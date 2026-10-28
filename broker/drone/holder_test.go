package drone

import (
	"crypto/ed25519"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
	"github.com/bluenviron/gomavlib/v3/pkg/frame"
	"github.com/bluenviron/gomavlib/v3/pkg/message"
)

// scripted is a fake aircraft for the holder's read-back. Its signing clock
// works as ArduPilot's does: it refuses a frame signed more than a minute
// behind it, rises to the newest frame it accepts and moves one unit a frame
// it sends; a boot moves it ahead (boot). It signs on one stream, sends one
// heartbeat at start with hello, answers TIMESYNC, SYS_STATUS requests,
// parameter reads from params and empty mission lists, and answers each
// key-holder heartbeat with its own when beat is set.
type scripted struct {
	t      *testing.T
	k      Key
	far    net.Conn
	mu     sync.Mutex
	ts     uint64
	hello  bool
	beat   bool
	relay  func() // run before it answers a heartbeat request: a relay's held frames
	rc     bool
	params map[string]float32
	pos    Point    // the aircraft's reported position
	mode   uint32   // its custom mode, which DO_SET_MODE changes
	cmds   []uint32 // the custom modes it was asked for
}

// boot moves the aircraft's clock as a reboot does (GCS_Signing.cpp: a
// minute past the last saved timestamp), and sends the booted aircraft's
// first heartbeat.
func (a *scripted) boot() {
	a.set(func(a *scripted) { a.ts += uint64(70 * time.Second / tsUnit) })
	go a.send(&common.MessageHeartbeat{Type: common.MAV_TYPE_QUADROTOR})
}

func (a *scripted) send(m message.Message) {
	a.mu.Lock()
	a.ts++
	b := signedFrame(a.t, a.k, 1, 1, 0, a.ts, m)
	a.mu.Unlock()
	a.far.Write(b)
}

func (a *scripted) run() {
	r, err := frame.NewReader(frame.ReaderConf{Reader: a.far, DialectRW: dialectRW(), InKey: a.k.s()})
	if err != nil {
		a.t.Error(err)
		return
	}
	if a.hello {
		go a.send(&common.MessageHeartbeat{Type: common.MAV_TYPE_QUADROTOR})
	}
	for {
		fr, err := r.Read()
		if err != nil {
			var re frame.ReadError
			if errors.As(err, &re) {
				continue
			}
			return
		}
		ts := fr.(*frame.V2Frame).SignatureTimestamp
		a.mu.Lock()
		if ts+uint64(time.Minute/tsUnit) < a.ts {
			a.mu.Unlock()
			continue // signed more than a minute behind the aircraft's clock
		}
		a.ts = max(a.ts, ts)
		beat, rc, params, pos, mode, relay := a.beat, a.rc, a.params, a.pos, a.mode, a.relay
		a.mu.Unlock()
		switch m := fr.GetMessage().(type) {
		case *common.MessageTimesync:
			a.send(&common.MessageTimesync{Tc1: 1, Ts1: m.Ts1})
		case *common.MessageHeartbeat:
			if beat {
				a.send(&common.MessageHeartbeat{Type: common.MAV_TYPE_QUADROTOR, CustomMode: mode,
					BaseMode: common.MAV_MODE_FLAG_SAFETY_ARMED | common.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED})
			}
		case *common.MessageCommandLong:
			switch {
			case m.Command == common.MAV_CMD_REQUEST_MESSAGE && uint32(m.Param1) == (&common.MessageSysStatus{}).GetID():
				st := &common.MessageSysStatus{}
				if rc {
					st.OnboardControlSensorsPresent = common.MAV_SYS_STATUS_SENSOR_RC_RECEIVER
				}
				a.send(st)
			case m.Command == common.MAV_CMD_REQUEST_MESSAGE && uint32(m.Param1) == (&common.MessageHeartbeat{}).GetID():
				if relay != nil {
					relay()
				}
				a.send(&common.MessageHeartbeat{Type: common.MAV_TYPE_QUADROTOR, CustomMode: mode,
					BaseMode: common.MAV_MODE_FLAG_SAFETY_ARMED | common.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED})
			case m.Command == common.MAV_CMD_REQUEST_MESSAGE && uint32(m.Param1) == (&common.MessageGlobalPositionInt{}).GetID():
				a.send(&common.MessageGlobalPositionInt{Lat: e7(pos.Lat), Lon: e7(pos.Lon)})
			case m.Command == common.MAV_CMD_DO_SET_MODE:
				a.set(func(a *scripted) { a.mode = uint32(m.Param2); a.cmds = append(a.cmds, uint32(m.Param2)) })
				a.send(&common.MessageCommandAck{Command: m.Command, Result: common.MAV_RESULT_ACCEPTED})
			}
		case *common.MessageParamRequestRead:
			if v, ok := params[m.ParamId]; ok {
				a.send(paramValue(m.ParamId, v))
			}
		case *common.MessageMissionRequestList:
			a.send(&common.MessageMissionCount{Count: 0, MissionType: m.MissionType})
		}
	}
}

func scriptedLink(t *testing.T, a *scripted) *Link {
	t.Helper()
	k, err := NewKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	near, far := net.Pipe()
	t.Cleanup(func() { near.Close(); far.Close() })
	a.t, a.k, a.far = t, k, far
	go a.run()
	l, err := Dial(near, k)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (a *scripted) set(f func(*scripted)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f(a)
}

// REQ: NET-2, P3
// TestReadBackRefusesRCReceiver: an aircraft that reports an RC receiver
// since its boot is refused even when every parameter reads back equal
// (ASSUMPTIONS.md DRONE-sim-14); the same aircraft without it reads back.
func TestReadBackRefusesRCReceiver(t *testing.T) {
	a := &scripted{rc: true, params: map[string]float32{"FENCE_ENABLE": 1}}
	l := scriptedLink(t, a)
	h, err := NewHolder(l, testOwner(t, 1).Public().(ed25519.PublicKey), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h.plan = &Plan{Params: []Param{{"FENCE_ENABLE", 1}}}
	err = h.ArmCheck()
	if !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "RC input") {
		t.Fatalf("an aircraft with an RC receiver: %v", err)
	}
	a.set(func(a *scripted) { a.rc = false })
	if err := h.ArmCheck(); err != nil {
		t.Fatalf("the same aircraft with no receiver: %v", err)
	}
}

// REQ: NET-2
// TestHeartbeatCountsOnlyAfterAnchor: a signed heartbeat that arrives before
// the link has anchored is not the aircraft's state (it may be a capture);
// one after the anchor is.
func TestHeartbeatCountsOnlyAfterAnchor(t *testing.T) {
	a := &scripted{beat: true, mode: ModeAuto}
	l := scriptedLink(t, a) // Dial's heartbeat draws one from the aircraft
	time.Sleep(200 * time.Millisecond)
	if hb, ok := l.LastHeartbeat(); ok {
		t.Fatalf("a heartbeat before any anchor counted: %+v", hb)
	}
	stop := l.KeepAlive()
	defer stop()
	hb, err := l.WaitHeartbeat(time.Time{}, 5*time.Second)
	if err != nil || !hb.Armed || hb.CustomMode != ModeAuto {
		t.Fatalf("a heartbeat after the anchor: %+v, %v", hb, err)
	}
}

// REQ: NET-2
// TestLinkReanchorsAfterAircraftBoot: the aircraft's signing clock jumps
// ahead when it boots, past the anchor's slack; the request that goes
// unanswered drops the anchor and the next one re-anchors with a fresh
// challenge, so the read-back works again after a boot.
func TestLinkReanchorsAfterAircraftBoot(t *testing.T) {
	a := &scripted{params: map[string]float32{"FENCE_ENABLE": 1}}
	l := scriptedLink(t, a)
	if v, err := l.GetParam("FENCE_ENABLE"); err != nil || v != 1 {
		t.Fatalf("before the boot: %v, %v", v, err)
	}
	a.boot()
	if v, err := l.GetParam("FENCE_ENABLE"); err != nil || v != 1 {
		t.Fatalf("after the boot: %v, %v", v, err)
	}
}

func (a *scripted) modesAsked() []uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]uint32(nil), a.cmds...)
}

// scriptedFlight is a holder over a scripted aircraft with the fixture
// policy in force and a flight in progress.
func scriptedFlight(t *testing.T, a *scripted, animals ...string) *Holder {
	t.Helper()
	l := scriptedLink(t, a)
	h, err := NewHolder(l, testOwner(t, 1).Public().(ed25519.PublicKey), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := testPolicy()
	f := testFlight(time.Now())
	f.Animals = append([]string{}, animals...)
	h.policy, h.flight = &p, &f
	return h
}

// REQ: NET-2
// TestCameraCheckReturnsOnlyAfterN: camera fixes within the policy's bound,
// and one outlier among them, send nothing; cameraFixesToRTL consecutive
// fixes beyond it send one return (RTL) and end the flight; with no flight
// in progress, fixes send nothing.
func TestCameraCheckReturnsOnlyAfterN(t *testing.T) {
	a := &scripted{pos: at(0, 120), mode: ModeAuto}
	h := scriptedFlight(t, a)
	near, far := at(0, 125), at(0, 140) // 5 m and 20 m off; the bound is 8 m
	for i, fix := range []Point{near, far, near, far, far} {
		if sent, err := h.CameraFix(fix); sent || err != nil {
			t.Fatalf("fix %d returned the aircraft: %v, %v", i, sent, err)
		}
	}
	if got := a.modesAsked(); len(got) != 0 {
		t.Fatalf("fixes short of %d in a row asked for modes %v", cameraFixesToRTL, got)
	}
	if sent, err := h.CameraFix(far); !sent || err != nil {
		t.Fatalf("the %dth disagreeing fix in a row: %v, %v", cameraFixesToRTL, sent, err)
	}
	if got := a.modesAsked(); len(got) != 1 || got[0] != ModeRTL {
		t.Fatalf("the return asked for modes %v, want RTL once", got)
	}
	for i := 0; i < 2*cameraFixesToRTL; i++ {
		if sent, err := h.CameraFix(far); sent || err != nil {
			t.Fatalf("with no flight in progress, a fix returned the aircraft: %v, %v", sent, err)
		}
	}
	if sent, err := h.CameraFix(Point{Lat: 95, Lon: 0}); sent || err == nil {
		t.Fatalf("a fix off the globe: %v, %v", sent, err)
	}
}

// REQ: NET-2
// TestFollowNeverOverridesAReturn: a flight that names no animals does not
// follow; one that does steers by guided velocity; once the aircraft is
// returning by itself (its heartbeat shows RTL), follow is refused, asks for
// no mode, and the flight is over.
func TestFollowNeverOverridesAReturn(t *testing.T) {
	a := &scripted{pos: at(0, 120), mode: ModeAuto, beat: true}
	h := scriptedFlight(t, a)
	stop := h.link.KeepAlive()
	defer stop()
	if _, err := h.link.WaitHeartbeat(time.Time{}, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := h.Follow(at(0, 100)); err == nil {
		t.Fatal("a flight that names no animals followed")
	}
	h.flight.Animals = []string{"deer"}
	if err := h.Follow(at(0, 100)); err != nil {
		t.Fatalf("following on a flight that names animals: %v", err)
	}
	if got := a.modesAsked(); len(got) != 1 || got[0] != ModeGuided {
		t.Fatalf("follow asked for modes %v, want GUIDED", got)
	}
	a.set(func(a *scripted) { a.mode, a.cmds = ModeRTL, nil })
	waitMode(t, h.link, ModeRTL)
	if err := h.Follow(at(0, 100)); err == nil {
		t.Fatal("follow took the aircraft out of its own return")
	}
	if got := a.modesAsked(); len(got) != 0 {
		t.Fatalf("a refused follow asked for modes %v", got)
	}
	a.set(func(a *scripted) { a.mode = ModeGuided })
	waitMode(t, h.link, ModeGuided)
	if err := h.Follow(at(0, 100)); err == nil {
		t.Fatal("follow resumed after the aircraft's return ended the flight")
	}
}

// REQ: NET-2
// TestFollowLeavesAutoOnlyOnAFreshHeartbeat: an aircraft whose clock is
// ahead of the key-holder's (as after a boot) signs a heartbeat in AUTO, then
// starts its own return; a relay holds that heartbeat and delivers it as the
// answer to follow's request, signed above the request's timestamp. Follow
// does not take it: it leaves AUTO only on a heartbeat signed after a fresh
// TIMESYNC echo, which shows the return, so follow is refused and the flight
// ends.
func TestFollowLeavesAutoOnlyOnAFreshHeartbeat(t *testing.T) {
	a := &scripted{pos: at(0, 120), mode: ModeAuto, beat: true}
	h := scriptedFlight(t, a, "deer")
	a.set(func(a *scripted) { a.ts = uint64(time.Since(signatureEpoch)/tsUnit) + uint64(50*time.Second/tsUnit) })
	if _, err := h.link.FreshHeartbeat(); err != nil {
		t.Fatal(err)
	}
	// Frames the aircraft signs from here are held: five, then the heartbeat.
	a.mu.Lock()
	a.ts += 6
	held := signedFrame(t, a.k, 1, 1, 0, a.ts, &common.MessageHeartbeat{Type: common.MAV_TYPE_QUADROTOR,
		CustomMode: ModeAuto, BaseMode: common.MAV_MODE_FLAG_SAFETY_ARMED | common.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED})
	a.beat, a.mode = false, ModeRTL
	a.relay = func() { a.far.Write(held) }
	a.mu.Unlock()
	if err := h.Follow(at(0, 100)); err == nil {
		t.Fatal("follow took the aircraft out of its own return")
	}
	if got := a.modesAsked(); len(got) != 0 {
		t.Fatalf("a refused follow asked for modes %v", got)
	}
	if h.flight != nil {
		t.Error("the aircraft's return did not end the flight")
	}
}

// waitMode waits for a heartbeat in mode: one received after a change may
// have been sent before it.
func waitMode(t *testing.T, l *Link, mode uint32) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if hb, ok := l.LastHeartbeat(); ok && hb.CustomMode == mode {
			return
		}
	}
	t.Fatalf("no heartbeat in mode %d", mode)
}

// REQ: NET-2
// TestKeepAliveBeatsEverySecond: the key-holder signs a heartbeat about once
// a second while the link is up, so a rebooted aircraft's signing clock is
// raised past every capture within a second (ASSUMPTIONS.md DRONE-sim-4),
// and stops when told.
func TestKeepAliveBeatsEverySecond(t *testing.T) {
	k, err := NewKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	near, far := net.Pipe()
	defer far.Close()
	var mu sync.Mutex
	var beats []time.Time
	go func() {
		r, err := frame.NewReader(frame.ReaderConf{Reader: far, DialectRW: dialectRW(), InKey: k.s()})
		if err != nil {
			return
		}
		for {
			fr, err := r.Read()
			if err != nil {
				var re frame.ReadError
				if errors.As(err, &re) {
					continue
				}
				return
			}
			if _, ok := fr.GetMessage().(*common.MessageHeartbeat); ok {
				mu.Lock()
				beats = append(beats, time.Now())
				mu.Unlock()
			}
		}
	}()
	l, err := Dial(near, k)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stop := l.KeepAlive()
	time.Sleep(3500 * time.Millisecond)
	stop()
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	n := len(beats)
	got := append([]time.Time(nil), beats...)
	mu.Unlock()
	if n < 4 { // Dial's own, then one at once and one a second
		t.Fatalf("%d signed heartbeats in 3.5 s", n)
	}
	for i := 1; i < len(got); i++ {
		if gap := got[i].Sub(got[i-1]); gap > 1500*time.Millisecond {
			t.Errorf("a %v gap between heartbeats", gap)
		}
	}
	time.Sleep(2 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(beats) != n {
		t.Errorf("%d heartbeats after stop", len(beats)-n)
	}
}

// REQ: NET-2
// TestLinkFollowsTheAircraftClock: after boots that put the aircraft's
// signing clock more than a minute ahead of the key-holder's, the aircraft
// refuses frames signed by the key-holder's clock; the link signs no lower
// than the newest verified frame from the aircraft, so it still anchors and
// reads back.
func TestLinkFollowsTheAircraftClock(t *testing.T) {
	ahead := uint64(time.Now().Add(2*time.Minute).Sub(signatureEpoch) / tsUnit)
	a := &scripted{ts: ahead, hello: true, params: map[string]float32{"FENCE_ENABLE": 1}}
	l := scriptedLink(t, a)
	if v, err := l.GetParam("FENCE_ENABLE"); err != nil || v != 1 {
		t.Fatalf("an aircraft two boots ahead: %v, %v", v, err)
	}
}
