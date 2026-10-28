package drone

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialect"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
	"github.com/bluenviron/gomavlib/v3/pkg/frame"
	"github.com/bluenviron/gomavlib/v3/pkg/message"
)

// The key-holder's MAVLink identity, and the aircraft's.
const (
	holderSysID  = gcsSysID
	holderCompID = 190 // MAV_COMP_ID_MISSIONPLANNER: a ground station
	holderLinkID = 1
	targetSysID  = 1
	targetCompID = 1
)

var signatureEpoch = time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)

// dialectRW is the codec for MAVLink's common dialect, which holds every
// message the key-holder sends or reads; ArduPilot-only messages arrive raw
// and are ignored.
func dialectRW() *dialect.ReadWriter {
	rw, err := dialect.NewReadWriter(common.Dialect)
	if err != nil {
		panic(err) // the vendored dialect is fixed; a failure is a build defect
	}
	return rw
}

// Link is a MAVLink 2 link to the aircraft on which every frame sent is
// signed with the key and every frame received must verify under it: an
// unsigned or wrongly signed frame from the aircraft's side (a spoofed
// PARAM_VALUE, say) is dropped, so a read-back cannot be faked (P1, P3).
//
// A captured signed frame is no answer either. Frames on each of the
// aircraft's signing streams must carry strictly increasing timestamps, and
// a reply counts only when its timestamp is at or above the request's: the
// aircraft raises its own signing clock to the newest timestamp it accepts,
// so only a frame signed after it saw the request can answer it. A heartbeat
// counts only from at or above the link's first frame (ASSUMPTIONS.md
// DRONE-sim-5).
type Link struct {
	conn io.ReadWriteCloser
	rw   *dialect.ReadWriter
	key  Key
	w    *frame.Writer

	wmu    sync.Mutex
	seq    byte
	lastTS uint64
	now    func() time.Time

	req  sync.Mutex // one request/response exchange at a time
	in   chan received
	done chan struct{}

	streams map[byte]uint64 // the aircraft's newest timestamp per signing link id; read loop only

	smu      sync.Mutex
	firstTS  uint64 // the timestamp of the link's first frame sent
	hb       *common.MessageHeartbeat
	hbAt     time.Time
	dropped  int
	readErr  error
	closeErr sync.Once
}

// received is a verified message from the aircraft and its signature timestamp.
type received struct {
	msg message.Message
	ts  uint64
}

// Dial wraps conn as a signed link, starts reading it and sends a heartbeat,
// whose timestamp is the floor for the aircraft's heartbeats on this link.
func Dial(conn io.ReadWriteCloser, k Key) (*Link, error) {
	if !k.valid() {
		return nil, errNoKey
	}
	w, err := frame.NewWriter(frame.WriterConf{Writer: conn, OutVersion: frame.V2})
	if err != nil {
		return nil, err
	}
	l := &Link{conn: conn, rw: dialectRW(), key: k, w: w, now: time.Now,
		in: make(chan received, 512), done: make(chan struct{}), streams: map[byte]uint64{}}
	r, err := frame.NewReader(frame.ReaderConf{Reader: conn, DialectRW: l.rw, InKey: k.s()})
	if err != nil {
		return nil, err
	}
	go l.readLoop(r)
	if err := l.SendHeartbeat(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Close closes the connection.
func (l *Link) Close() error {
	var err error
	l.closeErr.Do(func() { err = l.conn.Close() })
	return err
}

func (l *Link) readLoop(r *frame.Reader) {
	defer close(l.done)
	for {
		fr, err := r.Read()
		if err != nil {
			var re frame.ReadError
			if errors.As(err, &re) {
				l.smu.Lock()
				l.dropped++
				l.smu.Unlock()
				continue
			}
			l.smu.Lock()
			l.readErr = err
			l.smu.Unlock()
			return
		}
		v2, ok := fr.(*frame.V2Frame)
		if !ok || v2.Signature == nil || v2.GetSystemID() != targetSysID || v2.GetComponentID() != targetCompID {
			continue // the reader verified every frame; this is belt and braces
		}
		ts := v2.SignatureTimestamp
		if ts <= l.streams[v2.SignatureLinkID] {
			l.smu.Lock()
			l.dropped++ // replayed, or reordered: no older frame is trusted
			l.smu.Unlock()
			continue
		}
		l.streams[v2.SignatureLinkID] = ts
		msg := v2.GetMessage()
		if hb, ok := msg.(*common.MessageHeartbeat); ok {
			l.smu.Lock()
			if l.firstTS != 0 && ts >= l.firstTS {
				l.hb, l.hbAt = hb, l.now()
			}
			l.smu.Unlock()
		}
		select {
		case l.in <- received{msg, ts}:
		default: // nobody is waiting; requests drain before they send
		}
	}
}

// Dropped counts frames from the aircraft's side that failed to parse or
// verify, or were not newer than their stream's last.
func (l *Link) Dropped() int {
	l.smu.Lock()
	defer l.smu.Unlock()
	return l.dropped
}

// Send signs and writes one message.
func (l *Link) Send(m message.Message) error {
	_, err := l.send(m)
	return err
}

// send signs and writes m, and returns its signature timestamp.
func (l *Link) send(m message.Message) (uint64, error) {
	mp := l.rw.GetMessage(m.GetID())
	if mp == nil {
		return 0, fmt.Errorf("drone: message %d is not in the dialect", m.GetID())
	}
	l.wmu.Lock()
	defer l.wmu.Unlock()
	ts := uint64(l.now().Sub(signatureEpoch) / (10 * time.Microsecond))
	if ts <= l.lastTS {
		ts = l.lastTS + 1 // MAVLink 2 refuses a timestamp not above the stream's last
	}
	l.lastTS = ts
	l.smu.Lock()
	if l.firstTS == 0 {
		l.firstTS = ts
	}
	l.smu.Unlock()
	fr := &frame.V2Frame{
		IncompatibilityFlag: frame.V2FlagSigned,
		SequenceNumber:      l.seq,
		SystemID:            holderSysID,
		ComponentID:         holderCompID,
		Message:             mp.Write(m, true),
	}
	l.seq++
	fr.Checksum = fr.GenerateChecksum(mp.CRCExtra())
	fr.SignatureLinkID = holderLinkID
	fr.SignatureTimestamp = ts
	fr.Signature = fr.GenerateSignature(l.key.s())
	if err := l.w.Write(fr); err != nil {
		return 0, errors.New("drone: writing to the aircraft failed")
	}
	return ts, nil
}

var errTimeout = errors.New("drone: no answer from the aircraft")

// exchange sends m and returns the first message from the aircraft that match
// accepts and that was signed at or after m, within timeout.
func (l *Link) exchange(m message.Message, match func(message.Message) bool, timeout time.Duration) (message.Message, error) {
	l.req.Lock()
	defer l.req.Unlock()
	return l.exchangeLocked(m, match, timeout)
}

func (l *Link) exchangeLocked(m message.Message, match func(message.Message) bool, timeout time.Duration) (message.Message, error) {
	for drained := false; !drained; {
		select {
		case <-l.in:
		default:
			drained = true
		}
	}
	sent, err := l.send(m)
	if err != nil {
		return nil, err
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		select {
		case got := <-l.in:
			if got.ts >= sent && match(got.msg) {
				return got.msg, nil
			}
		case <-l.done:
			return nil, errors.New("drone: the link to the aircraft closed")
		case <-t.C:
			return nil, errTimeout
		}
	}
}

// Heartbeat is the aircraft's last signed heartbeat.
type Heartbeat struct {
	CustomMode uint32
	Armed      bool
	At         time.Time
}

// LastHeartbeat returns the aircraft's last signed heartbeat, if any.
func (l *Link) LastHeartbeat() (Heartbeat, bool) {
	l.smu.Lock()
	defer l.smu.Unlock()
	if l.hb == nil {
		return Heartbeat{}, false
	}
	return Heartbeat{CustomMode: l.hb.CustomMode,
		Armed: l.hb.BaseMode&common.MAV_MODE_FLAG_SAFETY_ARMED != 0, At: l.hbAt}, true
}

// WaitHeartbeat waits for a signed heartbeat newer than after.
func (l *Link) WaitHeartbeat(after time.Time, timeout time.Duration) (Heartbeat, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if hb, ok := l.LastHeartbeat(); ok && hb.At.After(after) {
			return hb, nil
		}
		select {
		case <-l.done:
			return Heartbeat{}, errors.New("drone: the link to the aircraft closed")
		case <-time.After(50 * time.Millisecond):
		}
	}
	return Heartbeat{}, errTimeout
}

// SendHeartbeat sends the key-holder's heartbeat (the aircraft's lost-link
// failsafe counts these from MAV_GCS_SYSID).
func (l *Link) SendHeartbeat() error {
	return l.Send(&common.MessageHeartbeat{
		Type: common.MAV_TYPE_GCS, Autopilot: common.MAV_AUTOPILOT_INVALID, MavlinkVersion: 3})
}

// GetParam reads one parameter back over the signed link.
func (l *Link) GetParam(name string) (float32, error) {
	var last error
	for try := 0; try < 3; try++ {
		got, err := l.exchange(&common.MessageParamRequestRead{
			TargetSystem: targetSysID, TargetComponent: targetCompID, ParamId: name, ParamIndex: -1,
		}, func(m message.Message) bool {
			pv, ok := m.(*common.MessageParamValue)
			return ok && pv.ParamId == name
		}, 2*time.Second)
		if err == nil {
			v := got.(*common.MessageParamValue).ParamValue
			if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
				return 0, fmt.Errorf("drone: parameter %s read back as %v", name, v)
			}
			return v, nil
		}
		last = err
	}
	return 0, fmt.Errorf("drone: reading parameter %s: %w", name, last)
}

// SetParam writes one parameter and returns the value the aircraft reports.
func (l *Link) SetParam(name string, v float32) (float32, error) {
	var last error
	for try := 0; try < 3; try++ {
		got, err := l.exchange(&common.MessageParamSet{
			TargetSystem: targetSysID, TargetComponent: targetCompID, ParamId: name, ParamValue: v,
			ParamType: common.MAV_PARAM_TYPE_REAL32,
		}, func(m message.Message) bool {
			pv, ok := m.(*common.MessageParamValue)
			return ok && pv.ParamId == name
		}, 2*time.Second)
		if err == nil {
			return got.(*common.MessageParamValue).ParamValue, nil
		}
		last = err
	}
	return 0, fmt.Errorf("drone: setting parameter %s: %w", name, last)
}

// Mission types of the MAVLink mission protocol.
const (
	MissionMission = common.MAV_MISSION_TYPE_MISSION
	MissionFence   = common.MAV_MISSION_TYPE_FENCE
	MissionRally   = common.MAV_MISSION_TYPE_RALLY
)

// Upload writes a whole mission, fence or rally list.
func (l *Link) Upload(kind common.MAV_MISSION_TYPE, items []Item) error {
	l.req.Lock()
	defer l.req.Unlock()
	isReq := func(m message.Message) bool {
		switch r := m.(type) {
		case *common.MessageMissionRequestInt:
			return r.MissionType == kind
		case *common.MessageMissionRequest:
			return r.MissionType == kind
		case *common.MessageMissionAck:
			return r.MissionType == kind
		}
		return false
	}
	var got message.Message
	var err error
	for try := 0; try < 3; try++ {
		got, err = l.exchangeLocked(&common.MessageMissionCount{TargetSystem: targetSysID,
			TargetComponent: targetCompID, Count: uint16(len(items)), MissionType: kind}, isReq, 2*time.Second)
		if err == nil {
			break
		}
	}
	for err == nil {
		var seq uint16
		switch r := got.(type) {
		case *common.MessageMissionAck:
			if r.Type != common.MAV_MISSION_ACCEPTED {
				return fmt.Errorf("drone: aircraft refused the %v upload: %v", kind, r.Type)
			}
			return nil
		case *common.MessageMissionRequestInt:
			seq = r.Seq
		case *common.MessageMissionRequest:
			seq = r.Seq
		}
		if int(seq) >= len(items) {
			return fmt.Errorf("drone: aircraft asked for %v item %d of %d", kind, seq, len(items))
		}
		got, err = l.exchangeLocked(itemMsg(kind, seq, items[seq]), isReq, 3*time.Second)
	}
	return fmt.Errorf("drone: uploading %v: %w", kind, err)
}

func itemMsg(kind common.MAV_MISSION_TYPE, seq uint16, it Item) *common.MessageMissionItemInt {
	m := &common.MessageMissionItemInt{
		TargetSystem: targetSysID, TargetComponent: targetCompID, Seq: seq,
		Frame: common.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT, Command: common.MAV_CMD(it.Command),
		Param1: it.Param1, X: it.Lat, Y: it.Lon, Z: it.AltM, Autocontinue: 1, MissionType: kind,
	}
	if it.Command == cmdFenceInclusion || it.Command == cmdFenceExclusion {
		m.Frame = common.MAV_FRAME_GLOBAL_INT
	}
	return m
}

// Download reads a whole mission, fence or rally list back.
func (l *Link) Download(kind common.MAV_MISSION_TYPE) ([]Item, error) {
	l.req.Lock()
	defer l.req.Unlock()
	var got message.Message
	var err error
	for try := 0; try < 3; try++ {
		got, err = l.exchangeLocked(&common.MessageMissionRequestList{TargetSystem: targetSysID,
			TargetComponent: targetCompID, MissionType: kind}, func(m message.Message) bool {
			c, ok := m.(*common.MessageMissionCount)
			return ok && c.MissionType == kind
		}, 2*time.Second)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("drone: listing %v: %w", kind, err)
	}
	n := got.(*common.MessageMissionCount).Count
	items := make([]Item, 0, n)
	for seq := uint16(0); seq < n; seq++ {
		var it message.Message
		for try := 0; try < 3; try++ {
			it, err = l.exchangeLocked(&common.MessageMissionRequestInt{TargetSystem: targetSysID,
				TargetComponent: targetCompID, Seq: seq, MissionType: kind}, func(m message.Message) bool {
				r, ok := m.(*common.MessageMissionItemInt)
				return ok && r.MissionType == kind && r.Seq == seq
			}, 2*time.Second)
			if err == nil {
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("drone: reading %v item %d: %w", kind, seq, err)
		}
		r := it.(*common.MessageMissionItemInt)
		if kind == MissionRally && !relativeFrame(r.Frame) {
			return nil, fmt.Errorf("drone: rally item %d is in frame %v, not above home", seq, r.Frame)
		}
		items = append(items, Item{Command: uint16(r.Command), Param1: r.Param1, Lat: r.X, Lon: r.Y, AltM: r.Z})
	}
	l.Send(&common.MessageMissionAck{TargetSystem: targetSysID, TargetComponent: targetCompID,
		Type: common.MAV_MISSION_ACCEPTED, MissionType: kind})
	return items, nil
}

func relativeFrame(f common.MAV_FRAME) bool {
	return f == common.MAV_FRAME_GLOBAL_RELATIVE_ALT || f == common.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT
}

// Command sends COMMAND_LONG and returns the aircraft's result.
func (l *Link) Command(cmd common.MAV_CMD, params [7]float32) (common.MAV_RESULT, error) {
	got, err := l.exchange(&common.MessageCommandLong{TargetSystem: targetSysID, TargetComponent: targetCompID,
		Command: cmd, Param1: params[0], Param2: params[1], Param3: params[2], Param4: params[3],
		Param5: params[4], Param6: params[5], Param7: params[6]}, func(m message.Message) bool {
		a, ok := m.(*common.MessageCommandAck)
		return ok && a.Command == cmd
	}, 3*time.Second)
	if err != nil {
		return 0, fmt.Errorf("drone: command %v: %w", cmd, err)
	}
	return got.(*common.MessageCommandAck).Result, nil
}
