package drone

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
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

// tsUnit is a signature timestamp's unit, and clockSlack how far the
// aircraft's signing clock may run ahead of its anchor plus the time since:
// it advances by one unit a frame and jumps only when its GPS time is ahead
// or it boots (about a minute, past the slack, so a request after a boot
// re-anchors; see exchangeLocked).
const (
	tsUnit     = 10 * time.Microsecond
	clockSlack = 10 * time.Second
)

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
// A captured signed frame is no answer either. Before the first answer the
// link anchors to the aircraft's signing clock with a TIMESYNC challenge,
// whose signed reply must echo a random nonce, so no capture can be the
// anchor. After it, frames on each of the aircraft's signing streams must
// carry strictly increasing timestamps; a frame counts only on the anchor's
// stream, at or above the anchor and no further ahead of it than the time
// since plus clockSlack; and a reply counts only when its timestamp is also
// at or above the request's, because the aircraft raises its signing clock
// to the newest timestamp it accepts (ASSUMPTIONS.md DRONE-sim-5). Neither
// clock is trusted: the link signs no lower than the newest verified frame
// from the aircraft, so a key-holder clock behind the aircraft's still gets
// an anchor once the aircraft has sent a frame, and a capture from the
// future is above the bound.
type Link struct {
	conn io.ReadWriteCloser
	rw   *dialect.ReadWriter
	key  Key
	w    *frame.Writer

	wmu    sync.Mutex
	seq    byte
	lastTS uint64
	stream byte // this link's signing link id
	now    func() time.Time

	// peerTS is the newest timestamp of any verified frame from the
	// aircraft. The key-holder signs no lower: the aircraft refuses a frame
	// signed more than a minute behind its own clock, which a boot sets a
	// minute past its last saved value (ASSUMPTIONS.md DRONE-sim-4).
	peerTS atomic.Uint64

	req  sync.Mutex // one request/response exchange at a time
	in   chan received
	done chan struct{}

	streams map[byte]uint64 // the aircraft's newest timestamp per signing link id; read loop only

	smu      sync.Mutex
	anchor   *anchor
	hb       *common.MessageHeartbeat
	hbAt     time.Time
	dropped  int
	readErr  error
	closeErr sync.Once
}

// received is a verified message from the aircraft, its signature
// timestamp and the signing stream it came on.
type received struct {
	msg    message.Message
	ts     uint64
	linkID byte
}

// anchor is the aircraft's signing clock as a TIMESYNC challenge read it.
type anchor struct {
	ts     uint64
	linkID byte
	at     time.Time
}

// fresh reports whether a frame can have been signed since the anchor.
func (a *anchor) fresh(got received, now time.Time) bool {
	return a != nil && got.linkID == a.linkID && got.ts >= a.ts &&
		got.ts <= a.ts+uint64((now.Sub(a.at)+clockSlack)/tsUnit)
}

// Dial wraps conn as a signed link, starts reading it and sends a heartbeat.
func Dial(conn io.ReadWriteCloser, k Key) (*Link, error) {
	return dial(conn, k, time.Now, holderLinkID)
}

func dial(conn io.ReadWriteCloser, k Key, now func() time.Time, stream byte) (*Link, error) {
	if !k.valid() {
		return nil, errNoKey
	}
	w, err := frame.NewWriter(frame.WriterConf{Writer: conn, OutVersion: frame.V2})
	if err != nil {
		return nil, err
	}
	l := &Link{conn: conn, rw: dialectRW(), key: k, w: w, now: now, stream: stream,
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
		if ts > l.peerTS.Load() {
			l.peerTS.Store(ts) // the read loop is the only writer
		}
		got := received{v2.GetMessage(), ts, v2.SignatureLinkID}
		if hb, ok := got.msg.(*common.MessageHeartbeat); ok {
			l.smu.Lock()
			if now := l.now(); l.anchor.fresh(got, now) {
				l.hb, l.hbAt = hb, now
			}
			l.smu.Unlock()
		}
		select {
		case l.in <- got:
		default: // nobody is waiting; requests drain before they send
		}
	}
}

// Done is closed when the link's reader stops: the connection closed or failed.
func (l *Link) Done() <-chan struct{} { return l.done }

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
	ts := max(uint64(l.now().Sub(signatureEpoch)/tsUnit), l.peerTS.Load())
	if ts <= l.lastTS {
		ts = l.lastTS + 1 // MAVLink 2 refuses a timestamp not above the stream's last
	}
	l.lastTS = ts
	fr := &frame.V2Frame{
		IncompatibilityFlag: frame.V2FlagSigned,
		SequenceNumber:      l.seq,
		SystemID:            holderSysID,
		ComponentID:         holderCompID,
		Message:             mp.Write(m, true),
	}
	l.seq++
	fr.Checksum = fr.GenerateChecksum(mp.CRCExtra())
	fr.SignatureLinkID = l.stream
	fr.SignatureTimestamp = ts
	fr.Signature = fr.GenerateSignature(l.key.s())
	if err := l.w.Write(fr); err != nil {
		return 0, errors.New("drone: writing to the aircraft failed")
	}
	return ts, nil
}

var errTimeout = errors.New("drone: no answer from the aircraft")

// exchange sends m and returns the first message from the aircraft that match
// accepts and that was signed at or after m and since the anchor, within
// timeout. It anchors the link first if it has no anchor.
func (l *Link) exchange(m message.Message, match func(message.Message) bool, timeout time.Duration) (message.Message, error) {
	l.req.Lock()
	defer l.req.Unlock()
	return l.exchangeLocked(m, match, timeout)
}

func (l *Link) exchangeLocked(m message.Message, match func(message.Message) bool, timeout time.Duration) (message.Message, error) {
	l.smu.Lock()
	anchored := l.anchor != nil
	l.smu.Unlock()
	if !anchored {
		if err := l.anchorLocked(timeout); err != nil {
			return nil, err
		}
	}
	got, err := l.roundTrip(m, func(got received, sent uint64) bool {
		if got.ts < sent || !match(got.msg) {
			return false
		}
		l.smu.Lock()
		defer l.smu.Unlock()
		return l.anchor.fresh(got, l.now())
	}, timeout)
	if errors.Is(err, errTimeout) {
		// The aircraft's signing clock jumps when it boots, past any anchor
		// taken before, so a request that goes unanswered drops the anchor and
		// the next one takes a fresh one (ASSUMPTIONS.md DRONE-sim-5).
		l.smu.Lock()
		l.anchor = nil
		l.smu.Unlock()
	}
	if err != nil {
		return nil, err
	}
	return got.msg, nil
}

// anchorLocked reads the aircraft's signing clock: it sends TIMESYNC with a
// random nonce, and the aircraft's signed answer must echo it.
func (l *Link) anchorLocked(timeout time.Duration) error {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return err
	}
	nonce := int64(binary.LittleEndian.Uint64(b[:]) >> 1)
	got, err := l.roundTrip(&common.MessageTimesync{Ts1: nonce, TargetSystem: targetSysID, TargetComponent: targetCompID},
		func(got received, _ uint64) bool {
			ts, ok := got.msg.(*common.MessageTimesync)
			return ok && ts.Tc1 != 0 && ts.Ts1 == nonce
		}, timeout)
	if err != nil {
		return fmt.Errorf("drone: no signed TIMESYNC answer to anchor the link: %w", err)
	}
	l.smu.Lock()
	l.anchor = &anchor{ts: got.ts, linkID: got.linkID, at: l.now()}
	l.smu.Unlock()
	return nil
}

// roundTrip sends m and returns the first frame accept takes, given the
// timestamp m was signed with, within timeout.
func (l *Link) roundTrip(m message.Message, accept func(got received, sent uint64) bool, timeout time.Duration) (received, error) {
	for drained := false; !drained; {
		select {
		case <-l.in:
		default:
			drained = true
		}
	}
	sent, err := l.send(m)
	if err != nil {
		return received{}, err
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	for {
		select {
		case got := <-l.in:
			if accept(got, sent) {
				return got, nil
			}
		case <-l.done:
			return received{}, errors.New("drone: the link to the aircraft closed")
		case <-t.C:
			return received{}, errTimeout
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

// FreshHeartbeat returns a heartbeat the aircraft signed after this call:
// it anchors afresh (a signed TIMESYNC echoing a new random nonce) and takes
// the first heartbeat on that stream strictly above the echo, which the
// aircraft signed after it, as its clock moves up a unit a frame. Unlike a
// reply at or above the request's timestamp, this holds whichever clock is
// ahead, so no heartbeat held in transit passes.
func (l *Link) FreshHeartbeat() (Heartbeat, error) {
	l.req.Lock()
	defer l.req.Unlock()
	var last error
	for try := 0; try < 3; try++ {
		if last = l.anchorLocked(3 * time.Second); last != nil {
			continue
		}
		l.smu.Lock()
		a := *l.anchor
		l.smu.Unlock()
		var got received
		got, last = l.roundTrip(&common.MessageCommandLong{TargetSystem: targetSysID, TargetComponent: targetCompID,
			Command: common.MAV_CMD_REQUEST_MESSAGE, Param1: float32((&common.MessageHeartbeat{}).GetID())},
			func(got received, _ uint64) bool {
				_, ok := got.msg.(*common.MessageHeartbeat)
				return ok && got.linkID == a.linkID && got.ts > a.ts
			}, 3*time.Second)
		if last == nil {
			hb := got.msg.(*common.MessageHeartbeat)
			return Heartbeat{CustomMode: hb.CustomMode,
				Armed: hb.BaseMode&common.MAV_MODE_FLAG_SAFETY_ARMED != 0, At: l.now()}, nil
		}
	}
	return Heartbeat{}, fmt.Errorf("drone: no fresh heartbeat from the aircraft: %w", last)
}

// WaitHeartbeat waits for a signed heartbeat newer than after, anchoring
// the link first if it has no anchor: only a heartbeat since the anchor counts.
func (l *Link) WaitHeartbeat(after time.Time, timeout time.Duration) (Heartbeat, error) {
	deadline := time.Now().Add(timeout)
	l.req.Lock()
	l.smu.Lock()
	anchored := l.anchor != nil
	l.smu.Unlock()
	for !anchored && time.Now().Before(deadline) {
		anchored = l.anchorLocked(min(time.Until(deadline), 2*time.Second)) == nil
	}
	l.req.Unlock()
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

// SysStatus asks the aircraft for SYS_STATUS and returns its answer.
func (l *Link) SysStatus() (*common.MessageSysStatus, error) {
	got, err := l.request(&common.MessageSysStatus{})
	if err != nil {
		return nil, err
	}
	return got.(*common.MessageSysStatus), nil
}

// Position asks the aircraft for its position estimate (GLOBAL_POSITION_INT).
func (l *Link) Position() (*common.MessageGlobalPositionInt, error) {
	got, err := l.request(&common.MessageGlobalPositionInt{})
	if err != nil {
		return nil, err
	}
	return got.(*common.MessageGlobalPositionInt), nil
}

// request asks the aircraft for one message of want's type, retrying as a
// parameter read does.
func (l *Link) request(want message.Message) (message.Message, error) {
	id := want.GetID()
	var last error
	for try := 0; try < 3; try++ {
		got, err := l.exchange(&common.MessageCommandLong{TargetSystem: targetSysID, TargetComponent: targetCompID,
			Command: common.MAV_CMD_REQUEST_MESSAGE, Param1: float32(id)},
			func(m message.Message) bool { return m.GetID() == id }, 3*time.Second)
		if err == nil {
			return got, nil
		}
		last = err
	}
	return nil, fmt.Errorf("drone: requesting message %d: %w", id, last)
}

// Copter custom modes (ArduCopter mode numbers).
const (
	ModeAuto   = 3
	ModeGuided = 4
	ModeRTL    = 6
	ModeLand   = 9
)

// SetMode asks the aircraft for a Copter flight mode and requires it accepted.
func (l *Link) SetMode(mode uint32) error {
	return l.accepted(common.MAV_CMD_DO_SET_MODE, [7]float32{float32(common.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED), float32(mode)})
}

// accepted sends a command and requires MAV_RESULT_ACCEPTED.
func (l *Link) accepted(cmd common.MAV_CMD, params [7]float32) error {
	res, err := l.Command(cmd, params)
	if err != nil {
		return err
	}
	if res != common.MAV_RESULT_ACCEPTED {
		return fmt.Errorf("drone: the aircraft refused %v: %v", cmd, res)
	}
	return nil
}

// Velocity sets a guided velocity (metres per second north, east and down)
// that the aircraft holds for about three seconds unless renewed.
func (l *Link) Velocity(north, east, down float32) error {
	const onlyVelocity = common.POSITION_TARGET_TYPEMASK_X_IGNORE | common.POSITION_TARGET_TYPEMASK_Y_IGNORE |
		common.POSITION_TARGET_TYPEMASK_Z_IGNORE | common.POSITION_TARGET_TYPEMASK_AX_IGNORE |
		common.POSITION_TARGET_TYPEMASK_AY_IGNORE | common.POSITION_TARGET_TYPEMASK_AZ_IGNORE |
		common.POSITION_TARGET_TYPEMASK_YAW_IGNORE | common.POSITION_TARGET_TYPEMASK_YAW_RATE_IGNORE
	return l.Send(&common.MessageSetPositionTargetLocalNed{TargetSystem: targetSysID, TargetComponent: targetCompID,
		CoordinateFrame: common.MAV_FRAME_LOCAL_NED, TypeMask: onlyVelocity, Vx: north, Vy: east, Vz: down})
}

// KeepAlive sends the key-holder's heartbeat every second until stop is
// called or the link closes: the aircraft's lost-link failsafe counts these.
func (l *Link) KeepAlive() (stop func()) {
	quit := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			if l.SendHeartbeat() != nil {
				return
			}
			select {
			case <-quit:
				return
			case <-l.done:
				return
			case <-t.C:
			}
		}
	}()
	return func() { once.Do(func() { close(quit) }) }
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
