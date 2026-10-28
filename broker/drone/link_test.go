package drone

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/bluenviron/gomavlib/v3/pkg/dialects/common"
	"github.com/bluenviron/gomavlib/v3/pkg/frame"
	"github.com/bluenviron/gomavlib/v3/pkg/message"
)

// signedFrame is m as the aircraft would sign it: from sys/comp on signing
// link linkID at timestamp ts.
func signedFrame(t *testing.T, k Key, sys, comp, linkID byte, ts uint64, m message.Message) []byte {
	t.Helper()
	rw := dialectRW()
	mp := rw.GetMessage(m.GetID())
	fr := &frame.V2Frame{IncompatibilityFlag: frame.V2FlagSigned, SystemID: sys, ComponentID: comp, Message: mp.Write(m, true)}
	fr.Checksum = fr.GenerateChecksum(mp.CRCExtra())
	fr.SignatureLinkID, fr.SignatureTimestamp = linkID, ts
	fr.Signature = fr.GenerateSignature(k.s())
	var b bytes.Buffer
	w, err := frame.NewWriter(frame.WriterConf{Writer: &b, OutVersion: frame.V2})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(fr); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// fakeAircraft answers the key-holder on far as the aircraft would: a
// TIMESYNC challenge with a signed echo of echo(nonce) one unit after the
// challenge, its timestamp sent on the returned channel, and every PARAM_REQUEST_READ with the frames
// answer returns for the request's signature timestamp. It answers nothing
// signed more than a minute behind clock, as ArduPilot refuses such frames.
func fakeAircraft(t *testing.T, far net.Conn, k Key, clock func() time.Time, echo func(int64) int64, answer func(reqTS uint64) [][]byte) <-chan uint64 {
	t.Helper()
	r, err := frame.NewReader(frame.ReaderConf{Reader: far, DialectRW: dialectRW(), InKey: k.s()})
	if err != nil {
		t.Fatal(err)
	}
	anchors := make(chan uint64, 8)
	go func() {
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
			if ts+uint64(time.Minute/tsUnit) < uint64(clock().Sub(signatureEpoch)/tsUnit) {
				continue
			}
			switch m := fr.GetMessage().(type) {
			case *common.MessageTimesync:
				far.Write(signedFrame(t, k, 1, 1, 0, ts+1, &common.MessageTimesync{Tc1: 1, Ts1: echo(m.Ts1)}))
				anchors <- ts + 1
			case *common.MessageParamRequestRead:
				for _, b := range answer(ts) {
					far.Write(b)
				}
			}
		}
	}()
	return anchors
}

func same(n int64) int64 { return n }

func paramValue(name string, v float32) *common.MessageParamValue {
	return &common.MessageParamValue{ParamId: name, ParamValue: v, ParamType: common.MAV_PARAM_TYPE_REAL32, ParamCount: 1}
}

// REQ: NET-2, P3
// TestCapturedFramesAreNoAnswer: a signed reply the aircraft sent before the
// request (a capture replayed on a fresh link, of any age), one signed far
// ahead (a capture from a clock pushed forward), a frame repeated on its
// stream, a frame from another system, a heartbeat from before the anchor,
// and any frame on a key-holder whose clock is far behind the aircraft's are
// not read back; a reply signed at or after the request is, so the refusals
// are not vacuous.
func TestCapturedFramesAreNoAnswer(t *testing.T) {
	k, err := NewKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	monthAgo := uint64(30 * 24 * time.Hour / (10 * time.Microsecond))
	cases := []struct {
		name   string
		answer func(t *testing.T, reqTS uint64) [][]byte
		ok     bool
	}{
		{"fresh reply", func(t *testing.T, ts uint64) [][]byte {
			return [][]byte{signedFrame(t, k, 1, 1, 0, ts+1, paramValue("FENCE_ENABLE", 1))}
		}, true},
		{"30-day-old capture", func(t *testing.T, ts uint64) [][]byte {
			return [][]byte{signedFrame(t, k, 1, 1, 0, ts-monthAgo, paramValue("FENCE_ENABLE", 1))}
		}, false},
		{"capture from a clock a year ahead", func(t *testing.T, ts uint64) [][]byte {
			return [][]byte{signedFrame(t, k, 1, 1, 0, ts+12*monthAgo, paramValue("FENCE_ENABLE", 1))}
		}, false},
		{"reply on another signing stream", func(t *testing.T, ts uint64) [][]byte {
			return [][]byte{signedFrame(t, k, 1, 1, 1, ts+1, paramValue("FENCE_ENABLE", 1))}
		}, false},
		{"capture from just before the request", func(t *testing.T, ts uint64) [][]byte {
			return [][]byte{signedFrame(t, k, 1, 1, 0, ts-1, paramValue("FENCE_ENABLE", 1))}
		}, false},
		{"another system", func(t *testing.T, ts uint64) [][]byte {
			return [][]byte{signedFrame(t, k, 2, 1, 0, ts+1, paramValue("FENCE_ENABLE", 1))}
		}, false},
		{"another component", func(t *testing.T, ts uint64) [][]byte {
			return [][]byte{signedFrame(t, k, 1, 2, 0, ts+1, paramValue("FENCE_ENABLE", 1))}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			near, far := net.Pipe()
			defer far.Close()
			fakeAircraft(t, far, k, time.Now, same, func(ts uint64) [][]byte { return c.answer(t, ts) })
			l, err := Dial(near, k)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			v, err := l.GetParam("FENCE_ENABLE")
			if c.ok && (err != nil || v != 1) {
				t.Fatalf("a fresh signed reply was not read back: %v, %v", v, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("read back %v from a frame that is no answer", v)
			}
		})
	}

	t.Run("repeated frame", func(t *testing.T) {
		near, far := net.Pipe()
		defer far.Close()
		var first []byte
		fakeAircraft(t, far, k, time.Now, same, func(ts uint64) [][]byte {
			if first == nil {
				first = signedFrame(t, k, 1, 1, 0, ts+1, paramValue("FENCE_ENABLE", 1))
				return [][]byte{first}
			}
			return [][]byte{first} // the same frame again: not new on its stream
		})
		l, err := Dial(near, k)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if v, err := l.GetParam("FENCE_ENABLE"); err != nil || v != 1 {
			t.Fatalf("first answer: %v, %v", v, err)
		}
		if v, err := l.GetParam("FENCE_ENABLE"); err == nil {
			t.Fatalf("a repeated frame answered a second request (%v)", v)
		}
		if l.Dropped() == 0 {
			t.Error("the repeated frame was not counted as dropped")
		}
	})

	t.Run("heartbeat from before the anchor", func(t *testing.T) {
		near, far := net.Pipe()
		defer far.Close()
		anchors := fakeAircraft(t, far, k, time.Now, same, func(uint64) [][]byte { return nil })
		l, err := Dial(near, k)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if _, err := l.WaitHeartbeat(time.Time{}, 300*time.Millisecond); err == nil {
			t.Fatal("a heartbeat counted before any was sent")
		}
		ts := <-anchors
		hb := &common.MessageHeartbeat{Type: common.MAV_TYPE_QUADROTOR, Autopilot: common.MAV_AUTOPILOT_ARDUPILOTMEGA, MavlinkVersion: 3}
		far.Write(signedFrame(t, k, 1, 1, 0, ts-1, hb)) // dropped twice over: below the stream's last and the anchor
		far.Write(signedFrame(t, k, 1, 1, 2, ts-1, hb)) // a new stream, but below the anchor
		if _, err := l.WaitHeartbeat(time.Time{}, 300*time.Millisecond); err == nil {
			t.Fatal("a heartbeat signed before the anchor counted")
		}
		far.Write(signedFrame(t, k, 1, 1, 0, ts+1, hb))
		if _, err := l.WaitHeartbeat(time.Time{}, 2*time.Second); err != nil {
			t.Fatalf("a heartbeat signed after the anchor did not count: %v", err)
		}
	})

	t.Run("key-holder clock two hours behind", func(t *testing.T) {
		near, far := net.Pipe()
		defer far.Close()
		hourAgo := uint64(time.Since(signatureEpoch.Add(time.Hour)) / tsUnit)
		fakeAircraft(t, far, k, time.Now, same, func(uint64) [][]byte { return nil })
		l, err := dial(near, k, func() time.Time { return time.Now().Add(-2 * time.Hour) }, holderLinkID)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for i := uint64(0); i < 40; i++ { // hour-old captures, each newer than the last, offered while the key-holder waits
				far.Write(signedFrame(t, k, 1, 1, 0, hourAgo+i, paramValue("FENCE_ENABLE", 1)))
				time.Sleep(100 * time.Millisecond)
			}
		}()
		if v, err := l.GetParam("FENCE_ENABLE"); err == nil {
			t.Fatalf("a key-holder whose clock is behind read back %v from hour-old captures", v)
		}
	})

	t.Run("TIMESYNC echoing another nonce", func(t *testing.T) {
		near, far := net.Pipe()
		defer far.Close()
		fakeAircraft(t, far, k, time.Now, func(n int64) int64 { return n ^ 1 }, func(ts uint64) [][]byte {
			return [][]byte{signedFrame(t, k, 1, 1, 0, ts+1, paramValue("FENCE_ENABLE", 1))}
		})
		l, err := Dial(near, k)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		hb := &common.MessageHeartbeat{Type: common.MAV_TYPE_QUADROTOR, Autopilot: common.MAV_AUTOPILOT_ARDUPILOTMEGA, MavlinkVersion: 3}
		go func() {
			for i := 0; i < 30; i++ { // fresh signed heartbeats on the aircraft's stream
				far.Write(signedFrame(t, k, 1, 1, 0, uint64(time.Since(signatureEpoch)/tsUnit), hb))
				time.Sleep(100 * time.Millisecond)
			}
		}()
		if _, err := l.WaitHeartbeat(time.Time{}, time.Second); err == nil {
			t.Fatal("a heartbeat counted on a link anchored by a TIMESYNC echoing another nonce")
		}
		if v, err := l.GetParam("FENCE_ENABLE"); err == nil {
			t.Fatalf("read back %v on a link anchored by a TIMESYNC echoing another nonce", v)
		}
	})
}
