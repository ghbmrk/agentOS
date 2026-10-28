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

// fakeAircraft answers every PARAM_REQUEST_READ on far with the frames
// answer returns for the request's signature timestamp, and returns the
// timestamp of the key-holder's first frame (Dial's heartbeat).
func fakeAircraft(t *testing.T, far net.Conn, k Key, answer func(reqTS uint64) [][]byte) <-chan uint64 {
	t.Helper()
	r, err := frame.NewReader(frame.ReaderConf{Reader: far, DialectRW: dialectRW(), InKey: k.s()})
	if err != nil {
		t.Fatal(err)
	}
	first := make(chan uint64, 1)
	go func() {
		for n := 0; ; n++ {
			fr, err := r.Read()
			if err != nil {
				var re frame.ReadError
				if errors.As(err, &re) {
					continue
				}
				return
			}
			ts := fr.(*frame.V2Frame).SignatureTimestamp
			if n == 0 {
				first <- ts
			}
			if _, ok := fr.GetMessage().(*common.MessageParamRequestRead); ok {
				for _, b := range answer(ts) {
					far.Write(b)
				}
			}
		}
	}()
	return first
}

func paramValue(name string, v float32) *common.MessageParamValue {
	return &common.MessageParamValue{ParamId: name, ParamValue: v, ParamType: common.MAV_PARAM_TYPE_REAL32, ParamCount: 1}
}

// REQ: NET-2, P3
// TestCapturedFramesAreNoAnswer: a signed reply the aircraft sent before the
// request (a capture replayed on a fresh link, of any age), a frame repeated
// on its stream, and a frame from another system are not read back; a reply
// signed at or after the request is, so the refusals are not vacuous.
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
			fakeAircraft(t, far, k, func(ts uint64) [][]byte { return c.answer(t, ts) })
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
		fakeAircraft(t, far, k, func(ts uint64) [][]byte {
			if first == nil {
				first = signedFrame(t, k, 1, 1, 0, ts+1<<40, paramValue("FENCE_ENABLE", 1))
				return [][]byte{first}
			}
			return [][]byte{first} // the same frame again: its timestamp is above the request's, but not new
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

	t.Run("heartbeat older than the link", func(t *testing.T) {
		near, far := net.Pipe()
		defer far.Close()
		first := fakeAircraft(t, far, k, func(uint64) [][]byte { return nil })
		l, err := Dial(near, k)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		ts := <-first
		hb := &common.MessageHeartbeat{Type: common.MAV_TYPE_QUADROTOR, Autopilot: common.MAV_AUTOPILOT_ARDUPILOTMEGA, MavlinkVersion: 3}
		far.Write(signedFrame(t, k, 1, 1, 0, ts-1, hb))
		if _, err := l.WaitHeartbeat(time.Time{}, 300*time.Millisecond); err == nil {
			t.Fatal("a heartbeat signed before the link's first frame counted")
		}
		far.Write(signedFrame(t, k, 1, 1, 1, ts, hb))
		if _, err := l.WaitHeartbeat(time.Time{}, 2*time.Second); err != nil {
			t.Fatalf("a heartbeat signed at the link's first frame did not count: %v", err)
		}
	})
}
