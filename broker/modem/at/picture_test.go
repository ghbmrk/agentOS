package at_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem/at"
)

// REQ: CH-12, CH12-mms-a, CH12-mms-b

// pushPort is a UDH addressing WAP-push port 2948 (IEI 0x05) from 9200.
var pushPort = []byte{0x05, 0x04, 0x0B, 0x84, 0x23, 0xF0}

// notice is a synthetic WSP push: transaction tid, push PDU, content type
// ct, X-Wap-Application-Id MMS, then an m-notification-ind start.
func notice(tid byte, ct ...byte) []byte {
	hdr := append(append([]byte{}, ct...), 0xAF, 0x84)
	b := append([]byte{tid, 0x06, byte(len(hdr))}, hdr...)
	b = append(b, 0x8C, 0x82, 0x98)
	return append(b, "T-synthetic\x00\x83http://mms.example.invalid/x\x00"...)
}

func TestMMSNoticeDecodesAsAPicture(t *testing.T) {
	twoPart := func(seq byte) []byte {
		return append([]byte{0x00, 0x03, 0x2A, 0x02, seq}, pushPort...)
	}
	for _, c := range []struct {
		name          string
		dcs           byte
		udh, body     []byte
		push, picture bool
	}{
		{"short content type", 0, pushPort, notice(1, 0xBE), true, true},
		{"general form", 0, pushPort, notice(2, 0x03, 0xBE, 0x81, 0xEA), true, true},
		{"text content type", 0, pushPort, notice(3, []byte("application/vnd.wap.mms-message\x00")...), true, true},
		{"class-coded 8-bit", 0xF5, pushPort, notice(4, 0xBE), true, true},
		{"confirmed push", 0, pushPort, append([]byte{5, 0x07}, notice(5, 0xBE)[2:]...), true, true},
		{"first of two parts", 0, twoPart(1), notice(6, 0xBE), true, true},
		{"second of two parts", 0, twoPart(2), []byte("rest of the notice"), true, false},
		{"service indication", 0, pushPort, notice(7, 0xAE), false, false},
		{"another port", 0, []byte{0x05, 0x04, 0x0B, 0x85, 0x23, 0xF0}, notice(8, 0xBE), false, false},
		{"no port", 0, nil, notice(9, 0xBE), false, false},
		{"8-bit port", 0, []byte{0x04, 0x02, 0x0B, 0x84}, notice(10, 0xBE), false, false},
	} {
		d, err := at.DecodeDeliver(at.DeliverPush(ownerNum, c.dcs, c.udh, c.body))
		if !c.push {
			if !errors.Is(err, at.ErrPDU) {
				t.Errorf("%s: got %+v, %v; want ErrPDU", c.name, d, err)
			}
			continue
		}
		if err != nil || !d.Push || d.Picture != c.picture || d.Text != "" || d.Addr != ownerNum {
			t.Errorf("%s: got %+v, %v", c.name, d, err)
		}
	}
	// A truncated push is no picture.
	if _, err := at.DecodeDeliver(at.DeliverPush(ownerNum, 0, pushPort, []byte{1, 0x06})); !errors.Is(err, at.ErrPDU) {
		t.Errorf("truncated push: %v", err)
	}
}

func TestOwnersPictureGetsOneReplyAnHour(t *testing.T) {
	if len(at.PictureText) > 160 {
		t.Fatalf("PictureText is %d characters", len(at.PictureText))
	}
	for _, c := range at.PictureText {
		if c < ' ' || c > '~' || c == '[' || c == ']' || c == '{' || c == '}' || c == '\\' || c == '^' || c == '~' || c == '|' || c == '`' {
			t.Fatalf("PictureText has %q, not one GSM-7 septet", c)
		}
	}
	r := newRig(t, vendors[0], at.KeysInBand, nil)
	first := at.DeliverPush(ownerNum, 0, pushPort, notice(1, 0xBE))
	r.dev.StorePDU(first)
	if got := r.text(); !got.Picture || !got.Owner || got.Text != "" || got.From != ownerNum || got.Ref != "" {
		t.Fatalf("delivered %+v", got)
	}
	if got := r.phoneText(); got.Text != at.PictureText {
		t.Fatalf("owner got %q", got.Text)
	}
	// A second picture within the hour is delivered and counted, with no
	// second reply.
	r.dev.StorePDU(at.DeliverPush(ownerNum, 0, pushPort, notice(2, 0xBE)))
	if got := r.text(); !got.Picture {
		t.Fatalf("delivered %+v", got)
	}
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("second reply %q", m.Text)
	case <-time.After(60 * time.Millisecond):
	}
	// The same notice handed over again is a replay: not delivered.
	r.dev.StorePDU(first)
	// The later part of a long notice is deleted, never counted.
	r.dev.StorePDU(at.DeliverPush(ownerNum, 0, append([]byte{0x00, 0x03, 0x2A, 0x02, 0x02}, pushPort...), []byte("rest")))
	eventually(t, "replay and later part deleted", func() bool { return r.dev.Stored() == 0 })
	select {
	case got := <-r.m.Inbox():
		t.Fatalf("delivered %+v", got)
	case <-time.After(60 * time.Millisecond):
	}
	r.advance(time.Hour)
	r.dev.StorePDU(at.DeliverPush(ownerNum, 0, pushPort, notice(3, 0xBE)))
	r.text()
	if got := r.phoneText(); got.Text != at.PictureText {
		t.Fatalf("after an hour the owner got %q", got.Text)
	}
	if r.m.Pictures() != 3 || r.m.Dropped() != 0 {
		t.Fatalf("pictures %d, dropped %d", r.m.Pictures(), r.m.Dropped())
	}
}

func TestOthersPictureGetsNoReply(t *testing.T) {
	r := newRig(t, vendors[1], at.KeysInBand, nil)
	shop := r.carrier.Line(shopNum)
	r.dev.StorePDU(at.DeliverPush(shopNum, 0, pushPort, notice(1, 0xBE)))
	if got := r.text(); !got.Picture || got.Owner || got.From != shopNum || got.Text != "" {
		t.Fatalf("delivered %+v", got)
	}
	select {
	case m := <-r.phone.Inbox():
		t.Fatalf("owner got %q", m.Text)
	case m := <-shop.Inbox():
		t.Fatalf("sender got %q", m.Text)
	case <-time.After(100 * time.Millisecond):
	}
	if r.m.Pictures() != 1 || r.m.Dropped() != 0 {
		t.Fatalf("pictures %d, dropped %d", r.m.Pictures(), r.m.Dropped())
	}
}
