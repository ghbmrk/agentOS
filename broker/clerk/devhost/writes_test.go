package devhost_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

// REQ: DEV-4

// writes is a driver that sends n declared get frames, one reading and
// done; a refused write ends it once the host closes the connection.
func writes(n int) script {
	return func(t *testing.T, c net.Conn) {
		if _, ok := declare(t, c); !ok {
			return
		}
		for range n {
			if !send(t, c, devslot.Msg{T: devslot.MsgWrite, Ch: "control", B: []byte{fixture.OpGet}}) {
				return
			}
			if m, err := recv(t, c); err != nil || m.T != devslot.MsgAck {
				return
			}
		}
		send(t, c, reading("temperature", -2, okTime))
		send(t, c, devslot.Msg{T: devslot.MsgDone})
	}
}

// The host, outside the driver's process, sends at most the operation's
// MaxWrites frames for one operation, so a hostile driver cannot repeat an
// actuation on one approval until the deadline (#3506).
func TestHostBoundsWrites(t *testing.T) {
	max := fixture.Declaration().Operations[0].MaxWrites
	t.Run("past MaxWrites", func(t *testing.T) {
		r := newRig(t, writes(max+5))
		if n, err := r.h.Do(context.Background(), "read-temperature"); !errors.Is(err, devslot.ErrWrites) || n != 0 {
			t.Fatalf("Do: %d, %v; want ErrWrites", n, err)
		}
		if len(r.tr.writes) != max || len(r.s.events) != 0 {
			t.Fatalf("%d frames reached the device, %d events; want %d and none", len(r.tr.writes), len(r.s.events), max)
		}
	})
	// A write the transport fails may still have reached the device, so it
	// counts at the host too, as in the slot (#4515).
	t.Run("failed writes count", func(t *testing.T) {
		r := newRig(t, writes(max+5))
		r.tr.fail = true
		if n, err := r.h.Do(context.Background(), "read-temperature"); !errors.Is(err, devslot.ErrWrites) || n != 0 {
			t.Fatalf("Do: %d, %v; want ErrWrites", n, err)
		}
		if len(r.tr.writes) != max {
			t.Fatalf("%d failed frames reached the transport, want %d", len(r.tr.writes), max)
		}
	})
	t.Run("control: MaxWrites writes, and each operation its own", func(t *testing.T) {
		r := newRig(t, writes(max), writes(max))
		for i := range 2 {
			if n, err := r.h.Do(context.Background(), "read-temperature"); err != nil || n != 1 {
				t.Fatalf("operation %d: %d, %v", i, n, err)
			}
		}
		if len(r.tr.writes) != 2*max {
			t.Fatalf("%d frames reached the device, want %d", len(r.tr.writes), 2*max)
		}
	})
	t.Run("a subscription instance", func(t *testing.T) {
		d := &dialer{t: t, scripts: []script{func(t *testing.T, c net.Conn) {
			if !declareSub(t, c) {
				return
			}
			for range 2 {
				send(t, c, devslot.Msg{T: devslot.MsgWrite, Ch: "control", B: []byte{fixture.OpGet}})
				if m, err := recv(t, c); err != nil || m.T != devslot.MsgAck {
					return
				}
			}
			t.Errorf("host acked a second write in an instance declaring one")
		}}}
		h := subHost(t, d, &sink{}, time.Minute, devhost.Limit{Burst: 10, Window: time.Minute}, nil)
		defer d.done.Wait()
		if _, err := h.Subscribe(context.Background(), "watch"); !errors.Is(err, devslot.ErrWrites) {
			t.Fatalf("Subscribe: %v, want ErrWrites", err)
		}
	})
}
