package camera

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// REQ: NET-2, KRN-2, DEV-8

// fixedLine is every line the clerk may log while reading a stream.
var fixedLine = regexp.MustCompile(`^camera porch: (stream ended: a frame broke the camera wire|stream ended: the decoder refused a frame|silent past its interval|streaming again|event not delivered \(KRN-7\))$`)

// FuzzStatusFrame: whatever a node sends after the handshake, the clerk's
// reader never panics; only video and thermal frames within their caps
// reach the decoder, as sent; the status it keeps is exactly the last
// well-formed status frame's; and it logs only fixed lines, so nothing the
// node sent reaches the log or an event. Revert mutant: serve passing a
// status frame to the decoder fails the type check.
func FuzzStatusFrame(f *testing.F) {
	st := status().Payload
	f.Add(append([]byte{byte(camwire.TypeStatus), 0, 0, 0, camwire.StatusLen}, st...))
	f.Add(append(append([]byte{byte(camwire.TypeStatus), 0, 0, 0, camwire.StatusLen}, st...), 1, 0, 0, 0, 5, 0, 0, 0, 1, 0x65))
	f.Add([]byte{byte(camwire.TypeStatus), 0, 0, 0, camwire.StatusLen - 1, 0})
	f.Add([]byte{byte(camwire.TypeStatus), 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{byte(camwire.TypeThermal), 0, 0, 0, 32})
	f.Add([]byte{byte(camwire.TypeBundle), 0, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		ev, fr, lg := &events{}, &frames{}, &lines{}
		c := &Clerk{
			cfg:   Config{Frames: fr, Events: ev, Limit: Limit{Burst: 5, Window: time.Minute}, Now: time.Now, Log: lg.add},
			nodes: map[string]*node{},
			win:   map[wkey]*window{},
		}
		pin := Node{ID: testID, Addr: testAddr, Key: [32]byte{1}, Thermal: lepton, Capture: Continuous, Interval: time.Hour}
		n := &node{pin: pin, last: time.Now()}
		c.nodes[testID] = n
		c.serve(n, bytes.NewReader(data), pin)

		// The expected frames, read by the codec itself.
		r := bytes.NewReader(data)
		var want []camwire.Frame
		var last camwire.Status
		has := false
		for {
			f, err := camwire.ReadFrame(r, camwire.ToCore, lepton)
			if err != nil {
				break
			}
			switch f.Type {
			case camwire.TypeStatus:
				last, _ = camwire.ParseStatus(f.Payload)
				has = true
			case camwire.TypeVideo, camwire.TypeThermal:
				want = append(want, f)
			default:
				t.Fatalf("the codec passed type %d on the core's channel", f.Type)
			}
		}
		if len(fr.f) != len(want) {
			t.Fatalf("%d frames reached the decoder, want %d", len(fr.f), len(want))
		}
		for i, f := range fr.f {
			if f.Type != want[i].Type || !bytes.Equal(f.Payload, want[i].Payload) {
				t.Fatalf("frame %d changed on its way to the decoder", i)
			}
			if f.Type == camwire.TypeVideo && len(f.Payload) > camwire.MaxVideo {
				t.Fatal("an over-cap frame reached the decoder")
			}
		}
		if n.has != has || n.status != last {
			t.Fatalf("status = %+v (%v), want %+v (%v)", n.status, n.has, last, has)
		}
		for _, l := range lg.l {
			if !fixedLine.MatchString(l) {
				t.Fatalf("log line %q is not a fixed line", l)
			}
		}
		for _, e := range ev.ev {
			if e.Camera != testID || e.Label != Label || !e.Verified {
				t.Fatalf("event %+v", e)
			}
		}
		if s := strings.Join(c.Status(), "\n"); strings.ContainsAny(s, "\x00\xff") {
			t.Fatalf("STATUS holds stream bytes: %q", s)
		}
	})
}

// A reader that ends mid-frame is a transport end, not a fault: no event.
func TestTruncatedStreamIsNotAFault(t *testing.T) {
	ev := &events{}
	c := &Clerk{cfg: Config{Frames: &frames{}, Events: ev, Limit: Limit{Burst: 5, Window: time.Minute}, Now: time.Now}, nodes: map[string]*node{}, win: map[wkey]*window{}}
	pin := Node{ID: testID, Interval: time.Hour}
	n := &node{pin: pin, last: time.Now()}
	c.serve(n, io.MultiReader(bytes.NewReader([]byte{1, 0, 0, 0, 9, 0, 0})), pin)
	if len(ev.ev) != 0 {
		t.Fatalf("events = %+v", ev.ev)
	}
}
