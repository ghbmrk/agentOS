package camera

import (
	"bytes"
	"testing"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// REQ: NET-2, KRN-2

// FuzzStatusFrame feeds the clerk's frame reader arbitrary node bytes: it
// never panics, returns a status only for an exact, well-formed status
// frame, which re-encodes to the bytes read, and returns a payload only
// for video or thermal.
func FuzzStatusFrame(f *testing.F) {
	st := camwire.AppendStatus(nil, camwire.Status{Uptime: 1, Settings: 2, Temperature: -50})
	good, _ := camwire.AppendFrame(nil, camwire.ToCore, camwire.Shape{}, camwire.Frame{Type: camwire.TypeStatus, Payload: st})
	f.Add(good)
	f.Add(append(good, good...))
	f.Add([]byte{3, 0, 0, 0, 49})
	f.Add([]byte{3, 0, 0, 0, 50, 1})
	f.Add([]byte{4, 0, 0, 0, 1, 0})
	f.Add([]byte{1, 0, 0, 0, 5, 0, 0, 0, 1, 9})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		for range 16 {
			at := len(b) - r.Len()
			fr, s, err := readOne(r, camwire.Shape{})
			if err != nil {
				return
			}
			if s != nil {
				if fr.Payload != nil {
					t.Fatal("status and payload both returned")
				}
				enc := camwire.AppendStatus(nil, *s)
				if got := b[at+camwire.HeaderLen : len(b)-r.Len()]; !bytes.Equal(enc, got) {
					t.Fatalf("status re-encodes to %x, read %x", enc, got)
				}
				continue
			}
			if fr.Type != camwire.TypeVideo && fr.Type != camwire.TypeThermal {
				t.Fatalf("payload of type %d returned", fr.Type)
			}
		}
	})
}
