package channel

import (
	"bytes"
	"io"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// REQ: NET-2, DEV-2

// watched wraps the engine and the radio and checks, on every call that
// acts, that what acted is one of the three kinds and allowed.
type watched struct {
	t     *testing.T
	eng   *policy.Engine
	radio *radio
}

func (w watched) Current() policy.Document { return w.eng.Current() }
func (w watched) Export() ([]byte, error)  { return w.eng.Export() }
func (w watched) Secure(d, c string, now int64) error {
	return w.eng.Secure(d, c, now)
}

func (w watched) Tighten(op policy.Op, now int64) error {
	prev := w.eng.Current()
	err := w.eng.Tighten(op, now)
	if err == nil {
		if c := policy.Classify(prev, w.eng.Current()); !c.Tightening || c.Owner {
			w.t.Fatalf("the channel applied %+v, which is not an unsigned closed-list tightening", op)
		}
	}
	return err
}

func (w watched) Do(device string, v wire.Verb, level uint8) error {
	dev := w.eng.Current().Device(device)
	if dev == nil || !Allowed(*dev, v) {
		w.t.Fatalf("the radio got %s %d for a device the table refuses it", device, v)
	}
	return w.radio.Do(device, v, level)
}

func (w watched) State(device string) ([]byte, error) { return w.radio.State(device) }

// FuzzParse (NET-2 Channel): any bytes after an honest hello. Only the
// three kinds act, and only as the table and the engine allow; every frame
// that decodes re-encodes to the same bytes (one encoding each); and the
// first frame that does not decode ends the connection with a logged
// refusal, so a loosening, rule change, unlock, disarm, arm, unknown or
// overlong frame never acts. Catches channel widening.
func FuzzParse(f *testing.F) {
	for _, m := range []wire.Msg{
		cmd(1, "heater", wire.VerbOff),
		cmd(2, "lamp", wire.VerbLevel),
		cmd(3, "drone", wire.VerbReturnToDock),
		wire.Tighten{ID: 4, Kind: wire.CutVendorCloud, Device: "tv"},
		wire.Tighten{ID: 5, Kind: wire.NarrowRule, Device: "lock", Rule: "plumber", FromMS: 5, ToMS: 6},
		wire.Read{ID: 6, What: wire.ReadExport},
		wire.Announce{ID: 7},
		wire.Head{ID: 8, Seq: 1},
		wire.Entry{ID: 9, Body: []byte("{}")},
		wire.Challenge{Answer: true, ID: 10, Data: []byte{1}},
	} {
		fr, err := wire.Encode(wire.ToEnforcer, m)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(frameBytes(fr.Type, fr.Payload))
	}
	f.Add([]byte{byte(wire.TCommand), 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 1, 8, 0, 1, 'x'})
	f.Fuzz(func(t *testing.T, data []byte) {
		var w watched
		r := newRig(t, func(c *Config) {
			w.t = t
			w.radio = &radio{}
			c.Radio = &w
			c.Policy = &w
		})
		w.eng = r.eng
		stream := append(helloFrame(t, r), data...)
		var out bytes.Buffer
		err := r.ch.Serve(struct {
			io.Reader
			io.Writer
		}{bytes.NewReader(stream), &out}, exporter)

		// Walk the same bytes with the codec alone.
		rd := bytes.NewReader(data)
		var bad bool
		for {
			fr, ferr := wire.ReadFrame(rd, wire.ToEnforcer)
			if ferr == io.EOF {
				break
			}
			var m wire.Msg
			if ferr == nil {
				m, ferr = wire.Decode(wire.ToEnforcer, fr)
			}
			if ferr == nil && fr.Type == wire.THello {
				ferr = wire.ErrType
			}
			if ferr != nil {
				bad = true
				break
			}
			again, eerr := wire.Encode(wire.ToEnforcer, m)
			if eerr != nil || again.Type != fr.Type || !bytes.Equal(again.Payload, fr.Payload) {
				t.Fatalf("%T decodes but does not re-encode to its bytes", m)
			}
		}
		if bad != (err != nil) {
			t.Fatalf("codec says malformed=%v, Serve returned %v", bad, err)
		}
		if bad {
			evs := r.events()
			if last := evs[len(evs)-1]; last.Kind != KindFrame || last.Code != wire.Refused {
				t.Fatalf("a refused frame was not logged: %+v", last)
			}
		}
	})
}
