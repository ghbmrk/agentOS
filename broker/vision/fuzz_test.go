package vision

// REQ: DEV-7, KRN-3

import (
	"encoding/json"
	"reflect"
	"testing"
)

// FuzzVisionReply feeds arbitrary reply lines to the client's parser. A
// line it accepts must hold only closed-vocabulary values inside the
// frame and of its format (the op byte's quotient by five picks the
// format), and must re-encode to a line it accepts again as the same reply;
// a line it refuses must be refused with a known cause.
func FuzzVisionReply(f *testing.F) {
	for _, s := range []string{
		`{}`,
		`{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":50,"face":"enrolled:alice"}]}`,
		`{"detections":[{"class":"vehicle","box":{"x0":1,"y0":1,"x1":8,"y1":8},"conf":99,"plate":"ABC 123"}]}`,
		`{"sounds":[{"label":"alarm","conf":80}]}`,
		`{"state":"ready","device":"cpu","model":"vis","sha256":"` + hash + `"}`,
		`{"error":"missing"}`,
		`{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":50,"embedding":[1,2]}]}`,
		`{"template":"AACAPwAAAEA="}`,
		`{"state":"ready"}`,
		`{"detections":[],"template":"AACAPw=="}`,
		`{"error":"no_face"}`,
		`{"detections":[{"class":"warm","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":50}]}`,
	} {
		for op := uint8(0); op < 15; op++ {
			f.Add([]byte(s), op, uint16(8), uint16(8))
		}
	}
	enrolled := func(id string) bool { return id == "alice" }
	ops := []string{OpHello, OpDetect, OpSound, OpEnrol, OpLend}
	formats := []string{FormatRGB24, FormatGray8, FormatY16}
	f.Fuzz(func(t *testing.T, line []byte, op uint8, w, h uint16) {
		o := ops[int(op)%len(ops)]
		fm := formats[int(op)/len(ops)%len(formats)]
		req := Request{Op: o, Format: fm, Width: int(w), Height: int(h)}
		r, err := parseReply(req, line, enrolled)
		if err != nil {
			if !CauseOf(err).Known() {
				t.Fatalf("unknown cause: %v", err)
			}
			return
		}
		if o != OpEnrol && r.Template != nil {
			t.Fatalf("%s accepted a template", o)
		}
		switch o {
		case OpEnrol:
			if CheckTemplate(r.Template) != nil || r.State != "" || r.Detections != nil || r.Sounds != nil || r.Model != "" {
				t.Fatalf("enrol accepted %+v", r)
			}
		case OpLend:
			if !reflect.DeepEqual(norm(r), Reply{State: StateReady}) {
				t.Fatalf("lend accepted %+v", r)
			}
		case OpHello:
			if r.State != StateReady || r.Device != DeviceCPU || !ValidModelName(r.Model) || !ValidHash(r.SHA256) || r.Detections != nil || r.Sounds != nil {
				t.Fatalf("hello accepted %+v", r)
			}
		case OpDetect:
			if err := CheckDetections(r.Detections, fm, int(w), int(h), enrolled); err != nil || r.Sounds != nil || r.Model != "" {
				t.Fatalf("detect accepted %+v: %v", r, err)
			}
			for _, d := range r.Detections {
				if id, ok := d.Enrolled(); ok && id != "alice" {
					t.Fatalf("enrolled id %q accepted", id)
				}
			}
		case OpSound:
			if err := CheckSounds(r.Sounds); err != nil || r.Detections != nil || r.Model != "" {
				t.Fatalf("sound accepted %+v: %v", r, err)
			}
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		again, err := parseReply(req, b, enrolled)
		if err != nil || !reflect.DeepEqual(norm(again), norm(r)) {
			t.Fatalf("re-encoded %s: %+v, %v; first %+v", b, again, err, r)
		}
	})
}

// norm treats an empty list as none, as the encoding does.
func norm(r Reply) Reply {
	if len(r.Template) == 0 {
		r.Template = nil
	}
	if len(r.Detections) == 0 {
		r.Detections = nil
	}
	if len(r.Sounds) == 0 {
		r.Sounds = nil
	}
	return r
}
