package vision

// REQ: DEV-7, DEV-8, KRN-3

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// serve answers each connection's request (header line and payload) with
// reply(req). A nil reply closes the connection unanswered; "SLEEP" sleeps
// instead of answering.
func serve(t *testing.T, reply func(Request) []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				line, err := ReadLine(r, MaxHeaderLine)
				if err != nil {
					return
				}
				var req Request
				if json.Unmarshal(line, &req) != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, r, int64(req.Bytes)); err != nil {
					return
				}
				b := reply(req)
				if string(b) == "SLEEP" {
					time.Sleep(5 * time.Second)
					return
				}
				c.Write(b)
			}()
		}
	}()
	return path
}

func frame(w, h int) Frame {
	return Frame{Format: FormatGray8, Width: w, Height: h, Data: make([]byte, w*h)}
}

func person(x0, y0, x1, y1, conf int) Detection {
	return Detection{Class: Person, Box: Box{x0, y0, x1, y1}, Conf: conf}
}

func detectReply(t *testing.T, ds ...Detection) []byte {
	b, err := json.Marshal(Reply{Detections: ds})
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// fixed answers every request with the same line.
func fixed(line string) func(Request) []byte {
	return func(Request) []byte { return []byte(line + "\n") }
}

func detect(t *testing.T, path string, f Frame, enrolled func(string) bool) ([]Detection, error) {
	t.Helper()
	return Client{Path: path, Timeout: time.Second, Enrolled: enrolled}.Detect(context.Background(), f)
}

func wantUnavailable(t *testing.T, name string, err error) {
	t.Helper()
	if err == nil || CauseOf(err) != Unavailable {
		t.Errorf("%s: %v, want unavailable", name, err)
	}
}

func TestProtocolRoundTrip(t *testing.T) {
	var seen atomic.Value
	path := serve(t, func(r Request) []byte {
		seen.Store(r)
		switch r.Op {
		case OpHello:
			return []byte(`{"state":"ready","device":"cpu","model":"vis-0.1","sha256":"` + hash + `"}` + "\n")
		case OpSound:
			return []byte(`{"sounds":[{"label":"glass-break","conf":91}]}` + "\n")
		}
		return detectReply(t, person(1, 2, 30, 40, 87),
			Detection{Class: Vehicle, Box: Box{0, 0, 64, 48}, Conf: 55, Plate: "ABC 123"})
	})
	c := Client{Path: path, Timeout: time.Second}
	in, err := c.Hello(context.Background())
	if err != nil || in != (Info{Model: "vis-0.1", SHA256: hash, Device: DeviceCPU}) {
		t.Fatalf("hello: %+v, %v", in, err)
	}
	ds, err := c.Detect(context.Background(), Frame{Format: FormatRGB24, Width: 64, Height: 48, Data: make([]byte, 64*48*3)})
	if err != nil || len(ds) != 2 || ds[0].Box != (Box{1, 2, 30, 40}) || ds[1].Plate != "ABC 123" {
		t.Fatalf("detect: %+v, %v", ds, err)
	}
	if r := seen.Load().(Request); r != (Request{Op: OpDetect, Format: FormatRGB24, Width: 64, Height: 48, Bytes: 64 * 48 * 3}) {
		t.Fatalf("header %+v", r)
	}
	ss, err := c.Sound(context.Background(), make([]byte, 3200))
	if err != nil || len(ss) != 1 || ss[0] != (Sound{"glass-break", 91}) {
		t.Fatalf("sound: %+v, %v", ss, err)
	}
	ds, err = detect(t, serve(t, fixed(`{}`)), frame(8, 8), nil)
	if err != nil || len(ds) != 0 {
		t.Fatalf("empty detect: %+v, %v", ds, err)
	}
}

// REQ: DEV-7
//
// An enrolled face names an id the client holds; any other id, or any
// enrolled face when the client holds none, is unavailable, so the service
// cannot invent ids to carry bits or claim a stranger is household.
func TestEnrolledIDMustBeKnown(t *testing.T) {
	known := func(id string) bool { return id == "alice" }
	face := func(f string) []byte {
		d := person(0, 0, 4, 4, 90)
		d.Face = f
		return detectReply(t, d)
	}
	ds, err := detect(t, serve(t, func(Request) []byte { return face("enrolled:alice") }), frame(8, 8), known)
	if err != nil || len(ds) != 1 {
		t.Fatalf("known id: %+v, %v", ds, err)
	}
	if id, ok := ds[0].Enrolled(); !ok || id != "alice" {
		t.Fatalf("Enrolled() = %q, %v", id, ok)
	}
	if _, err := detect(t, serve(t, func(Request) []byte { return face("unknown") }), frame(8, 8), known); err != nil {
		t.Fatalf("unknown face: %v", err)
	}
	for name, c := range map[string]struct {
		face     string
		enrolled func(string) bool
	}{
		"unknown id":         {"enrolled:mallory", known},
		"none held":          {"enrolled:alice", nil},
		"empty id":           {"enrolled:", func(string) bool { return true }},
		"id off its charset": {"enrolled:Alice", func(string) bool { return true }},
		"long id":            {"enrolled:" + strings.Repeat("a", MaxEnrolledID+1), func(string) bool { return true }},
		"free text":          {"looks like alice", known},
		"no prefix":          {"alice", known},
	} {
		_, err := detect(t, serve(t, func(Request) []byte { return face(c.face) }), frame(8, 8), c.enrolled)
		wantUnavailable(t, name, err)
	}
	d := Detection{Class: Dog, Box: Box{0, 0, 4, 4}, Conf: 90, Face: FaceUnknown}
	_, err = detect(t, serve(t, func(Request) []byte { return detectReply(t, d) }), frame(8, 8), known)
	wantUnavailable(t, "face on a dog", err)
}

// REQ: DEV-8
//
// Plate text is [A-Z0-9 -]{1,10} with no space at either end, only on a
// vehicle, and an event quotes it as device-supplied text.
func TestPlateTextBounded(t *testing.T) {
	car := func(p string) Detection { return Detection{Class: Vehicle, Box: Box{0, 0, 4, 4}, Conf: 70, Plate: p} }
	for _, p := range []string{"A", "ABC 123", "7-XYZ-12", "0123456789"} {
		ds, err := detect(t, serve(t, func(Request) []byte { return detectReply(t, car(p)) }), frame(8, 8), nil)
		if err != nil || ds[0].Plate != p {
			t.Errorf("plate %q: %+v, %v", p, ds, err)
			continue
		}
		if q := ds[0].QuotedPlate(); q != `"`+p+`"` {
			t.Errorf("quoted %q", q)
		}
	}
	for _, p := range []string{"abc123", "ABC_123", "ABCDEFGHIJK", " ABC", "ABC ", "ÄBC", "AB\n12", "AB\"1", "AB\\x"} {
		_, err := detect(t, serve(t, func(Request) []byte { return detectReply(t, car(p)) }), frame(8, 8), nil)
		wantUnavailable(t, "plate "+p, err)
	}
	d := person(0, 0, 4, 4, 70)
	d.Plate = "ABC"
	_, err := detect(t, serve(t, func(Request) []byte { return detectReply(t, d) }), frame(8, 8), nil)
	wantUnavailable(t, "plate on a person", err)
	if (Detection{}).QuotedPlate() != "" {
		t.Error("no plate quotes as text")
	}
}

// Boxes are integers inside the frame with positive size, confidences are
// whole percent from 1 to 100, and a reply holds at most MaxDetections.
func TestBoxesAndConfidenceBounded(t *testing.T) {
	for name, line := range map[string]string{
		"x1 past width":     `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":9,"y1":4},"conf":50}]}`,
		"y1 past height":    `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":9},"conf":50}]}`,
		"negative x0":       `{"detections":[{"class":"person","box":{"x0":-1,"y0":0,"x1":4,"y1":4},"conf":50}]}`,
		"empty box":         `{"detections":[{"class":"person","box":{"x0":3,"y0":0,"x1":3,"y1":4},"conf":50}]}`,
		"inverted box":      `{"detections":[{"class":"person","box":{"x0":0,"y0":4,"x1":4,"y1":1},"conf":50}]}`,
		"fractional box":    `{"detections":[{"class":"person","box":{"x0":0.5,"y0":0,"x1":4,"y1":4},"conf":50}]}`,
		"exponent box":      `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4e0,"y1":4},"conf":50}]}`,
		"string box":        `{"detections":[{"class":"person","box":{"x0":"0","y0":0,"x1":4,"y1":4},"conf":50}]}`,
		"array box":         `{"detections":[{"class":"person","box":[0,0,4,4],"conf":50}]}`,
		"huge box":          `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":99999999999999999999,"y1":4},"conf":50}]}`,
		"fractional conf":   `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":50.25}]}`,
		"unit-scale conf":   `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":0.87}]}`,
		"zero conf":         `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":0}]}`,
		"conf over 100":     `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":101}]}`,
		"missing conf":      `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4}}]}`,
		"sound on a detect": `{"sounds":[{"label":"alarm","conf":50}]}`,
	} {
		_, err := detect(t, serve(t, fixed(line)), frame(8, 8), nil)
		wantUnavailable(t, name, err)
	}
	for name, line := range map[string]string{
		"sound conf over":      `{"sounds":[{"label":"alarm","conf":101}]}`,
		"sound conf fraction":  `{"sounds":[{"label":"alarm","conf":0.5}]}`,
		"repeated sound":       `{"sounds":[{"label":"alarm","conf":50},{"label":"alarm","conf":60}]}`,
		"unknown sound":        `{"sounds":[{"label":"speech","conf":50}]}`,
		"detections on sound":  `{"detections":[]}`,
		"sound with extra key": `{"sounds":[{"label":"alarm","conf":50,"clip":"AAAA"}]}`,
	} {
		_, err := Client{Path: serve(t, fixed(line)), Timeout: time.Second}.Sound(context.Background(), make([]byte, 320))
		wantUnavailable(t, name, err)
	}
	if len(SoundLabels()) != MaxSounds {
		t.Fatalf("%d labels, MaxSounds %d", len(SoundLabels()), MaxSounds)
	}
	all := make([]Sound, 0, MaxSounds)
	for _, l := range SoundLabels() {
		all = append(all, Sound{l, 60})
	}
	b, _ := json.Marshal(Reply{Sounds: all})
	if ss, err := (Client{Path: serve(t, fixed(string(b))), Timeout: time.Second}).Sound(context.Background(), make([]byte, 320)); err != nil || len(ss) != MaxSounds {
		t.Fatalf("every label once: %v, %v", ss, err)
	}
	full := make([]Detection, MaxDetections)
	for i := range full {
		full[i] = person(0, 0, 8, 8, 100)
	}
	if ds, err := detect(t, serve(t, func(Request) []byte { return detectReply(t, full...) }), frame(8, 8), nil); err != nil || len(ds) != MaxDetections {
		t.Fatalf("%d detections: %d, %v", MaxDetections, len(ds), err)
	}
	over := append(full, person(0, 0, 8, 8, 100))
	_, err := detect(t, serve(t, func(Request) []byte { return detectReply(t, over...) }), frame(8, 8), nil)
	wantUnavailable(t, "over-count", err)
}

// REQ: DEV-7, KRN-3
//
// Every field is from a closed vocabulary: a class off the list, free
// text, or any field the protocol does not define is unavailable, so a
// compromised service has nowhere to put an encoding.
func TestRepliesAreClosedVocabulary(t *testing.T) {
	ok := `{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":50`
	for name, line := range map[string]string{
		"class off the list":   `{"detections":[{"class":"burglar","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":50}]}`,
		"class case":           `{"detections":[{"class":"Person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":50}]}`,
		"caption":              `{"detections":[` + ok + `,"caption":"man in a red jacket"}]}`,
		"attributes":           `{"detections":[` + ok + `,"attributes":["red jacket"]}]}`,
		"embedding":            `{"detections":[` + ok + `,"embedding":[0.1,0.2,0.3]}]}`,
		"track id":             `{"detections":[` + ok + `,"track":7}]}`,
		"box extra":            `{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4,"z":1},"conf":50}]}`,
		"top-level extra":      `{"detections":[` + ok + `}],"note":"x"}`,
		"detail on an error":   `{"error":"unavailable","detail":"AAAAAAAAAAAAAAAAAAAAAAAAAA"}`,
		"unknown cause":        `{"error":"oops"}`,
		"error with data":      `{"error":"missing","detections":[]}`,
		"hello fields":         `{"model":"vis","detections":[` + ok + `}]}`,
		"face as free text":    `{"detections":[` + ok + `,"face":"tall, beard"}]}`,
		"second JSON value":    `{"detections":[]} {"embedding":[1]}`,
		"trailing garbage":     `{"detections":[]}xx`,
		"non-object":           `["person"]`,
		"null":                 `null`,
		"detections an object": `{"detections":{"class":"person"}}`,
	} {
		_, err := detect(t, serve(t, fixed(line)), frame(8, 8), func(string) bool { return true })
		wantUnavailable(t, name, err)
	}
	// Every class on the list passes.
	for _, c := range Classes() {
		d := Detection{Class: c, Box: Box{0, 0, 4, 4}, Conf: 50}
		if _, err := detect(t, serve(t, func(Request) []byte { return detectReply(t, d) }), frame(8, 8), nil); err != nil {
			t.Errorf("class %s: %v", c, err)
		}
	}
	// A hello reply's fields are closed too: the model name has no free
	// text, and the device is the one this build may report.
	for name, line := range map[string]string{
		"model free text":  `{"state":"ready","device":"cpu","model":"Vision model, see notes","sha256":"` + hash + `"}`,
		"model with space": `{"state":"ready","device":"cpu","model":"vis model","sha256":"` + hash + `"}`,
		"other device":     `{"state":"ready","device":"gpu0","model":"vis","sha256":"` + hash + `"}`,
		"no device":        `{"state":"ready","model":"vis","sha256":"` + hash + `"}`,
		"bad hash":         `{"state":"ready","device":"cpu","model":"vis","sha256":"XYZ"}`,
		"not ready":        `{"state":"loading","device":"cpu","model":"vis","sha256":"` + hash + `"}`,
		"with detections":  `{"state":"ready","device":"cpu","model":"vis","sha256":"` + hash + `","detections":[]}`,
	} {
		_, err := Client{Path: serve(t, fixed(line)), Timeout: time.Second}.Hello(context.Background())
		wantUnavailable(t, name, err)
	}
}

// Malformed replies are unavailable: wrong counts, NaN boxes, an over-long
// line, truncated JSON and a deadline.
func TestClientRejectsMalformedReplies(t *testing.T) {
	long := `{"detections":[` + strings.Repeat(`{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":50},`, 600) + `]}`
	for name, reply := range map[string]func(Request) []byte{
		"wrong count":    func(Request) []byte { return detectReply(t, make([]Detection, MaxDetections+1)...) },
		"NaN box":        fixed(`{"detections":[{"class":"person","box":{"x0":NaN,"y0":0,"x1":4,"y1":4},"conf":50}]}`),
		"infinite conf":  fixed(`{"detections":[{"class":"person","box":{"x0":0,"y0":0,"x1":4,"y1":4},"conf":1e999}]}`),
		"over-long line": fixed(long),
		"truncated JSON": func(Request) []byte { return []byte(`{"detections":[{"class":"per`) },
		"no newline":     func(Request) []byte { return []byte(`{}`) },
		"no reply":       func(Request) []byte { return nil },
		"deadline":       func(Request) []byte { return []byte("SLEEP") },
		"not JSON":       fixed(`hello`),
	} {
		start := time.Now()
		_, err := Client{Path: serve(t, reply), Timeout: 300 * time.Millisecond}.Detect(context.Background(), frame(8, 8))
		wantUnavailable(t, name, err)
		if time.Since(start) > 2*time.Second {
			t.Errorf("%s: took %s", name, time.Since(start))
		}
	}
	_, err := Client{Path: filepath.Join(t.TempDir(), "none.sock")}.Detect(context.Background(), frame(8, 8))
	wantUnavailable(t, "no service", err)
}

// The service's own error cause passes; its text never does.
func TestClientPassesTheServiceCause(t *testing.T) {
	for _, c := range []Cause{Missing, Corrupt, Unavailable, BadRequest} {
		_, err := detect(t, serve(t, fixed(`{"error":"`+string(c)+`"}`)), frame(8, 8), nil)
		var e *Error
		if !errors.As(err, &e) || e.Cause != c || e.Detail != "" {
			t.Errorf("%s: %v", c, err)
		}
	}
}

// Requests outside the bounds are refused before anything is sent.
func TestClientChecksBoundsBeforeSending(t *testing.T) {
	var calls atomic.Int32
	path := serve(t, func(Request) []byte { calls.Add(1); return []byte("{}\n") })
	c := Client{Path: path, Timeout: time.Second}
	for name, f := range map[string]Frame{
		"unknown format": {Format: "jpeg", Width: 2, Height: 2, Data: make([]byte, 4)},
		"short data":     {Format: FormatRGB24, Width: 2, Height: 2, Data: make([]byte, 11)},
		"long data":      {Format: FormatY16, Width: 2, Height: 2, Data: make([]byte, 9)},
		"zero width":     {Format: FormatGray8, Width: 0, Height: 2},
		"too wide":       {Format: FormatGray8, Width: MaxWidth + 1, Height: 1, Data: make([]byte, MaxWidth+1)},
		"too tall":       {Format: FormatGray8, Width: 1, Height: MaxHeight + 1, Data: make([]byte, MaxHeight+1)},
	} {
		if _, err := c.Detect(context.Background(), f); err == nil || CauseOf(err) != BadRequest {
			t.Errorf("%s: %v, want bad_request", name, err)
		}
	}
	for name, n := range map[string]int{"empty": 0, "odd": 3, "too long": MaxAudioBytes + 2} {
		if _, err := c.Sound(context.Background(), make([]byte, n)); err == nil || CauseOf(err) != BadRequest {
			t.Errorf("audio %s: %v, want bad_request", name, err)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("%d requests reached the service", calls.Load())
	}
	for name, r := range map[string]Request{
		"hello with size": {Op: OpHello, Width: 1},
		"unknown op":      {Op: "describe"},
		"sound sized":     {Op: OpSound, Format: AudioPCM16k, Width: 1, Bytes: 2},
	} {
		if err := r.Check(); err == nil || CauseOf(err) != BadRequest {
			t.Errorf("%s passed Check", name)
		}
	}
}

func TestReadLineBound(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 100)+"\n"), 16)
	if _, err := ReadLine(r, 99); err != ErrLineTooLong {
		t.Fatalf("100 bytes at bound 99: %v", err)
	}
	r = bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 99)+"\nrest"), 16)
	if l, err := ReadLine(r, 99); err != nil || len(l) != 99 {
		t.Fatalf("99 bytes at bound 99: %d, %v", len(l), err)
	}
	if _, err := ReadLine(r, 99); err != io.ErrUnexpectedEOF {
		t.Fatalf("unterminated: %v", err)
	}
}
