package vision

// REQ: DEV-7

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// tplB64 is a valid template (1.0, 2.0) as a reply line carries it.
const tplB64 = "AACAPwAAAEA="

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// recordDecoded keeps every template decodeReply decodes until the test
// ends.
func recordDecoded(t *testing.T) *[][]byte {
	t.Helper()
	var got [][]byte
	old := decoded
	decoded = func(v []byte) { got = append(got, v) }
	t.Cleanup(func() { decoded = old })
	return &got
}

// The reply is read into one buffer the call owns, and every byte of it
// is zero once the call returns, whether the reply was taken, refused,
// over its bound or cut short. The buffer starts non-zero, so a wipe of
// only the line, or none, shows.
func TestReplyReadBufferZeroed(t *testing.T) {
	var bufs [][]byte
	old := replyBuf
	replyBuf = func() []byte {
		b := bytes.Repeat([]byte{0xAA}, MaxReplyLine+1)
		bufs = append(bufs, b)
		return b
	}
	t.Cleanup(func() { replyBuf = old })
	ctx := context.Background()
	long := `{"template":"` + strings.Repeat("A", MaxReplyLine) + `"}`
	for name, line := range map[string]string{
		"taken":       `{"template":"` + tplB64 + `"}` + "\n",
		"error reply": `{"error":"no_face","template":"` + tplB64 + `"}` + "\n",
		"refused":     `{"template":"AADAfw=="}` + "\n",
		"over bound":  long + "\n",
		"cut short":   `{"template":"` + tplB64,
	} {
		bufs = nil
		path := serve(t, func(Request) []byte { return []byte(line) })
		got, err := ControlClient{Path: path, Timeout: time.Second}.Enrol(ctx, frame(4, 4))
		if name == "taken" {
			if err != nil || base64.StdEncoding.EncodeToString(got) != tplB64 {
				t.Fatalf("%s: %v %v", name, got, err)
			}
		} else if err == nil {
			t.Fatalf("%s: accepted", name)
		}
		if len(bufs) != 1 {
			t.Fatalf("%s: %d read buffers", name, len(bufs))
		}
		if !allZero(bufs[0]) {
			t.Errorf("%s: read buffer not zeroed", name)
		}
	}
}

// readLine's bound is the buffer: a line that fills it and its newline
// is read, one byte more is too long, and one cut short is an
// unexpected EOF.
func TestReadLineIntoBuffer(t *testing.T) {
	buf := make([]byte, 100)
	if l, err := readLine(strings.NewReader(strings.Repeat("a", 99)+"\nb"), buf); err != nil || len(l) != 99 {
		t.Fatalf("at the bound: %d %v", len(l), err)
	}
	if _, err := readLine(strings.NewReader(strings.Repeat("a", 100)+"\n"), buf); err != ErrLineTooLong {
		t.Fatalf("over the bound: %v", err)
	}
	if _, err := readLine(strings.NewReader("abc"), buf); err != io.ErrUnexpectedEOF {
		t.Fatalf("cut short: %v", err)
	}
	if _, err := readLine(strings.NewReader(""), buf); err != io.EOF {
		t.Fatalf("empty: %v", err)
	}
	// One byte a read: the newline is found in whichever read brings it.
	if l, err := readLine(io.MultiReader(strings.NewReader("ab"), strings.NewReader("c\n")), buf); err != nil || string(l) != "abc" {
		t.Fatalf("split: %q %v", l, err)
	}
}

// Every template decoded from a refused reply is zero once parseReply
// returns, whichever check refused it: the error-reply branch included.
func TestRefusedReplyTemplateZeroed(t *testing.T) {
	got := recordDecoded(t)
	enrol := Request{Op: OpEnrol}
	for name, c := range map[string]struct {
		req  Request
		line string
	}{
		"error reply":   {enrol, `{"error":"no_face","template":"` + tplB64 + `"}`},
		"unknown error": {enrol, `{"error":"x","template":"` + tplB64 + `"}`},
		"on detect":     {Request{Op: OpDetect, Format: FormatGray8, Width: 4, Height: 4}, `{"template":"` + tplB64 + `"}`},
		"on lend":       {Request{Op: OpLend}, `{"state":"ready","template":"` + tplB64 + `"}`},
		"other field":   {enrol, `{"template":"` + tplB64 + `","sounds":[]}`},
		"not finite":    {enrol, `{"template":"AACAPwAAwH8="}`},
		"twice":         {enrol, `{"template":"` + tplB64 + `","template":"` + tplB64 + `"}`},
		"unknown field": {enrol, `{"template":"` + tplB64 + `","x":1}`},
		"bad base64":    {enrol, `{"template":"AACAPwAAAE*="}`},
		"wrong type":    {enrol, `{"template":"` + tplB64 + `","state":1}`},
	} {
		*got = nil
		if _, err := parseReply(c.req, []byte(c.line), nil); err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if len(*got) == 0 {
			t.Errorf("%s: no template decoded", name)
		}
		for _, v := range *got {
			if !allZero(v) {
				t.Errorf("%s: a refused template is not zeroed", name)
			}
		}
	}
}

// A taken template is the one buffer it was decoded into, so the
// caller's wipe of it is the only one needed.
func TestTakenTemplateIsDecodedBuffer(t *testing.T) {
	got := recordDecoded(t)
	r, err := parseReply(Request{Op: OpEnrol}, []byte(`{"template":"`+tplB64+`"}`), nil)
	if err != nil || len(*got) != 1 || base64.StdEncoding.EncodeToString(r.Template) != tplB64 {
		t.Fatalf("%+v %v %d", r, err, len(*got))
	}
	if &r.Template[0] != &(*got)[0][0] {
		t.Fatal("the taken template is a copy of the decoded one")
	}
}

// The strict decoder, which copies its input into a buffer of its own,
// never sees the template's text; the line it sees differs from the
// reply only there. A template that is not plain base64 text (escaped,
// or not a string) is refused, and a null one takes no part.
func TestStrictDecoderNeverSeesTemplate(t *testing.T) {
	var seen [][]byte
	old := strictInput
	strictInput = func(b []byte) io.Reader {
		seen = append(seen, bytes.Clone(b))
		return bytes.NewReader(b)
	}
	t.Cleanup(func() { strictInput = old })
	line := `{ "template" : "` + tplB64 + `" }`
	if _, err := parseReply(Request{Op: OpEnrol}, []byte(line), nil); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(line, tplB64, strings.Repeat("A", len(tplB64)), 1)
	if len(seen) != 1 || string(seen[0]) != want {
		t.Fatalf("strict decoder saw %q, want %q", seen, want)
	}
	for name, l := range map[string]string{
		"escaped":    `{"template":"AACAPwAAAE` + "\\" + `u0041="}`,
		"array":      `{"template":[1234567890123456]}`,
		"object":     `{"template":{}}`,
		"upper case": `{"TEMPLATE":"` + tplB64 + `","template":"` + tplB64 + `"}`,
	} {
		_, err := parseReply(Request{Op: OpEnrol}, []byte(l), nil)
		wantUnavailable(t, name, err)
	}
	hello := `{"state":"ready","device":"cpu","model":"vis","sha256":"` + hash + `","template":null}`
	if _, err := parseReply(Request{Op: OpHello}, []byte(hello), nil); err != nil {
		t.Fatalf("null template: %v", err)
	}
}

// offsetIn finds a template's text only in the line's own memory: a
// slice of another allocation is refused, even one whose capacity puts
// its computed offset inside the line, so a copying encoding/json fails
// closed instead of blanking the wrong bytes.
func TestOffsetInLineOnly(t *testing.T) {
	// Spare capacity past the line, so a slice can run past its end.
	text := `{"template":"` + tplB64 + `"}`
	line := append(make([]byte, 0, len(text)+16), text...)
	raw := line[12 : 12+len(tplB64)+2]
	if at, ok := offsetIn(line, raw); !ok || at != 12 {
		t.Fatalf("sub-slice: %d %v", at, ok)
	}
	elsewhere := bytes.Clone(raw)
	if _, ok := offsetIn(line, elsewhere); ok {
		t.Fatal("a slice of another allocation was taken")
	}
	// cap(line) - cap(inRange) is 12, inside the line.
	inRange := make([]byte, len(raw), cap(line)-12)
	copy(inRange, raw)
	if at := cap(line) - cap(inRange); at+len(inRange) > len(line) {
		t.Fatal("fixture's offset is not in range")
	}
	if _, ok := offsetIn(line, inRange); ok {
		t.Fatal("a slice of another allocation with an in-range offset was taken")
	}
	// Offsets before the line, and past its end, are refused, not read.
	before := make([]byte, len(raw), cap(line)+1)
	if _, ok := offsetIn(line, before); ok {
		t.Fatal("a slice with a negative offset was taken")
	}
	if at, ok := offsetIn(line, line[:3]); !ok || at != 0 {
		t.Fatalf("the line's own first bytes: %d %v", at, ok)
	}
	if _, ok := offsetIn(line, line[len(line)-2:]); !ok {
		t.Fatal("the line's own last bytes were refused")
	}
	tail := make([]byte, 4, cap(line)-len(line)+2) // offset len(line)-2
	if _, ok := offsetIn(line, tail); ok {
		t.Fatal("a slice running past the line's end was taken")
	}
	if _, ok := offsetIn(line, line[len(line):]); ok {
		t.Fatal("an empty slice was taken")
	}
}

// An unmarshal that reads a copy of the line, as a future encoding/json
// might, leaves the template's text outside it: the reply is refused,
// not decoded strictly from a line still holding that text, and the
// template decoded from the copy is zeroed.
func TestTemplateReadFromCopyRefused(t *testing.T) {
	got := recordDecoded(t)
	old := unmarshal
	unmarshal = func(b []byte, v any) error { return old(bytes.Clone(b), v) }
	t.Cleanup(func() { unmarshal = old })
	_, err := parseReply(Request{Op: OpEnrol}, []byte(`{"template":"`+tplB64+`"}`), nil)
	var e *Error
	if !errors.As(err, &e) || e.Cause != Unavailable || e.Detail != "template not read in place" {
		t.Fatalf("got %v", err)
	}
	if len(*got) != 1 || !allZero((*got)[0]) {
		t.Fatalf("template from the copy not zeroed: %v", *got)
	}
}

// A request whose op the client does not know is refused as a bad
// request whatever the reply says.
func TestCheckReplyUnknownOp(t *testing.T) {
	_, err := parseReply(Request{Op: "bogus"}, []byte(`{}`), nil)
	var e *Error
	if !errors.As(err, &e) || e.Cause != BadRequest || e.Detail != "unknown op" {
		t.Fatalf("got %v", err)
	}
}
