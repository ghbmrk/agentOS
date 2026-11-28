package vision

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"
)

// Client is agentosd's side of the vision service's feed socket. Each call
// dials the socket, writes one request (a header line and its payload) and
// reads one reply line, within Timeout.
type Client struct {
	// Path is the service's socket.
	Path string
	// Timeout bounds each call; zero is DefaultTimeout.
	Timeout time.Duration
	// Enrolled reports whether id is one the client holds a template for:
	// from its own clerk.Secrets slots (part c), never from the service.
	// Nil holds none, so every enrolled face is refused.
	Enrolled func(id string) bool
}

// Hello asks the service for its models and device. A service that is up
// but has no usable model answers Missing or Corrupt.
func (c Client) Hello(ctx context.Context) (Info, error) {
	r, err := c.call(ctx, Request{Op: OpHello}, nil)
	if err != nil {
		return Info{}, err
	}
	return Info{Model: r.Model, SHA256: r.SHA256, Device: r.Device}, nil
}

// Detect returns what the service saw in f. On any error it returns no
// detections, and the error's cause (CauseOf) is one of the four.
func (c Client) Detect(ctx context.Context, f Frame) ([]Detection, error) {
	req := Request{Op: OpDetect, Format: f.Format, Width: f.Width, Height: f.Height, Bytes: len(f.Data)}
	if err := req.Check(); err != nil {
		return nil, err
	}
	r, err := c.call(ctx, req, f.Data)
	if err != nil {
		return nil, err
	}
	return r.Detections, nil
}

// Sound returns the sound events the service heard in pcm, AudioPCM16k.
// Only labels come back; the audio is never kept (VIS-core point 7).
func (c Client) Sound(ctx context.Context, pcm []byte) ([]Sound, error) {
	req := Request{Op: OpSound, Format: AudioPCM16k, Bytes: len(pcm)}
	if err := req.Check(); err != nil {
		return nil, err
	}
	r, err := c.call(ctx, req, pcm)
	if err != nil {
		return nil, err
	}
	return r.Sounds, nil
}

// call sends one request and returns its checked reply, an error reply as
// its *Error, and anything else that goes wrong as Unavailable.
func (c Client) call(ctx context.Context, req Request, payload []byte) (Reply, error) {
	return c.callWith(ctx, req, payload, seams{})
}

// seams are the points a test watches or replaces in one call: the
// buffer a reply is read into, each template as it is decoded, the line
// the strict json.Decoder copies, and the unmarshal that reads the
// template in place. A nil field is the real one, so the zero value is
// production and no state is shared between calls.
type seams struct {
	buf         func() []byte
	decoded     func([]byte)
	strictInput func([]byte) io.Reader
	unmarshal   func([]byte, any) error
}

func (s seams) newBuf() []byte {
	if s.buf != nil {
		return s.buf()
	}
	return replyBuf()
}

func (s seams) strict(b []byte) io.Reader {
	if s.strictInput != nil {
		return s.strictInput(b)
	}
	return bytes.NewReader(b)
}

func (s seams) unmarshalLine(b []byte, v any) error {
	if s.unmarshal != nil {
		return s.unmarshal(b, v)
	}
	return json.Unmarshal(b, v)
}

// callWith is call with s's seams.
func (c Client) callWith(ctx context.Context, req Request, payload []byte, s seams) (Reply, error) {
	d := c.Timeout
	if d <= 0 {
		d = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	hdr, err := json.Marshal(req)
	if err != nil || len(hdr) > MaxHeaderLine {
		return Reply{}, badRequest("header line over its bound")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Path)
	if err != nil {
		return Reply{}, unavailable("service not reachable")
	}
	defer conn.Close()
	// The context's end closes the call however far it got.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	// A service that refuses the header answers and closes before taking
	// the payload, so a failed write still reads for its reply. The
	// payload is written from the caller's own buffer, never copied, so
	// no frame or template is left in a buffer here that nothing zeroes.
	_, werr := conn.Write(append(hdr, '\n'))
	if werr == nil && len(payload) > 0 {
		_, werr = conn.Write(payload)
	}
	// An enrol reply's line holds a template as text, so the reply is
	// read straight into one buffer this call owns and zeroes on every
	// path: no bufio.Reader keeps a window of it, and no append growth
	// leaves an earlier copy behind.
	buf := s.newBuf()
	defer clear(buf)
	line, err := readLine(conn, buf)
	if err != nil {
		switch {
		case ctx.Err() != nil:
			return Reply{}, unavailable("deadline")
		case err == ErrLineTooLong:
			return Reply{}, unavailable("reply line over its bound")
		case werr != nil:
			return Reply{}, unavailable("write failed")
		}
		return Reply{}, unavailable("no complete reply")
	}
	return parseReplyWith(req, line, c.Enrolled, s)
}

// replyBuf returns the buffer one call reads its reply into: a line at
// its bound and its newline.
func replyBuf() []byte { return make([]byte, MaxReplyLine+1) }

// readLine reads one reply line from r into buf and returns it without
// its newline, a slice of buf. A line that does not fit is
// ErrLineTooLong; one cut short is io.ErrUnexpectedEOF.
func readLine(r io.Reader, buf []byte) ([]byte, error) {
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		if i := bytes.IndexByte(buf[n:n+m], '\n'); i >= 0 {
			return buf[:n+i], nil
		}
		n += m
		if err != nil {
			if err == io.EOF && n > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
	}
	return nil, ErrLineTooLong
}

// skipValue takes any JSON value and keeps none of it.
type skipValue struct{}

func (*skipValue) UnmarshalJSON([]byte) error { return nil }

// wireTemplate decodes a reply's template from the line itself into one
// buffer of its own, so no copy of it, as text or bytes, is left in
// encoding/json, and keeps where in the line its text was. A template
// that is not a string, or is given twice, is refused, and so is one
// written with escapes (which encoding/json would unquote into a buffer
// of its own), since base64 has no backslash. The one decoded first stays
// for the caller to zero.
type wireTemplate struct {
	v   []byte
	raw []byte
	// decoded, if set, sees each template as it is decoded.
	decoded func([]byte)
}

func (t *wireTemplate) UnmarshalJSON(b []byte) error {
	if t.raw != nil {
		return errors.New("template twice")
	}
	t.raw = b
	if string(b) == "null" {
		return nil
	}
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return errors.New("template is not a string")
	}
	s := b[1 : len(b)-1]
	v := make([]byte, base64.StdEncoding.DecodedLen(len(s)))
	n, err := base64.StdEncoding.Decode(v, s)
	t.v = v[:n]
	if t.decoded != nil {
		t.decoded(v)
	}
	return err
}

// decodeReply decodes one reply line: an object of Reply's fields with
// none unknown, at any depth, and nothing after it. The template is
// decoded first, in place; the rest is decoded strictly from a copy of
// the line with the template's text left out, since a json.Decoder
// copies its input into a buffer nothing zeroes. On an error the
// template, if one was decoded, is zeroed.
func decodeReply(line []byte) (Reply, error) { return decodeReplyWith(line, seams{}) }

// decodeReplyWith is decodeReply with s's seams.
func decodeReplyWith(line []byte, s seams) (_ Reply, err error) {
	// An object only: null would decode as an empty reply.
	if t := bytes.TrimLeft(line, " \t\r"); len(t) == 0 || t[0] != '{' {
		return Reply{}, unavailable("reply is not an object")
	}
	// A valid object followed by more is its own fault, told apart from
	// a malformed reply before json.Unmarshal refuses both alike.
	if trailing(line) {
		return Reply{}, unavailable("data after the reply")
	}
	// json.Unmarshal reads the line in place: no copy of it is made.
	var tw struct {
		Template wireTemplate `json:"template"`
	}
	tw.Template.decoded = s.decoded
	defer func() {
		if err != nil {
			clear(tw.Template.v[:cap(tw.Template.v)])
		}
	}()
	if err := s.unmarshalLine(line, &tw); err != nil {
		return Reply{}, unavailable("malformed reply")
	}
	blank := line
	if raw := tw.Template.raw; len(raw) > 0 && raw[0] == '"' {
		at, ok := offsetIn(line, raw)
		if !ok {
			return Reply{}, unavailable("template not read in place")
		}
		// The line with the template's text as As: it never holds the text.
		blank = make([]byte, 0, len(line))
		blank = append(blank, line[:at+1]...)
		blank = append(blank, bytes.Repeat([]byte("A"), len(raw)-2)...)
		blank = append(blank, line[at+len(raw)-1:]...)
	}
	// trailing and json.Unmarshal above refused any data after the reply.
	dec := json.NewDecoder(s.strict(blank))
	dec.DisallowUnknownFields()
	var w struct {
		Reply
		// Shallower than Reply.Template, so it takes the "template" key.
		Template skipValue `json:"template"`
	}
	if err := dec.Decode(&w); err != nil {
		return Reply{}, unavailable("malformed reply")
	}
	r := w.Reply
	r.Template = tw.Template.v
	return r, nil
}

// trailing reports whether line is one valid JSON object followed by
// anything but white space. It scans the line in place and copies none
// of it: the object ends where its depth, outside strings, returns to
// zero.
func trailing(line []byte) bool {
	depth, inString, escaped := 0, false, false
	for i, c := range line {
		switch {
		case inString:
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			depth--
			if depth == 0 {
				end := i + 1
				return len(bytes.TrimLeft(line[end:], " \t\r\n")) > 0 && json.Valid(line[:end])
			}
		}
	}
	return false
}

// offsetIn returns where raw starts in line, if raw is a non-empty slice
// of line's own memory: its offset is what its capacity lacks. A raw
// from anywhere else (an encoding/json that copied its input) is not, so
// its text cannot be found in line to leave out.
func offsetIn(line, raw []byte) (int, bool) {
	at := cap(line) - cap(raw)
	if len(raw) == 0 || at < 0 || at+len(raw) > len(line) || &line[at] != &raw[0] {
		return 0, false
	}
	return at, true
}

// parseReply decodes one reply line for req and checks every field: an
// unknown field, a field req's op does not take, or a value off its list
// or outside its bound (a detection's against req's frame) is
// Unavailable. A refused reply's template is zeroed, whichever check
// refused it.
func parseReply(req Request, line []byte, enrolled func(string) bool) (Reply, error) {
	return parseReplyWith(req, line, enrolled, seams{})
}

// parseReplyWith is parseReply with s's seams.
func parseReplyWith(req Request, line []byte, enrolled func(string) bool, s seams) (Reply, error) {
	r, err := decodeReplyWith(line, s)
	if err != nil {
		return Reply{}, err
	}
	if err := checkReply(req, r, enrolled); err != nil {
		clear(r.Template[:cap(r.Template)])
		return Reply{}, err
	}
	return r, nil
}

// checkReply checks a decoded reply against req's op.
func checkReply(req Request, r Reply, enrolled func(string) bool) error {
	op := req.Op
	if r.Error != "" {
		if !r.Error.Known() || r.State != "" || r.Device != "" || r.Model != "" || r.SHA256 != "" || r.Detections != nil || r.Sounds != nil || r.Template != nil {
			return unavailable("malformed error reply")
		}
		return &Error{Cause: r.Error}
	}
	if r.Template != nil && op != OpEnrol {
		return unavailable("template on a reply that takes none")
	}
	hello := r.State != "" || r.Device != "" || r.Model != "" || r.SHA256 != ""
	switch op {
	case OpHello:
		if r.State != StateReady || r.Device != DeviceCPU || !ValidModelName(r.Model) || !ValidHash(r.SHA256) {
			return unavailable("hello reply is not ready")
		}
		if r.Detections != nil || r.Sounds != nil {
			return unavailable("hello reply has other fields")
		}
	case OpDetect:
		if hello || r.Sounds != nil {
			return unavailable("detect reply has other fields")
		}
		return CheckDetections(r.Detections, req.Format, req.Width, req.Height, enrolled)
	case OpSound:
		if hello || r.Detections != nil {
			return unavailable("sound reply has other fields")
		}
		return CheckSounds(r.Sounds)
	case OpEnrol:
		if hello || r.Detections != nil || r.Sounds != nil {
			return unavailable("enrol reply has other fields")
		}
		return CheckTemplate(r.Template)
	case OpLend:
		if r.State != StateReady || r.Device != "" || r.Model != "" || r.SHA256 != "" || r.Detections != nil || r.Sounds != nil {
			return unavailable("lend reply is not ready")
		}
	default:
		return badRequest("unknown op")
	}
	return nil
}

// ControlClient is the trusted side's client of the service's control
// socket (vision/faces): the one path that asks for an enrolment template
// and lends the enrolled ones. Only the side holding the template slots
// holds it; the feed's Client never sends a control op.
type ControlClient struct {
	// Path is the service's control socket.
	Path string
	// Timeout bounds each call; zero is DefaultTimeout.
	Timeout time.Duration
}

// Enrol returns the template of the one face in f. The caller seals it
// and zeroes it; a frame without exactly one clear face is NoFace.
func (c ControlClient) Enrol(ctx context.Context, f Frame) ([]byte, error) {
	req := Request{Op: OpEnrol, Format: f.Format, Width: f.Width, Height: f.Height, Bytes: len(f.Data)}
	if err := req.Check(); err != nil {
		return nil, err
	}
	r, err := Client{Path: c.Path, Timeout: c.Timeout}.call(ctx, req, f.Data)
	if err != nil {
		return nil, err
	}
	return r.Template, nil
}

// Lend replaces every template the service holds with ts; none holds
// none. The payload is zeroed once sent.
func (c ControlClient) Lend(ctx context.Context, ts []Template) error {
	payload, err := EncodeLend(ts)
	if err != nil {
		return err
	}
	defer clear(payload)
	req := Request{Op: OpLend, Bytes: len(payload)}
	if err := req.Check(); err != nil {
		return err
	}
	_, err = Client{Path: c.Path, Timeout: c.Timeout}.call(ctx, req, payload)
	return err
}
