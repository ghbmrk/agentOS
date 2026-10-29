package vision

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
	line, err := ReadLine(bufio.NewReaderSize(conn, 4<<10), MaxReplyLine)
	// An enrol reply's line holds a template as text.
	defer clear(line)
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
	return parseReply(req, line, c.Enrolled)
}

// parseReply decodes one reply line for req and checks every field: an
// unknown field, a field req's op does not take, or a value off its list
// or outside its bound (a detection's against req's frame) is
// Unavailable.
func parseReply(req Request, line []byte, enrolled func(string) bool) (Reply, error) {
	op := req.Op
	// An object only: null would decode as an empty reply.
	if t := bytes.TrimLeft(line, " \t\r"); len(t) == 0 || t[0] != '{' {
		return Reply{}, unavailable("reply is not an object")
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var r Reply
	if err := dec.Decode(&r); err != nil {
		return Reply{}, unavailable("malformed reply")
	}
	if _, err := dec.Token(); err != io.EOF {
		return Reply{}, unavailable("data after the reply")
	}
	if r.Error != "" {
		if !r.Error.Known() || r.State != "" || r.Device != "" || r.Model != "" || r.SHA256 != "" || r.Detections != nil || r.Sounds != nil || r.Template != nil {
			return Reply{}, unavailable("malformed error reply")
		}
		return Reply{}, &Error{Cause: r.Error}
	}
	if r.Template != nil && op != OpEnrol {
		clear(r.Template)
		return Reply{}, unavailable("template on a reply that takes none")
	}
	hello := r.State != "" || r.Device != "" || r.Model != "" || r.SHA256 != ""
	switch op {
	case OpHello:
		if r.State != StateReady || r.Device != DeviceCPU || !ValidModelName(r.Model) || !ValidHash(r.SHA256) {
			return Reply{}, unavailable("hello reply is not ready")
		}
		if r.Detections != nil || r.Sounds != nil {
			return Reply{}, unavailable("hello reply has other fields")
		}
	case OpDetect:
		if hello || r.Sounds != nil {
			return Reply{}, unavailable("detect reply has other fields")
		}
		if err := CheckDetections(r.Detections, req.Format, req.Width, req.Height, enrolled); err != nil {
			return Reply{}, err
		}
	case OpSound:
		if hello || r.Detections != nil {
			return Reply{}, unavailable("sound reply has other fields")
		}
		if err := CheckSounds(r.Sounds); err != nil {
			return Reply{}, err
		}
	case OpEnrol:
		if hello || r.Detections != nil || r.Sounds != nil {
			clear(r.Template)
			return Reply{}, unavailable("enrol reply has other fields")
		}
		if err := CheckTemplate(r.Template); err != nil {
			clear(r.Template)
			return Reply{}, err
		}
	case OpLend:
		if r.State != StateReady || r.Device != "" || r.Model != "" || r.SHA256 != "" || r.Detections != nil || r.Sounds != nil {
			return Reply{}, unavailable("lend reply is not ready")
		}
	default:
		return Reply{}, badRequest("unknown op")
	}
	return r, nil
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
