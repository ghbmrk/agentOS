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

// Client is agentosd's side of the vision service's socket. Each call
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
	r, err := c.call(ctx, Request{Op: OpHello}, nil, 0, 0)
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
	r, err := c.call(ctx, req, f.Data, f.Width, f.Height)
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
	r, err := c.call(ctx, req, pcm, 0, 0)
	if err != nil {
		return nil, err
	}
	return r.Sounds, nil
}

// call sends one request and returns its checked reply, an error reply as
// its *Error, and anything else that goes wrong as Unavailable.
func (c Client) call(ctx context.Context, req Request, payload []byte, w, h int) (Reply, error) {
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
	// the payload, so a failed write still reads for its reply.
	_, werr := conn.Write(append(append(hdr, '\n'), payload...))
	line, err := ReadLine(bufio.NewReaderSize(conn, 4<<10), MaxReplyLine)
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
	return parseReply(req.Op, line, w, h, c.Enrolled)
}

// parseReply decodes one reply line for op and checks every field: an
// unknown field, a field op does not take, or a value off its list or
// outside its bound is Unavailable.
func parseReply(op string, line []byte, w, h int, enrolled func(string) bool) (Reply, error) {
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
		if !r.Error.Known() || r.State != "" || r.Device != "" || r.Model != "" || r.SHA256 != "" || r.Detections != nil || r.Sounds != nil {
			return Reply{}, unavailable("malformed error reply")
		}
		return Reply{}, &Error{Cause: r.Error}
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
		if err := CheckDetections(r.Detections, w, h, enrolled); err != nil {
			return Reply{}, err
		}
	case OpSound:
		if hello || r.Detections != nil {
			return Reply{}, unavailable("sound reply has other fields")
		}
		if err := CheckSounds(r.Sounds); err != nil {
			return Reply{}, err
		}
	default:
		return Reply{}, badRequest("unknown op")
	}
	return r, nil
}
