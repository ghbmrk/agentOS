package infer

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"time"
)

// Client is agentosd's side of the inference service's socket. Each call
// dials the socket, writes one request line and reads one reply line,
// within Timeout.
type Client struct {
	// Path is the service's socket.
	Path string
	// Timeout bounds each call; zero is DefaultTimeout.
	Timeout time.Duration
}

// Hello asks the service for its model. A service that is up but has no
// usable model answers Missing or Corrupt.
func (c Client) Hello(ctx context.Context) (Info, error) {
	r, err := c.call(ctx, Request{Op: OpHello})
	if err != nil {
		return Info{}, err
	}
	if r.State != StateReady || r.Vectors != nil {
		return Info{}, unavailable("hello reply is not ready")
	}
	return info(r)
}

// Embed returns one vector per text, in order, and the model they came
// from. On any error it returns no vectors, and the error's cause
// (CauseOf) is one of the four.
func (c Client) Embed(ctx context.Context, texts []string) ([][]float32, Info, error) {
	req := Request{Op: OpEmbed, Texts: texts}
	if err := req.Check(); err != nil {
		return nil, Info{}, err
	}
	r, err := c.call(ctx, req)
	if err != nil {
		return nil, Info{}, err
	}
	if r.Model != "" || r.State != "" {
		return nil, Info{}, unavailable("embed reply has hello fields")
	}
	in, err := info(r)
	if err != nil {
		return nil, Info{}, err
	}
	if len(r.Vectors) != len(texts) {
		return nil, Info{}, unavailable("wrong vector count")
	}
	for _, v := range r.Vectors {
		if len(v) != in.Dim {
			return nil, Info{}, unavailable("vector length differs from dim")
		}
		if !Finite(v) {
			return nil, Info{}, unavailable("non-finite value")
		}
	}
	return r.Vectors, in, nil
}

// info checks a reply's model fields.
func info(r Reply) (Info, error) {
	if !ValidHash(r.SHA256) {
		return Info{}, unavailable("bad sha256")
	}
	if r.Dim <= 0 || r.Dim > MaxDim {
		return Info{}, unavailable("bad dim")
	}
	return Info{Model: clean(r.Model), SHA256: r.SHA256, Dim: r.Dim}, nil
}

// call sends one request and returns the reply, an error reply as its
// *Error, and anything else that goes wrong as Unavailable.
func (c Client) call(ctx context.Context, req Request) (Reply, error) {
	d := c.Timeout
	if d <= 0 {
		d = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	b, err := json.Marshal(req)
	if err != nil || len(b) > MaxRequestLine {
		return Reply{}, &Error{Cause: BadRequest, Detail: "request line over its bound"}
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
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return Reply{}, unavailable("write failed")
	}
	line, err := ReadLine(bufio.NewReaderSize(conn, 64<<10), MaxReplyLine)
	if err != nil {
		if ctx.Err() != nil {
			return Reply{}, unavailable("deadline")
		}
		if err == ErrLineTooLong {
			return Reply{}, unavailable("reply line over its bound")
		}
		return Reply{}, unavailable("no complete reply")
	}
	var r Reply
	if err := json.Unmarshal(line, &r); err != nil {
		return Reply{}, unavailable("malformed reply")
	}
	if r.Error != "" {
		if !r.Error.Known() || r.Vectors != nil || r.SHA256 != "" {
			return Reply{}, unavailable("malformed error reply")
		}
		return Reply{}, &Error{Cause: r.Error, Detail: clean(r.Detail)}
	}
	if r.Detail != "" {
		return Reply{}, unavailable("detail without an error")
	}
	return r, nil
}
