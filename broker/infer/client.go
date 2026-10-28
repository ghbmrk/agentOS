package infer

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"time"
	"unicode/utf8"
)

// Client is the caller's side of the inference service's socket. Each call
// dials the socket, writes its request lines and reads one reply line to
// each, within Timeout (GenerateTimeout for Generate).
type Client struct {
	// Path is the service's socket.
	Path string
	// Timeout bounds each hello or embed call; zero is DefaultTimeout.
	Timeout time.Duration
	// GenerateTimeout bounds each Generate call; zero is
	// DefaultGenerateTimeout.
	GenerateTimeout time.Duration
}

// Hello asks the service for its model. A service that is up but has no
// usable model answers Missing or Corrupt.
func (c Client) Hello(ctx context.Context) (Info, error) {
	r, err := c.call(ctx, Request{Op: OpHello})
	if err != nil {
		return Info{}, err
	}
	return helloInfo(r)
}

// Generate returns the loaded model's text for prompt, at most maxOut
// tokens of it, and the model it came from. It asks hello first on the
// same connection and sends the prompt only to a model that serves
// generate (else Missing); the reply must name the model hello named. On
// any error it returns no text, and the error's cause (CauseOf) is one of
// the four.
func (c Client) Generate(ctx context.Context, prompt string, maxOut int) (string, Info, error) {
	req := Request{Op: OpGenerate, Prompt: prompt, MaxOut: maxOut}
	if err := req.Check(); err != nil {
		return "", Info{}, err
	}
	d := c.GenerateTimeout
	if d <= 0 {
		d = DefaultGenerateTimeout
	}
	k, done, err := c.dial(ctx, d)
	if err != nil {
		return "", Info{}, err
	}
	defer done()
	r, err := k.roundTrip(Request{Op: OpHello})
	if err != nil {
		return "", Info{}, err
	}
	in, err := helloInfo(r)
	if err != nil {
		return "", Info{}, err
	}
	if !in.Generate {
		return "", Info{}, &Error{Cause: Missing, Detail: "the model does not serve generate"}
	}
	if r, err = k.roundTrip(req); err != nil {
		return "", Info{}, err
	}
	if r.Model != "" || r.State != "" || r.Ops != nil || r.Dim != 0 || r.Vectors != nil {
		return "", Info{}, unavailable("generate reply has other fields")
	}
	if r.SHA256 != in.SHA256 {
		return "", Info{}, unavailable("generate reply names another model")
	}
	if r.Text == nil || !ValidText(*r.Text) {
		return "", Info{}, unavailable("generate reply has no valid text")
	}
	return *r.Text, in, nil
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
	if r.Model != "" || r.State != "" || r.Ops != nil || r.Text != nil {
		return nil, Info{}, unavailable("embed reply has other fields")
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

// helloInfo checks a hello reply: ready, a known and non-empty ops list
// with no repeats, and a dim exactly when embed is served.
func helloInfo(r Reply) (Info, error) {
	if r.State != StateReady || r.Vectors != nil || r.Text != nil {
		return Info{}, unavailable("hello reply is not ready")
	}
	if !ValidHash(r.SHA256) {
		return Info{}, unavailable("bad sha256")
	}
	in := Info{Model: clean(r.Model), SHA256: r.SHA256}
	seen := map[string]bool{}
	for _, op := range r.Ops {
		if seen[op] || op != OpEmbed && op != OpGenerate {
			return Info{}, unavailable("bad ops")
		}
		seen[op] = true
	}
	switch {
	case len(seen) == 0:
		return Info{}, unavailable("bad ops")
	case seen[OpEmbed] && (r.Dim <= 0 || r.Dim > MaxDim), !seen[OpEmbed] && r.Dim != 0:
		return Info{}, unavailable("bad dim")
	}
	in.Dim, in.Generate = r.Dim, seen[OpGenerate]
	return in, nil
}

// info checks an embed reply's model fields.
func info(r Reply) (Info, error) {
	if !ValidHash(r.SHA256) {
		return Info{}, unavailable("bad sha256")
	}
	if r.Dim <= 0 || r.Dim > MaxDim {
		return Info{}, unavailable("bad dim")
	}
	return Info{Model: clean(r.Model), SHA256: r.SHA256, Dim: r.Dim}, nil
}

// call sends one request on its own connection and returns the reply.
func (c Client) call(ctx context.Context, req Request) (Reply, error) {
	d := c.Timeout
	if d <= 0 {
		d = DefaultTimeout
	}
	k, done, err := c.dial(ctx, d)
	if err != nil {
		return Reply{}, err
	}
	defer done()
	return k.roundTrip(req)
}

// conn is one connection to the service, bounded by its context.
type conn struct {
	ctx context.Context
	c   net.Conn
	r   *bufio.Reader
}

// dial connects within d; done closes the connection and releases the
// deadline.
func (c Client) dial(ctx context.Context, d time.Duration) (*conn, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	nc, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Path)
	if err != nil {
		cancel()
		return nil, nil, unavailable("service not reachable")
	}
	// The context's end closes the call however far it got.
	stop := context.AfterFunc(ctx, func() { nc.Close() })
	if dl, ok := ctx.Deadline(); ok {
		nc.SetDeadline(dl)
	}
	done := func() {
		stop()
		nc.Close()
		cancel()
	}
	return &conn{ctx: ctx, c: nc, r: bufio.NewReaderSize(nc, 64<<10)}, done, nil
}

// roundTrip sends one request and returns the reply, an error reply as its
// *Error, and anything else that goes wrong as Unavailable.
func (k *conn) roundTrip(req Request) (Reply, error) {
	b, err := json.Marshal(req)
	if err != nil || len(b) > MaxRequestLine {
		return Reply{}, &Error{Cause: BadRequest, Detail: "request line over its bound"}
	}
	if _, err := k.c.Write(append(b, '\n')); err != nil {
		return Reply{}, unavailable("write failed")
	}
	line, err := ReadLine(k.r, MaxReplyLine)
	if err != nil {
		if k.ctx.Err() != nil {
			return Reply{}, unavailable("deadline")
		}
		if err == ErrLineTooLong {
			return Reply{}, unavailable("reply line over its bound")
		}
		return Reply{}, unavailable("no complete reply")
	}
	// json.Unmarshal would turn invalid UTF-8 into U+FFFD silently.
	if !utf8.Valid(line) {
		return Reply{}, unavailable("reply is not UTF-8")
	}
	var r Reply
	if err := json.Unmarshal(line, &r); err != nil {
		return Reply{}, unavailable("malformed reply")
	}
	if r.Error != "" {
		if !r.Error.Known() || r.Vectors != nil || r.SHA256 != "" || r.Text != nil {
			return Reply{}, unavailable("malformed error reply")
		}
		return Reply{}, &Error{Cause: r.Error, Detail: clean(r.Detail)}
	}
	if r.Detail != "" {
		return Reply{}, unavailable("detail without an error")
	}
	return r, nil
}
