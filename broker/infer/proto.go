// Package infer is the client side of the local inference service
// (INFER-SVC): the wire types, their bounds and error causes, and the
// client that dials the service's unix socket. The service is untrusted
// (SPEC §4): every reply is checked before a vector or text leaves this
// package, and anything malformed is Unavailable, never data (INF-2).
//
// The package imports the standard library only and starts nothing; the
// service process is started by infer/supervise (ARC-2, INF-5).
package infer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Bounds both sides enforce (INF-2).
const (
	MaxTexts       = 64      // texts in one embed request
	MaxText        = 8 << 10 // bytes in one text
	MaxRequestLine = 1 << 20 // bytes in one request line, without its newline
	MaxReplyLine   = 4 << 20 // bytes in one reply line, without its newline
	// MaxDim bounds a reply's dim, so a reply cannot declare a size the
	// line bound would not hold anyway.
	MaxDim = 8192
	// maxDetail bounds the error detail kept from a reply.
	maxDetail = 200
	// DefaultTimeout is a call's deadline when Client.Timeout is zero.
	DefaultTimeout = 2 * time.Second

	// Generate's bounds (PLN-7 local route, INFER-SVC G1).
	MaxPrompt   = 32 << 10 // bytes in one prompt
	MaxOut      = 1024     // most tokens a generate request may ask for
	MaxGenerate = 16 << 10 // bytes in one generate reply's text
	// DefaultGenerateTimeout is a generate call's deadline when
	// Client.GenerateTimeout is zero.
	DefaultGenerateTimeout = 120 * time.Second
)

// Ops a request names.
const (
	OpHello    = "hello"
	OpEmbed    = "embed"
	OpGenerate = "generate"
)

// StateReady is the only state a hello reply may carry.
const StateReady = "ready"

// Cause is why a call returned no vectors.
type Cause string

// The four causes (INF-4). Missing and Corrupt are about the model file;
// Unavailable is the service or its runtime not answering, or answering
// something malformed; BadRequest is a request outside the bounds.
const (
	Missing     Cause = "missing"
	Corrupt     Cause = "corrupt"
	Unavailable Cause = "unavailable"
	BadRequest  Cause = "bad_request"
)

// Known reports one of the four causes.
func (c Cause) Known() bool {
	switch c {
	case Missing, Corrupt, Unavailable, BadRequest:
		return true
	}
	return false
}

// Request is one request line.
type Request struct {
	Op     string   `json:"op"`
	Texts  []string `json:"texts,omitempty"`
	Prompt string   `json:"prompt,omitempty"`
	MaxOut int      `json:"max_out,omitempty"`
}

// Check enforces the request bounds; the error is a BadRequest *Error that
// names the bound, never the text.
func (r Request) Check() error {
	switch r.Op {
	case OpHello:
		if r.Texts != nil || r.Prompt != "" || r.MaxOut != 0 {
			return &Error{Cause: BadRequest, Detail: "hello takes no arguments"}
		}
		return nil
	case OpGenerate:
		return r.checkGenerate()
	case OpEmbed:
		if r.Prompt != "" || r.MaxOut != 0 {
			return &Error{Cause: BadRequest, Detail: "embed takes texts only"}
		}
	default:
		return &Error{Cause: BadRequest, Detail: "unknown op"}
	}
	if len(r.Texts) == 0 || len(r.Texts) > MaxTexts {
		return &Error{Cause: BadRequest, Detail: fmt.Sprintf("%d texts, want 1 to %d", len(r.Texts), MaxTexts)}
	}
	for i, t := range r.Texts {
		if len(t) > MaxText {
			return &Error{Cause: BadRequest, Detail: fmt.Sprintf("text %d is %d bytes, over %d", i, len(t), MaxText)}
		}
	}
	return nil
}

func (r Request) checkGenerate() error {
	if r.Texts != nil {
		return &Error{Cause: BadRequest, Detail: "generate takes a prompt, not texts"}
	}
	if r.Prompt == "" || len(r.Prompt) > MaxPrompt {
		return &Error{Cause: BadRequest, Detail: fmt.Sprintf("prompt is %d bytes, want 1 to %d", len(r.Prompt), MaxPrompt)}
	}
	if r.MaxOut < 1 || r.MaxOut > MaxOut {
		return &Error{Cause: BadRequest, Detail: fmt.Sprintf("max_out %d, want 1 to %d", r.MaxOut, MaxOut)}
	}
	return nil
}

// Reply is one reply line. Which fields are set says which reply it is:
// hello (Model, SHA256, Dim, State, Ops), embed (SHA256, Dim, Vectors),
// generate (SHA256, Text) or an error (Error, Detail). Text is a pointer so
// that an empty generation is told apart from a reply that has none.
type Reply struct {
	Model   string      `json:"model,omitempty"`
	SHA256  string      `json:"sha256,omitempty"`
	Dim     int         `json:"dim,omitempty"`
	State   string      `json:"state,omitempty"`
	Ops     []string    `json:"ops,omitempty"`
	Vectors [][]float32 `json:"vectors,omitempty"`
	Text    *string     `json:"text,omitempty"`
	Error   Cause       `json:"error,omitempty"`
	Detail  string      `json:"detail,omitempty"`
}

// Info is what the service says about its model: its name, the SHA-256 of
// the file it loaded, the length of every vector (0 when the model serves
// no embed op) and whether it serves generate.
type Info struct {
	Model    string
	SHA256   string
	Dim      int
	Generate bool
}

// Ops is the ops list a hello reply carries for in.
func (in Info) Ops() []string {
	var ops []string
	if in.Dim > 0 {
		ops = append(ops, OpEmbed)
	}
	if in.Generate {
		ops = append(ops, OpGenerate)
	}
	return ops
}

// ValidText reports a generate reply's text as valid UTF-8 within
// MaxGenerate bytes.
func ValidText(s string) bool { return len(s) <= MaxGenerate && utf8.ValidString(s) }

// Error is a call's failure, with one of the four causes.
type Error struct {
	Cause  Cause
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "infer: " + string(e.Cause)
	}
	return "infer: " + string(e.Cause) + ": " + e.Detail
}

// CauseOf is err's cause: an *Error's own, else Unavailable.
func CauseOf(err error) Cause {
	var e *Error
	if errors.As(err, &e) && e.Cause.Known() {
		return e.Cause
	}
	return Unavailable
}

func unavailable(detail string) error { return &Error{Cause: Unavailable, Detail: detail} }

// ValidHash reports a SHA-256 as 64 lower-case hex digits.
func ValidHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// Finite reports a vector with no NaN or infinity.
func Finite(v []float32) bool {
	for _, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return false
		}
	}
	return true
}

// ErrLineTooLong is ReadLine's answer to a line over its bound.
var ErrLineTooLong = errors.New("infer: line over its bound")

// ReadLine reads one line of at most max bytes, without its newline. A
// longer line is ErrLineTooLong as soon as more than max bytes are read, so
// a peer cannot make the reader hold more than the bound and one buffer; a
// line with no newline before EOF is io.ErrUnexpectedEOF (io.EOF if nothing
// was read).
func ReadLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		frag, err := r.ReadSlice('\n')
		line = append(line, frag...)
		if err == nil {
			line = line[:len(line)-1]
			if len(line) > max {
				return nil, ErrLineTooLong
			}
			return line, nil
		}
		switch {
		case len(line) > max:
			return nil, ErrLineTooLong
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err == io.EOF && len(line) > 0:
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
}

// clean keeps a reply's detail short and printable: it is the untrusted
// service's text, and may reach a log.
func clean(s string) string {
	if len(s) > maxDetail {
		s = s[:maxDetail]
	}
	return strings.Map(func(r rune) rune {
		if r == unicode.ReplacementChar || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, s)
}
