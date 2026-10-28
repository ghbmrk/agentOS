// Package vision is agentosd's side of the camera vision service
// (VIS-core): the wire types, their bounds and closed vocabularies, and the
// client that dials the service's unix socket. The service is untrusted
// (SPEC §4) and sees raw capture and, from part (c), enrolled templates, so
// every reply is checked field by field before anything leaves this
// package: a class from a fixed list, integer boxes inside the frame, a
// confidence in whole percent, a face that is unknown or an id the client
// itself knows, plate text from a fixed alphabet, and sound labels from a
// fixed list. A reply with anything else, an unknown field among them, is
// Unavailable, never data, so a compromised service has no field to carry
// an encoding out in (DEV-7).
//
// The package imports the standard library only and starts nothing; the
// service process is started by vision/supervise (ARC-2, KRN-3).
package vision

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// Bounds both sides enforce.
const (
	MaxWidth  = 3840 // pixels across one frame
	MaxHeight = 2160 // pixels down one frame
	// MaxAudioBytes is ten seconds of AudioPCM16k.
	MaxAudioBytes = 10 * 16000 * 2
	// MaxDetections bounds one detect reply.
	MaxDetections = 64
	// MaxSounds bounds one sound reply: each label at most once.
	MaxSounds = 8
	// MaxHeaderLine bounds a request's header line, without its newline.
	MaxHeaderLine = 1 << 10
	// MaxReplyLine bounds a reply line, without its newline: MaxDetections
	// detections at their longest fit well inside it.
	MaxReplyLine = 32 << 10
	// MaxPlate bounds plate text.
	MaxPlate = 10
	// MaxEnrolledID bounds the id in "enrolled:<id>".
	MaxEnrolledID = 32
	// DefaultTimeout is a call's deadline when Client.Timeout is zero.
	DefaultTimeout = 5 * time.Second
	// MaxTemplate bounds one enrolled template: little-endian float32s,
	// at most 1024 of them.
	MaxTemplate = 4 << 10
	// MaxEnrolled bounds the templates one lend carries.
	MaxEnrolled = 32
	// MaxLend bounds a lend's payload: MaxEnrolled templates at their
	// longest, each with its id and lengths.
	MaxLend = MaxEnrolled * (1 + MaxEnrolledID + 2 + MaxTemplate)
)

// Ops a request names. Hello, detect and sound are the feed's, on the
// service's socket; enrol and lend are the control ops (part c), served on
// the control socket only, which only the trusted side holding the template
// slots reaches (vision/faces).
const (
	OpHello  = "hello"
	OpDetect = "detect"
	OpSound  = "sound"
	// OpEnrol asks for the template of the one face in an enrolment
	// frame: the only op whose reply carries an encoding, and only of a
	// person the owner is enrolling at the tier-4 step.
	OpEnrol = "enrol"
	// OpLend replaces every template the service holds with the ones its
	// payload carries (EncodeLend); an empty payload holds none.
	OpLend = "lend"
)

// Control reports an op served on the control socket only.
func Control(op string) bool { return op == OpEnrol || op == OpLend }

// Frame formats: decoded pixels, row-major, no padding. Y16 is a thermal
// frame's 16-bit little-endian counts.
const (
	FormatRGB24 = "rgb24"
	FormatGray8 = "gray8"
	FormatY16   = "y16"
)

// AudioPCM16k is 16-bit little-endian mono samples at 16 kHz.
const AudioPCM16k = "pcm16k"

// bytesPerPixel holds every frame format.
var bytesPerPixel = map[string]int{FormatRGB24: 3, FormatGray8: 1, FormatY16: 2}

// StateReady is the only state a hello reply may carry.
const StateReady = "ready"

// DeviceCPU is the only device this build may report: the service runs on
// CPU when no accelerator is leased (RES-3); an accelerator lease adds its
// own value (brief, budget R8).
const DeviceCPU = "cpu"

// Class is a detection's class, from a fixed list.
type Class string

// The classes. There is no free-text class, caption or attribute.
const (
	Person        Class = "person"
	Vehicle       Class = "vehicle"
	Dog           Class = "dog"
	Cat           Class = "cat"
	Bird          Class = "bird"
	Deer          Class = "deer"
	Fox           Class = "fox"
	Coyote        Class = "coyote"
	Bear          Class = "bear"
	UnknownAnimal Class = "unknown-animal"
	// Drone is an aircraft: the household's own drone, whose camera
	// fixes the GPS cross-check weighs (part b, VIS-A24). It is never
	// fused, zoned or counted.
	Drone Class = "drone"
	// Warm is a body warmer than its surroundings on a thermal frame,
	// kind unknown: the thermal stream finds heat, and the visible
	// stream and the drone say what it is (part e, VIS-A29).
	Warm Class = "warm"
)

// classes is the whole list, in order; unexported, so no caller can widen
// it.
var classes = []Class{Person, Vehicle, Dog, Cat, Bird, Deer, Fox, Coyote, Bear, UnknownAnimal, Drone, Warm}

// Classes returns the fixed list of classes.
func Classes() []Class { return append([]Class(nil), classes...) }

// Known reports a class on the list.
func (c Class) Known() bool {
	for _, k := range classes {
		if c == k {
			return true
		}
	}
	return false
}

// soundLabels is the fixed list of sound events, MaxSounds long.
var soundLabels = []string{"alarm", "glass-break", "gunshot", "scream", "dog-bark", "vehicle", "knock", "doorbell"}

// SoundLabels returns the fixed list of sound event labels.
func SoundLabels() []string { return append([]string(nil), soundLabels...) }

// KnownSound reports a label on the list.
func KnownSound(l string) bool {
	for _, k := range soundLabels {
		if l == k {
			return true
		}
	}
	return false
}

// A person detection's face, when one was seen: unknown, or an enrolled
// person's id. A face is compared inside the service only (DEV-7); no
// encoding is ever on the wire.
const (
	FaceUnknown    = "unknown"
	FaceEnrolledAs = "enrolled:"
)

// Box is a detection's box in pixels: X0 <= x < X1, Y0 <= y < Y1, inside
// the frame. Integers only, so a box carries no fraction to hide bits in.
type Box struct {
	X0 int `json:"x0"`
	Y0 int `json:"y0"`
	X1 int `json:"x1"`
	Y1 int `json:"y1"`
}

// Detection is one thing the service saw. Conf is the confidence in whole
// percent, 1 to 100: the brief's two-decimal quantisation, held exactly by
// an integer. Face is set only on a person, Plate only on a vehicle. There
// is no track id: tracking runs in the client (part b), so the service
// cannot number detections to carry bits.
type Detection struct {
	Class Class  `json:"class"`
	Box   Box    `json:"box"`
	Conf  int    `json:"conf"`
	Face  string `json:"face,omitempty"`
	Plate string `json:"plate,omitempty"`
}

// Enrolled returns the enrolled person's id when the face was recognised.
func (d Detection) Enrolled() (string, bool) {
	return strings.CutPrefix(d.Face, FaceEnrolledAs)
}

// QuotedPlate is the plate text as an event carries it: quoted, as
// device-supplied text (DEV-8). Empty when there is no plate.
func (d Detection) QuotedPlate() string {
	if d.Plate == "" {
		return ""
	}
	return strconv.Quote(d.Plate)
}

// Sound is one sound event heard in an audio clip.
type Sound struct {
	Label string `json:"label"`
	Conf  int    `json:"conf"`
}

// Frame is one decoded frame for a detect request.
type Frame struct {
	Format        string
	Width, Height int
	Data          []byte
}

// Info is what the service says about itself: the models' name and the
// SHA-256 of what it loaded, and the device it runs on.
type Info struct {
	Model  string
	SHA256 string
	Device string
}

// Request is a request's header line. A detect or sound header is followed
// by exactly Bytes bytes of frame or audio, so no payload is base64 on a
// JSON line.
type Request struct {
	Op     string `json:"op"`
	Format string `json:"format,omitempty"`
	Width  int    `json:"width,omitempty"`
	Height int    `json:"height,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
}

// Check enforces the request bounds; the error is a BadRequest *Error.
func (r Request) Check() error {
	switch r.Op {
	case OpHello:
		if r != (Request{Op: OpHello}) {
			return badRequest("hello takes no fields")
		}
		return nil
	case OpDetect:
		bpp, ok := bytesPerPixel[r.Format]
		if !ok {
			return badRequest("unknown frame format")
		}
		if r.Width < 1 || r.Width > MaxWidth || r.Height < 1 || r.Height > MaxHeight {
			return badRequest(fmt.Sprintf("frame %dx%d outside 1x1 to %dx%d", r.Width, r.Height, MaxWidth, MaxHeight))
		}
		if r.Bytes != r.Width*r.Height*bpp {
			return badRequest("frame bytes differ from its size")
		}
		return nil
	case OpEnrol:
		// An enrolment frame is bounded as a detect frame.
		return Request{Op: OpDetect, Format: r.Format, Width: r.Width, Height: r.Height, Bytes: r.Bytes}.Check()
	case OpLend:
		if r.Format != "" || r.Width != 0 || r.Height != 0 || r.Bytes < 0 || r.Bytes > MaxLend {
			return badRequest(fmt.Sprintf("lend of %d bytes, want 0 to %d and no frame fields", r.Bytes, MaxLend))
		}
		return nil
	case OpSound:
		if r.Format != AudioPCM16k || r.Width != 0 || r.Height != 0 {
			return badRequest("unknown audio format")
		}
		if r.Bytes < 2 || r.Bytes > MaxAudioBytes || r.Bytes%2 != 0 {
			return badRequest(fmt.Sprintf("audio of %d bytes, want an even 2 to %d", r.Bytes, MaxAudioBytes))
		}
		return nil
	}
	return badRequest("unknown op")
}

// Reply is one reply line. Which fields may be set depends on the op:
// hello (State, Device, Model, SHA256), detect (Detections), sound
// (Sounds), enrol (Template), lend (State alone), or an error (Error
// alone). An error reply has no detail: the service's own text is a
// channel this package does not open.
type Reply struct {
	State      string      `json:"state,omitempty"`
	Device     string      `json:"device,omitempty"`
	Model      string      `json:"model,omitempty"`
	SHA256     string      `json:"sha256,omitempty"`
	Detections []Detection `json:"detections,omitempty"`
	Sounds     []Sound     `json:"sounds,omitempty"`
	Template   []byte      `json:"template,omitempty"`
	Error      Cause       `json:"error,omitempty"`
}

// Cause is why a call returned nothing.
type Cause string

// The causes: INFER-SVC's four, and NoFace. Missing and Corrupt are about
// the models; Unavailable is the service not answering, or answering
// something malformed; BadRequest is a request outside the bounds; NoFace
// is an enrolment frame without exactly one clear face.
const (
	Missing     Cause = "missing"
	Corrupt     Cause = "corrupt"
	Unavailable Cause = "unavailable"
	BadRequest  Cause = "bad_request"
	NoFace      Cause = "no_face"
)

// Known reports one of the causes.
func (c Cause) Known() bool {
	switch c {
	case Missing, Corrupt, Unavailable, BadRequest, NoFace:
		return true
	}
	return false
}

// Error is a call's failure. Detail is this package's own fixed text,
// never the service's.
type Error struct {
	Cause  Cause
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return "vision: " + string(e.Cause)
	}
	return "vision: " + string(e.Cause) + ": " + e.Detail
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
func badRequest(detail string) error  { return &Error{Cause: BadRequest, Detail: detail} }

// CheckDetections checks a detect reply's detections against a frame of
// w by h pixels; enrolled says whether an id is one the checker itself
// holds (nil: none is). The service checks its runtime's answer with it
// too, so a runtime is not trusted to keep the shape.
func CheckDetections(ds []Detection, w, h int, enrolled func(string) bool) error {
	if len(ds) > MaxDetections {
		return unavailable("too many detections")
	}
	for _, d := range ds {
		if !d.Class.Known() {
			return unavailable("class not on the list")
		}
		b := d.Box
		if b.X0 < 0 || b.Y0 < 0 || b.X1 > w || b.Y1 > h || b.X0 >= b.X1 || b.Y0 >= b.Y1 {
			return unavailable("box outside the frame")
		}
		if d.Conf < 1 || d.Conf > 100 {
			return unavailable("confidence outside 1 to 100")
		}
		if d.Face != "" {
			if d.Class != Person {
				return unavailable("face on a non-person")
			}
			if d.Face != FaceUnknown {
				id, ok := d.Enrolled()
				if !ok || !ValidEnrolledID(id) || enrolled == nil || !enrolled(id) {
					return unavailable("face names no enrolled id")
				}
			}
		}
		if d.Plate != "" {
			if d.Class != Vehicle {
				return unavailable("plate on a non-vehicle")
			}
			if !ValidPlate(d.Plate) {
				return unavailable("plate text outside its alphabet")
			}
		}
	}
	return nil
}

// CheckSounds checks a sound reply's labels: each from the list, at most
// once, with a confidence in whole percent.
func CheckSounds(ss []Sound) error {
	if len(ss) > MaxSounds {
		return unavailable("too many sounds")
	}
	seen := map[string]bool{}
	for _, s := range ss {
		if !KnownSound(s.Label) || seen[s.Label] {
			return unavailable("sound label not on the list, or repeated")
		}
		seen[s.Label] = true
		if s.Conf < 1 || s.Conf > 100 {
			return unavailable("confidence outside 1 to 100")
		}
	}
	return nil
}

// CheckTemplate checks an enrolled template: 1 to MaxTemplate/4
// little-endian float32s, each finite, not all zero.
func CheckTemplate(t []byte) error {
	if len(t) < 4 || len(t) > MaxTemplate || len(t)%4 != 0 {
		return unavailable("template outside its bounds")
	}
	zero := true
	for i := 0; i < len(t); i += 4 {
		f := math.Float32frombits(binary.LittleEndian.Uint32(t[i:]))
		if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
			return unavailable("template not finite")
		}
		zero = zero && f == 0
	}
	if zero {
		return unavailable("template all zero")
	}
	return nil
}

// Template is one enrolled person's template as a lend carries it: the id
// a recognised face is named by, and its little-endian float32s.
type Template struct {
	ID  string
	Vec []byte
}

// EncodeLend is a lend's payload: for each template, its id's length (one
// byte), the id, its vector's length (two bytes, big-endian) and the
// vector. No JSON, so nothing holds the vector as text the sender cannot
// zero.
func EncodeLend(ts []Template) ([]byte, error) {
	if len(ts) > MaxEnrolled {
		return nil, badRequest("too many templates")
	}
	n := 0
	for _, t := range ts {
		n += 3 + len(t.ID) + len(t.Vec)
	}
	b := make([]byte, 0, n)
	seen := map[string]bool{}
	for _, t := range ts {
		if !ValidEnrolledID(t.ID) || seen[t.ID] || CheckTemplate(t.Vec) != nil {
			clear(b[:cap(b)])
			return nil, badRequest("template outside its bounds")
		}
		seen[t.ID] = true
		b = append(b, byte(len(t.ID)))
		b = append(b, t.ID...)
		b = binary.BigEndian.AppendUint16(b, uint16(len(t.Vec)))
		b = append(b, t.Vec...)
	}
	return b, nil
}

// DecodeLend reads EncodeLend's payload. The vectors are slices of b, so
// zeroing b zeroes them.
func DecodeLend(b []byte) ([]Template, error) {
	var ts []Template
	seen := map[string]bool{}
	for len(b) > 0 {
		if len(ts) == MaxEnrolled {
			return nil, badRequest("too many templates")
		}
		n := int(b[0])
		if len(b) < 1+n+2 {
			return nil, badRequest("lend cut short")
		}
		id := string(b[1 : 1+n])
		m := int(binary.BigEndian.Uint16(b[1+n:]))
		b = b[3+n:]
		if len(b) < m {
			return nil, badRequest("lend cut short")
		}
		if !ValidEnrolledID(id) || seen[id] || CheckTemplate(b[:m]) != nil {
			return nil, badRequest("template outside its bounds")
		}
		seen[id] = true
		ts = append(ts, Template{ID: id, Vec: b[:m:m]})
		b = b[m:]
	}
	return ts, nil
}

// ValidPlate reports plate text of 1 to MaxPlate characters from
// [A-Z0-9 -], with no space at either end.
func ValidPlate(p string) bool {
	if len(p) < 1 || len(p) > MaxPlate || p[0] == ' ' || p[len(p)-1] == ' ' {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !('A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == ' ' || c == '-') {
			return false
		}
	}
	return true
}

// ValidEnrolledID reports an enrolment id of 1 to MaxEnrolledID
// characters from [a-z0-9-].
func ValidEnrolledID(id string) bool {
	if len(id) < 1 || len(id) > MaxEnrolledID {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

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

// ValidModelName reports a model name of 1 to 64 characters from
// [a-z0-9._-]: a hello reply's one name, and no free text.
func ValidModelName(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ErrLineTooLong is ReadLine's answer to a line over its bound.
var ErrLineTooLong = errors.New("vision: line over its bound")

// ReadLine reads one line of at most max bytes, without its newline. A
// longer line is ErrLineTooLong as soon as more than max bytes are read; a
// line with no newline before EOF is io.ErrUnexpectedEOF (io.EOF if
// nothing was read). As infer.ReadLine, kept here so this package links
// the standard library only.
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
