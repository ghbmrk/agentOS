package retrieve

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"unicode/utf8"
)

// Chunk splits text into at most MaxChunks chunks of at most MaxChunk
// bytes, cutting at the last paragraph break in reach, else the last
// sentence end, else the last UTF-8 boundary. Invalid UTF-8 is replaced
// first, so no chunk splits a sequence. Blank chunks are dropped, and the
// bytes past the last chunk are returned as the overflow.
func Chunk(text string) (chunks []string, overflow int) {
	rest := strings.ToValidUTF8(text, "�")
	for rest != "" {
		if len(chunks) == MaxChunks {
			return chunks, len(rest)
		}
		n := len(rest)
		if n > MaxChunk {
			n = cut(rest[:MaxChunk+1])
		}
		if c := rest[:n]; strings.TrimSpace(c) != "" {
			chunks = append(chunks, c)
		}
		rest = rest[n:]
	}
	return chunks, 0
}

// cut returns where to end a chunk of w, which is MaxChunk+1 bytes, so
// that the chunk is at most MaxChunk bytes.
func cut(w string) int {
	w0 := w[:MaxChunk]
	if i := strings.LastIndex(w0, "\n\n"); i > 0 {
		return i + 2
	}
	best := -1
	for _, end := range []string{". ", "! ", "? ", ".\n", "!\n", "?\n", "\n"} {
		if i := strings.LastIndex(w0, end); i >= 0 && i+len(end) > best {
			best = i + len(end)
		}
	}
	if best > 0 {
		return best
	}
	n := MaxChunk
	for n > 0 && !utf8.RuneStart(w[n]) {
		n--
	}
	return n
}

// qvec is one stored vector: Dim int8 values and the float32 scale that
// maps them back.
type qvec struct {
	scale float32
	vec   []int8
}

// quantise truncates v to Dim, renormalises it to unit length and
// quantises it to int8 with one scale. It refuses a vector with a value
// that is not finite, or with no length in its first Dim values.
func quantise(v []float32) (qvec, bool) {
	if len(v) < Dim {
		return qvec{}, false
	}
	var ss float64
	for _, x := range v {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			return qvec{}, false
		}
	}
	for _, x := range v[:Dim] {
		ss += float64(x) * float64(x)
	}
	norm := math.Sqrt(ss)
	if norm == 0 || math.IsInf(norm, 0) {
		return qvec{}, false
	}
	var maxAbs float64
	for _, x := range v[:Dim] {
		maxAbs = max(maxAbs, math.Abs(float64(x)/norm))
	}
	scale := maxAbs / 127
	q := qvec{scale: float32(scale), vec: make([]int8, Dim)}
	for i, x := range v[:Dim] {
		q.vec[i] = int8(math.Round(float64(x) / norm / scale))
	}
	return q, true
}

func dot(a, b []int8) int32 {
	var s int32
	for i := range a {
		s += int32(a[i]) * int32(b[i])
	}
	return s
}

// A vector item's bytes (all integers little-endian):
//
//	magic "RETV", version 1
//	model SHA-256 (32 bytes), source item hash (32 bytes)
//	dim uint16, chunks uint16, overflow uint32 (bytes never indexed)
//	chunks × (scale float32 bits, dim × int8)
const (
	magic      = "RETV"
	version    = 1
	headerSize = 4 + 1 + 32 + 32 + 2 + 2 + 4
)

var errFormat = errors.New("retrieve: malformed vector item")

type record struct {
	model    string // hex SHA-256
	source   Hash
	dim      int
	overflow uint32
	vecs     []qvec
}

func encode(r record) []byte {
	b := make([]byte, 0, headerSize+len(r.vecs)*(4+r.dim))
	b = append(b, magic...)
	b = append(b, version)
	m, _ := hex.DecodeString(r.model)
	b = append(b, m...)
	b = append(b, r.source[:]...)
	b = binary.LittleEndian.AppendUint16(b, uint16(r.dim))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(r.vecs)))
	b = binary.LittleEndian.AppendUint32(b, r.overflow)
	for _, v := range r.vecs {
		b = binary.LittleEndian.AppendUint32(b, math.Float32bits(v.scale))
		for _, x := range v.vec {
			b = append(b, byte(x))
		}
	}
	return b
}

// decode parses a vector item, refusing anything that is not exactly one:
// another magic or version, a dim outside 1..PinnedDim, more than
// MaxChunks chunks, a length that differs from what the header says, or
// a scale that is not finite and positive.
func decode(b []byte) (record, error) {
	if len(b) < headerSize || string(b[:4]) != magic || b[4] != version {
		return record{}, errFormat
	}
	var r record
	r.model = hex.EncodeToString(b[5:37])
	copy(r.source[:], b[37:69])
	r.dim = int(binary.LittleEndian.Uint16(b[69:71]))
	n := int(binary.LittleEndian.Uint16(b[71:73]))
	r.overflow = binary.LittleEndian.Uint32(b[73:77])
	if r.dim < 1 || r.dim > PinnedDim || n > MaxChunks || len(b) != headerSize+n*(4+r.dim) {
		return record{}, errFormat
	}
	p := b[headerSize:]
	for range n {
		s := math.Float32frombits(binary.LittleEndian.Uint32(p))
		if !(s > 0) || math.IsInf(float64(s), 0) {
			return record{}, errFormat
		}
		v := make([]int8, r.dim)
		for i := range v {
			v[i] = int8(p[4+i])
		}
		r.vecs = append(r.vecs, qvec{scale: s, vec: v})
		p = p[4+r.dim:]
	}
	return r, nil
}
