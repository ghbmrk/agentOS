package wire

// REQ: UPD-5

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestFramesRoundTrip(t *testing.T) {
	var b bytes.Buffer
	for _, f := range []struct {
		k byte
		b string
	}{{Case, "in"}, {Answer, ""}, {ModelCall, "q"}} {
		if err := Write(&b, f.k, []byte(f.b)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"Cin", "A", "Mq"} {
		k, body, err := Read(&b, 8)
		if err != nil || string(k)+string(body) != want {
			t.Fatalf("Read = %q %q, %v; want %q", k, body, err, want)
		}
	}
	if _, _, err := Read(&b, 8); err != io.EOF {
		t.Fatalf("Read at the end = %v, want EOF", err)
	}
}

// TestFrameOverTheBoundIsRefused: a frame longer than the reader's bound
// is refused before its body is read or held.
func TestFrameOverTheBoundIsRefused(t *testing.T) {
	var b bytes.Buffer
	Write(&b, Answer, []byte("12345"))
	n := b.Len()
	if _, _, err := Read(&b, 4); !errors.Is(err, ErrTooLarge) || b.Len() != n-5 {
		t.Fatalf("Read = %v with %d bytes left; want ErrTooLarge and only the header read", err, b.Len())
	}
	if err := Write(io.Discard, Answer, make([]byte, MaxBody+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Write past MaxBody = %v", err)
	}
	// A bound above MaxBody is MaxBody.
	hdr := []byte{Answer, 0, 0x40, 0, 1} // MaxBody+1
	if _, _, err := Read(bytes.NewReader(hdr), 1<<30); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Read past MaxBody = %v", err)
	}
}

func TestTruncatedFrameIsAnError(t *testing.T) {
	var b bytes.Buffer
	Write(&b, Answer, []byte("abc"))
	for _, n := range []int{2, 5, 7} {
		if _, _, err := Read(bytes.NewReader(b.Bytes()[:n]), 8); err == nil || err == io.EOF {
			t.Fatalf("%d of 8 bytes: %v, want an unexpected end", n, err)
		}
	}
}
