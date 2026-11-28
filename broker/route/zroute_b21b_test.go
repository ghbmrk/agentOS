package route

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// REQ: PLN-7
//
// Package B2-1 (#1460): the end of an OpenAI stream stays covered after the
// late-error test stopped reaching it: a source that ends without [DONE]
// reports io.ErrUnexpectedEOF, and a source read error is returned as is.

type failingReader struct {
	data string
	err  error
	done bool
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.done {
		return 0, f.err
	}
	f.done = true
	return copy(p, f.data), nil
}

func TestOpenAIStreamEndsWithoutDone(t *testing.T) {
	src := "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n"
	var out strings.Builder
	u, err := OpenAI().Stream(&out, func() {}, strings.NewReader(src), "default", false)
	if err != io.ErrUnexpectedEOF || u.Complete {
		t.Fatalf("truncated stream: %v %+v", err, u)
	}
}

func TestOpenAIStreamReadErrorReturned(t *testing.T) {
	boom := errors.New("read boom")
	src := &failingReader{data: "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n", err: boom}
	var out strings.Builder
	if _, err := OpenAI().Stream(&out, func() {}, src, "default", false); err != boom {
		t.Fatalf("read error: %v", err)
	}
}
