package imapconn

// REQ: CRED-1, CRED-8

import (
	"bufio"
	"errors"
	"runtime"
	"runtime/metrics"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap"
)

// TestResponseFieldsAreBounded (SR3-mail-k18b): one response of tiny
// fields, the shape that holds the most memory per byte, stops at a
// million fields, which bounds what any response holds whatever the
// read budget. A UID SEARCH of a million messages still parses.
func TestResponseFieldsAreBounded(t *testing.T) {
	const max = 1 << 20
	read := func(fields int) (uint64, error) {
		reply := "* SEARCH " + strings.Repeat("a ", fields-1) + "a\r\n"
		runtime.GC()
		peak := heapPeak()
		_, err := imap.ReadResp(imap.NewReader(bufio.NewReader(strings.NewReader(reply))))
		return peak(), err
	}
	if _, err := read(max - 1); err != nil {
		t.Fatalf("a SEARCH of %d UIDs failed: %v", max-1, err)
	}
	grew, err := read(max + 1)
	if !errors.Is(err, imap.ErrTooManyFields) {
		t.Fatalf("a response of %d fields: err %v, want ErrTooManyFields", max+1, err)
	}
	if grew > 96<<20 {
		t.Fatalf("a response stopped at the field bound grew the heap by %d bytes at its peak", grew)
	}
	t.Logf("a response stopped at the field bound grew the heap by %d bytes at its peak", grew)
}

// heapPeak samples the heap's live and unswept objects until the
// returned function is called, which reports the most they grew past
// where they started. Sampling can miss a spike between samples, so it
// understates the peak a little, never overstates it.
func heapPeak() func() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	read := func() uint64 { metrics.Read(s); return s[0].Value.Uint64() }
	base, top := read(), uint64(0)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			if v := read(); v > top {
				top = v
			}
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Microsecond):
			}
		}
	}()
	return func() uint64 {
		close(stop)
		<-done
		if top < base {
			return 0
		}
		return top - base
	}
}
