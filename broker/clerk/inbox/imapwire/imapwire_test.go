package imapwire

// REQ: VRB-2

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// MAIL-world-b1: an AddrHeads request and its answer cross the wire as
// they were sent: the folder, validity and UIDs asked for, and each head's
// UID, header and arrival.
func TestAddrHeadsRoundTrips(t *testing.T) {
	at := time.Date(2026, 10, 27, 9, 30, 0, 0, time.UTC)
	q := Request{Op: OpAddrHeads, Folder: "Archive", Validity: 7, UIDs: []uint32{3, 9}}
	a := Response{Heads: []Head{{UID: 3, Header: []byte("From: <a@x.test>\r\nTo: <b@y.test>\r\nCc: <c@z.test>\r\n\r\n"), Arrived: at}}}
	var buf bytes.Buffer
	if err := Write(&buf, q); err != nil {
		t.Fatal(err)
	}
	if err := Write(&buf, a); err != nil {
		t.Fatal(err)
	}
	var gq Request
	var ga Response
	if err := Read(&buf, 1<<20, &gq); err != nil {
		t.Fatal(err)
	}
	if err := Read(&buf, 1<<20, &ga); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gq, q) {
		t.Fatalf("request %+v, want %+v", gq, q)
	}
	if len(ga.Heads) != 1 || ga.Heads[0].UID != 3 || !bytes.Equal(ga.Heads[0].Header, a.Heads[0].Header) || !ga.Heads[0].Arrived.Equal(at) {
		t.Fatalf("answer %+v, want %+v", ga, a)
	}
}

// An answer past its reader's bound fails before it is read, and a long
// header crosses as its code and the mail it names: its folder and arrival,
// never success.
func TestAddrHeadsAnswerIsBounded(t *testing.T) {
	big := Response{Heads: []Head{{UID: 1, Header: bytes.Repeat([]byte("x"), 4096)}}}
	var buf bytes.Buffer
	if err := Write(&buf, big); err != nil {
		t.Fatal(err)
	}
	if err := Read(&buf, 1024, &Response{}); !errors.Is(err, ErrFrame) {
		t.Fatalf("an answer over the bound: err %v, want ErrFrame", err)
	}

	at := time.Date(2026, 10, 27, 9, 30, 0, 0, time.FixedZone("", 2*3600))
	long := Response{Err: Code(ErrLongHeader), Long: &LongHeaderError{Folder: "Archive", Arrived: at, UID: 4}}
	buf.Reset()
	if err := Write(&buf, long); err != nil {
		t.Fatal(err)
	}
	var got Response
	if err := Read(&buf, 1<<20, &got); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(Err(got.Err), ErrLongHeader) || got.Long == nil {
		t.Fatalf("a long header crossed as %+v", got)
	}
	msg := got.Long.Error()
	for _, want := range []string{"Archive", "2026-10-27 09:30 +0200", "UID 4"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the long header's error %q does not name %q", msg, want)
		}
	}
	if Err("unknown") != ErrFailed {
		t.Fatal("an unknown code is not a failure")
	}
}
