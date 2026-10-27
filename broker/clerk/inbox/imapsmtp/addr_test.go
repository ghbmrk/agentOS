package imapsmtp

// REQ: VRB-2

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

func addrMail(n int) string {
	return fmt.Sprintf("From: <a%d@x.test>\nTo: <owner@example.test>\nCc: <c%d@y.test>\nSubject: %s\nMessage-ID: <m%d@x.test>\n\nbody\n", n, n, planCanary, n)
}

type addrHead struct {
	header  string
	arrived time.Time
}

func addrHeads(st *Store, folder string, validity uint32, uids []uint32) ([]addrHead, error) {
	var got []addrHead
	err := st.AddrHeads(context.Background(), folder, validity, uids, func(h []byte, at time.Time) error {
		got = append(got, addrHead{string(h), at})
		return nil
	})
	return got, err
}

// MAIL-world-b1: AddrHeads reads the From, To and Cc and the arrival of every
// UID asked for, past one batch, in one session, with nothing marked read.
func TestAddrHeadsReadsEveryUIDAskedFor(t *testing.T) {
	srv := imaptest.Start(t)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	const n = addrBatch + 3
	for i := 1; i <= n; i++ {
		srv.DeliverAt("Archive", at.Add(time.Duration(i)*time.Minute), addrMail(i))
	}
	st := planStore(t, srv)
	v, uids, err := st.UIDs(context.Background(), "Archive")
	if err != nil {
		t.Fatal(err)
	}
	got, err := addrHeads(st, "Archive", v, uids)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != n {
		t.Fatalf("read %d heads, want %d", len(got), n)
	}
	for _, h := range got {
		var k int
		if _, err := fmt.Sscanf(strings.SplitN(h.header, "<a", 2)[1], "%d", &k); err != nil || !h.arrived.Equal(at.Add(time.Duration(k)*time.Minute)) {
			t.Fatalf("head %q arrived %v", h.header, h.arrived)
		}
		if strings.Contains(h.header, planCanary) || !strings.Contains(h.header, fmt.Sprintf("<c%d@y.test>", k)) {
			t.Fatalf("head %q", h.header)
		}
	}
	if len(srv.Logins()) != 2 { // UIDs, then AddrHeads
		t.Fatalf("signed in %d times", len(srv.Logins()))
	}
	for _, m := range srv.Messages("Archive") {
		if slices.Contains(m.Flags, imap.SeenFlag) {
			t.Fatal("a mail marked read")
		}
	}
}

// A UID with no answer fails the call rather than being skipped, whether the
// mail was deleted since it was listed or the server left it out; so does a
// folder renumbered since.
func TestAddrHeadsFailsAMissingAnswer(t *testing.T) {
	srv := imaptest.Start(t)
	for i := 1; i <= 3; i++ {
		srv.Deliver("INBOX", addrMail(i))
	}
	st := planStore(t, srv)
	v, uids, err := st.UIDs(context.Background(), "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	srv.Remove("INBOX", "<m2@x.test>")
	if _, err := addrHeads(st, "INBOX", v, uids); !errors.Is(err, ErrUnanswered) {
		t.Fatalf("a mail gone since it was listed: err %v, want ErrUnanswered", err)
	}
	srv.Renumber("INBOX")
	if _, err := addrHeads(st, "INBOX", v, []uint32{1}); !errors.Is(err, ErrValidity) {
		t.Fatalf("a renumbered folder: err %v, want ErrValidity", err)
	}

	// A server that answers OK for UIDs 1 and 2 but sends only 1.
	addr := seenServe(t, func(string, int) string { return "" }, each(addrAnswer(1, "From: <a@x.test>\r\n\r\n")), 0)
	got, err := addrHeads(hostileStore(t, addr, 5*time.Second), "INBOX", 7, []uint32{1, 2})
	if !errors.Is(err, ErrUnanswered) {
		t.Fatalf("a UID the server left out: got %v, err %v; want ErrUnanswered", got, err)
	}
}

// A header past headMax names its folder and arrival, as Seen does, and the
// caller's error stops the call.
func TestAddrHeadsNamesALongHeaderAndStopsOnTheCallersError(t *testing.T) {
	srv := imaptest.Start(t)
	at := time.Date(2026, 10, 2, 7, 0, 0, 0, time.UTC)
	srv.DeliverAt("INBOX", at, addrMail(1))
	srv.DeliverAt("INBOX", at.Add(time.Hour), "From: <a@long.test>\nCc: <"+strings.Repeat("x", headMax)+"@y.test>\nSubject: the long one\n\nbody\n")
	st := planStore(t, srv)
	v, uids, err := st.UIDs(context.Background(), "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	_, err = addrHeads(st, "INBOX", v, uids)
	var lh *LongHeaderError
	if !errors.As(err, &lh) || lh.Folder != "INBOX" || !lh.Arrived.Equal(at.Add(time.Hour)) || lh.Subject != "the long one" {
		t.Fatalf("err %v (%+v); want a LongHeaderError naming INBOX and its arrival", err, lh)
	}
	stop := errors.New("canary-stop")
	if err := st.AddrHeads(context.Background(), "INBOX", v, uids[:1], func([]byte, time.Time) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("err %v, want the caller's", err)
	}
}

func addrAnswer(uid int, h string) string {
	return "* " + strconv.Itoa(uid) + " FETCH (UID " + strconv.Itoa(uid) + " INTERNALDATE \"01-Oct-2026 08:00:00 +0000\" BODY[HEADER.FIELDS (FROM TO CC)]<0> {" +
		strconv.Itoa(len(h)) + "}\r\n" + h + ")\r\n"
}
