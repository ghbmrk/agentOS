package inbox

// REQ: VRB-2

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/emersion/go-imap/client"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
)

// The kills of row #6331: mailbox.go's Opened and senders read, each test
// failing when one statement of theirs is deleted.

// newest is the n highest UIDs in ascending order, whatever order the
// server listed them in.
func TestNewestSortsWhatTheServerListed(t *testing.T) {
	if got := newest([]uint32{5, 1, 4, 2, 3}, 2); !slices.Equal(got, []uint32{4, 5}) {
		t.Fatalf("newest = %v; want [4 5]", got)
	}
}

// A record no step has counted a source in is not complete.
func TestAnEmptySendersRecordIsNotComplete(t *testing.T) {
	if (SendersRecord{}).Complete() || (SendersRecord{Sources: map[string]SendersSource{}}).Complete() {
		t.Fatal("a record with no source is complete")
	}
}

// A log already past openedMax fails Opened before any request: the
// transport is never touched (a Live with none would panic on it).
func TestOpenedFailsOnALogPastItsBoundBeforeAnyRequest(t *testing.T) {
	defer func(n int) { openedMax = n }(openedMax)
	openedMax = entryCost
	log := SeenLog{Since: "2026-10-01", Seen: []Seen{{From: "pat@example.test", ID: strings.Repeat("ab", 16), Date: "2026-10-18"}}}
	got, kept, err := (&Live{}).Opened(context.Background(), "2026-10-19", log)
	if !errors.Is(err, ErrTooMuchReadMail) || got != nil || kept.Seen != nil {
		t.Fatalf("opened %v, log %+v, err %v; want ErrTooMuchReadMail and nothing else", got, kept, err)
	}
}

// An old entry the read finds is charged the rest of an entry; past
// openedMax that charge fails the add, and the entry is not logged.
func TestAFoundOldEntryPastTheBoundIsNotLogged(t *testing.T) {
	defer func(n int) { openedMax = n }(openedMax)
	const from = "pat@example.test"
	id := seenID(from, "<old@example.test>", arrived)
	log := SeenLog{Since: "2026-01-01", Seen: []Seen{{From: from, ID: hex.EncodeToString(id[:]), Date: "2026-02-01"}}}
	for _, over := range []bool{false, true} {
		o, err := newOpened("2026-10-19", log)
		if err != nil || len(o.old) != 1 {
			t.Fatalf("newOpened: %v, %d old entries", err, len(o.old))
		}
		openedMax = o.kept + entryCost - oldCost
		if over {
			openedMax--
		}
		err = o.add(id, from, o.today, true, arrived.Unix())
		_, logged := o.log[id]
		if over && (!errors.Is(err, ErrTooMuchReadMail) || logged || o.kept > openedMax) ||
			!over && (err != nil || !logged || o.kept != openedMax) {
			t.Fatalf("over %v: err %v, logged %v, kept %d of %d", over, err, logged, o.kept, openedMax)
		}
	}
}

// Once full, a read only keeps the read mail the log lacks: it opens no
// sender, whether the mail is named (kept) or not (passed over).
func TestAFullReadOpensNoSender(t *testing.T) {
	for _, h := range []string{
		"From: pat@example.test\r\n\r\n",
		"From: pat@example.test\r\nMessage-ID: <a@example.test>\r\n\r\n",
	} {
		o, err := newOpened("2026-10-19", SeenLog{})
		if err != nil || o.watched {
			t.Fatalf("newOpened: %v, watched %v", err, o.watched)
		}
		o.fill()
		named := strings.Contains(h, "Message-ID")
		kept := o.kept
		if err := o.header([]byte(h), arrived); err != nil {
			t.Fatal(err)
		}
		want := kept
		if named {
			want += fullCost("pat@example.test")
		}
		if len(o.senders) != 0 || o.kept != want || len(o.log) != len(o.fresh) {
			t.Fatalf("named %v: senders %v, kept %d (want %d), %d logged, %d fresh", named, o.senders, o.kept, want, len(o.log), len(o.fresh))
		}
	}
}

// tamperedStore is liveStore with each answer of the connection process
// passed through tamper before the clerk reads it, so a test can have the
// server list UIDs out of order or a request fail.
func tamperedStore(t *testing.T, srv *imaptest.Server, tamper func(imapwire.Request, *imapwire.Response)) *imapsmtp.Store {
	t.Helper()
	conn := func(context.Context) (*net.UnixConn, error) {
		mine, theirs, err := imapconn.Socketpair()
		if err != nil {
			return nil, err
		}
		go func() {
			defer theirs.Close()
			b, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
			_, oobn, _, _, err := theirs.ReadMsgUnix(b, oob)
			if err != nil {
				return
			}
			msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
			if err != nil || len(msgs) != 1 {
				return
			}
			fds, err := syscall.ParseUnixRights(&msgs[0])
			if err != nil || len(fds) != 1 {
				return
			}
			f := os.NewFile(uintptr(fds[0]), "imap-stream")
			stream, err := net.FileConn(f)
			f.Close()
			if err != nil {
				return
			}
			defer stream.Close()
			c, err := client.New(stream)
			if err != nil {
				return
			}
			c.ErrorLog = log.New(io.Discard, "", 0)
			for {
				var q imapwire.Request
				if imapwire.Read(theirs, 64<<20, &q) != nil {
					return
				}
				r := imapconn.Handle(c, q)
				tamper(q, &r)
				if imapwire.Write(theirs, r) != nil {
					return
				}
			}
		}()
		return mine, nil
	}
	st, err := imapsmtp.New(imapsmtp.Config{Conn: conn, IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: imaptest.User,
		Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: imaptest.User, Secret: imaptest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// sendersAt is a mail from sender to deliver at minute i of a day.
func sendersAt(srv *imaptest.Server, folder string, i int, sender string) {
	srv.DeliverAt(folder, time.Date(2026, 10, 1, 0, i, 0, 0, time.UTC), rawMail("<m"+sender+">", sender, "Hi"))
}

// One step's limit is spent across the folders in name order: a folder
// reached with none left reads nothing, and only mail left to read now makes
// more; a folder read through waits, with its new mail, for the next step.
func TestSendersStepSpendsOneLimitAcrossFolders(t *testing.T) {
	ctx := context.Background()
	srv := imaptest.Start(t)
	sendersAt(srv, "Archive", 1, "a1@x.test")
	sendersAt(srv, "Archive", 2, "a2@x.test")
	sendersAt(srv, "INBOX", 3, "i1@x.test")
	l := NewLive(liveStore(t, srv))
	var r SendersRecord
	if more, err := l.SendersStep(ctx, &r, 1); err != nil || !more || !maps.Equal(r.Senders, map[string]int64{"a1@x.test": time.Date(2026, 10, 1, 0, 1, 0, 0, time.UTC).Unix()}) ||
		r.Sources["Archive"] != (SendersSource{Validity: r.Sources["Archive"].Validity, High: 1}) || r.Sources["INBOX"] != (SendersSource{}) {
		t.Fatalf("first step: more %v, err %v, record %+v", more, err, r)
	}
	if more, err := l.SendersStep(ctx, &r, 10); err != nil || more || !r.Complete() || len(r.Senders) != 3 || r.Sources["Archive"].High != 2 || r.Sources["INBOX"].High != 1 {
		t.Fatalf("second step: more %v, err %v, record %+v", more, err, r)
	}
	// Archive takes the one mail the step may read, and is through again;
	// INBOX, through, waits with its new mail; nothing is left to read now.
	sendersAt(srv, "Archive", 4, "a3@x.test")
	sendersAt(srv, "INBOX", 5, "i2@x.test")
	if more, err := l.SendersStep(ctx, &r, 1); err != nil || more || r.Sources["Archive"].High != 3 || r.Sources["INBOX"].High != 1 || r.Senders["i2@x.test"] != 0 {
		t.Fatalf("third step: more %v, err %v, record %+v", more, err, r)
	}
	// Archive's two new mails, one at a time: the first leaves more.
	sendersAt(srv, "Archive", 6, "a4@x.test")
	sendersAt(srv, "Archive", 7, "a5@x.test")
	if more, err := l.SendersStep(ctx, &r, 1); err != nil || !more || r.Sources["Archive"].High != 4 {
		t.Fatalf("fourth step: more %v, err %v, record %+v", more, err, r)
	}
}

// A folder the step reaches with no limit left, and not yet read through,
// is counted in the record and leaves more, though the folder before it was
// read through.
func TestSendersStepCountsAFolderItHadNoLimitFor(t *testing.T) {
	srv := imaptest.Start(t)
	sendersAt(srv, "Archive", 1, "a1@x.test")
	sendersAt(srv, "INBOX", 2, "i1@x.test")
	l := NewLive(liveStore(t, srv))
	var r SendersRecord
	more, err := l.SendersStep(context.Background(), &r, 1)
	_, counted := r.Sources["INBOX"]
	if err != nil || !more || r.Complete() || !counted || !r.Sources["Archive"].Through || r.Sources["INBOX"].High != 0 {
		t.Fatalf("more %v, err %v, INBOX counted %v, record %+v", more, err, counted, r)
	}
}

// Past longPerStep long-header mails in one step, the step ends at the next
// one: the folder goes on above it at the next step.
func TestSendersStepEndsAtTooManyLongHeaders(t *testing.T) {
	srv := imaptest.Start(t)
	for i := range longPerStep + 1 {
		srv.DeliverAt("Archive", time.Date(2026, 10, 1, 0, i, 0, 0, time.UTC), "From: \""+strings.Repeat("x", 9<<10)+"\" <long@x.test>\nMessage-ID: <long"+strconv.Itoa(i)+"@x.test>\n\nsynthetic body\n")
	}
	sendersAt(srv, "Archive", 59, "a1@x.test")
	l := NewLive(liveStore(t, srv))
	var r SendersRecord
	if more, err := l.SendersStep(context.Background(), &r, 100); err != nil || !more || r.Sources["Archive"].High != longPerStep+1 || len(r.Senders) != 0 {
		t.Fatalf("first step: more %v, err %v, record %+v", more, err, r)
	}
	if more, err := l.SendersStep(context.Background(), &r, 100); err != nil || more || r.Sources["Archive"].High != longPerStep+2 || r.Senders["a1@x.test"] == 0 {
		t.Fatalf("second step: more %v, err %v, record %+v", more, err, r)
	}
}

// A source no longer counted (gone, or of another role) is dropped, and a
// folder renumbered from UID 1 is read again from the start.
func TestSendersStepFollowsTheFoldersAsTheyAre(t *testing.T) {
	ctx := context.Background()
	srv := imaptest.Start(t)
	sendersAt(srv, "Archive", 1, "a1@x.test")
	l := NewLive(liveStore(t, srv))
	r := SendersRecord{Sources: map[string]SendersSource{"Gone": {}}}
	if more, err := l.SendersStep(ctx, &r, 10); err != nil || more || !r.Complete() || slices.Contains(slices.Collect(maps.Keys(r.Sources)), "Gone") {
		t.Fatalf("first step: more %v, err %v, record %+v", more, err, r)
	}
	old := r.Sources["Archive"]
	srv.Reset("Archive")
	sendersAt(srv, "Archive", 2, "b1@x.test")
	if more, err := l.SendersStep(ctx, &r, 10); err != nil || more || r.Senders["b1@x.test"] == 0 ||
		r.Sources["Archive"].Validity == old.Validity || r.Sources["Archive"].High != 1 {
		t.Fatalf("after the reset: more %v, err %v, record %+v (was %+v)", more, err, r, old)
	}
}

// UIDs the server lists out of order are read in UID order: the highest
// read is the folder's High, and nothing is left.
func TestSendersStepReadsUIDsInOrder(t *testing.T) {
	srv := imaptest.Start(t)
	for i, s := range []string{"a1@x.test", "a2@x.test", "a3@x.test"} {
		sendersAt(srv, "Archive", i, s)
	}
	l := NewLive(tamperedStore(t, srv, func(q imapwire.Request, r *imapwire.Response) {
		if q.Op == imapwire.OpUIDs {
			slices.Reverse(r.UIDs)
		}
	}))
	var r SendersRecord
	if more, err := l.SendersStep(context.Background(), &r, 10); err != nil || more || !r.Complete() || r.Sources["Archive"].High != 3 || len(r.Senders) != 3 {
		t.Fatalf("more %v, err %v, record %+v", more, err, r)
	}
}

// A step whose folder list, or a folder's UID list, fails returns the error
// and leaves the record as it was.
func TestSendersStepFailsWithItsListing(t *testing.T) {
	for _, op := range []string{imapwire.OpFolders, imapwire.OpUIDs} {
		srv := imaptest.Start(t)
		sendersAt(srv, "Archive", 1, "a1@x.test")
		l := NewLive(tamperedStore(t, srv, func(q imapwire.Request, r *imapwire.Response) {
			if q.Op == op {
				*r = imapwire.Response{Err: imapwire.Code(errors.New("listing failed"))}
			}
		}))
		r := SendersRecord{Sources: map[string]SendersSource{"Archive": {Validity: 7, High: 0}, "Gone": {}}, Senders: map[string]int64{}, Sent: map[string]bool{}}
		before := SendersRecord{Sources: maps.Clone(r.Sources), Senders: map[string]int64{}, Sent: map[string]bool{}}
		if more, err := l.SendersStep(context.Background(), &r, 10); err == nil || more {
			t.Fatalf("%s failing: more %v, err %v", op, more, err)
		}
		if op == imapwire.OpFolders && !reflect.DeepEqual(r, before) || r.Sources["Archive"] != before.Sources["Archive"] {
			t.Fatalf("%s failing changed the record: %+v; want %+v", op, r, before)
		}
	}
}

// A mail whose From passes the header bound is passed over; the mails around
// it are read and the folder is read through.
func TestSendersStepPassesOverALongHeader(t *testing.T) {
	srv := imaptest.Start(t)
	sendersAt(srv, "Archive", 1, "a1@x.test")
	srv.DeliverAt("Archive", time.Date(2026, 10, 1, 0, 2, 0, 0, time.UTC), "From: \""+strings.Repeat("x", 9<<10)+"\" <long@x.test>\nMessage-ID: <long@x.test>\n\nsynthetic body\n")
	sendersAt(srv, "Archive", 3, "a3@x.test")
	l := NewLive(liveStore(t, srv))
	var r SendersRecord
	if more, err := l.SendersStep(context.Background(), &r, 10); err != nil || more || !r.Complete() || r.Sources["Archive"].High != 3 ||
		!maps.Equal(r.Senders, map[string]int64{"a1@x.test": time.Date(2026, 10, 1, 0, 1, 0, 0, time.UTC).Unix(), "a3@x.test": time.Date(2026, 10, 1, 0, 3, 0, 0, time.UTC).Unix()}) {
		t.Fatalf("more %v, err %v, record %+v", more, err, r)
	}
}
