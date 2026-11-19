package inbox

// REQ: VRB-2, OWN-13

// The fault seam lives in its own file so its imports reach only these tests.

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

// faultyLive is a Live over srv whose connection process fails to start on
// session fail, counted from the last arm, so each read or change can be
// made to fail on its own; 0 fails none.
type faultyLive struct {
	box        *Live
	n, failure atomic.Int64
}

func newFaultyLive(t *testing.T, srv *imaptest.Server) *faultyLive {
	t.Helper()
	f := &faultyLive{}
	pipe := imapconn.Pipe()
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: imaptest.User,
		Conn: func(ctx context.Context) (*net.UnixConn, error) {
			if f.n.Add(1) == f.failure.Load() {
				return nil, errors.New("test: no connection process")
			}
			return pipe(ctx)
		},
		Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: imaptest.User, Secret: imaptest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	f.box = NewLive(st)
	return f
}

func (f *faultyLive) arm(session int64) { f.n.Store(0); f.failure.Store(session) }

const noProcess = "could not start the connection process"

// A failure of any of Read's sessions (the folder list, the inbox's UIDs,
// its fetch) fails the read, never a partial or empty one; an account that
// lists no inbox says so.
func TestLiveReadFailsWhenAnySessionFails(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", rawMail("<r1@shop.test>", "x@shop.test", "Hi"))
	f := newFaultyLive(t, srv)
	if ms, err := f.box.Read(context.Background()); err != nil || len(ms) != 1 {
		t.Fatalf("clean read: %d mails, %v", len(ms), err)
	}
	if got := f.n.Load(); got != 3 {
		t.Fatalf("a read ran %d sessions, want 3", got)
	}
	for session := int64(1); session <= 3; session++ {
		f.arm(session)
		if ms, err := f.box.Read(context.Background()); err == nil || !strings.Contains(err.Error(), noProcess) {
			t.Errorf("session %d failing: %d mails, %v; want the session's error", session, len(ms), err)
		}
	}
	f.arm(0)
	srv.Hide("INBOX", true)
	if _, err := f.box.Read(context.Background()); err == nil || err.Error() != "inbox: the account lists no inbox" {
		t.Errorf("no inbox listed: %v", err)
	}
}

// A trash fails with the error of its read-back's fetch or trash search,
// never confirmed or merely unconfirmed; a mail this mailbox did not read is
// unknown.
func TestLiveTrashFailsWhenItsReadBackFails(t *testing.T) {
	const id = "<t1@spam.test>"
	for _, session := range []int64{3, 4} { // after the trash's next UID (1) and the move (2)
		srv := imaptest.Start(t)
		srv.Deliver("INBOX", rawMail(id, "x@spam.test", "Win"))
		f := newFaultyLive(t, srv)
		ms, err := f.box.Read(context.Background())
		if err != nil || len(ms) != 1 {
			t.Fatalf("read: %d mails, %v", len(ms), err)
		}
		f.arm(session)
		if err := f.box.Trash(context.Background(), ms[0].ID); err == nil || !strings.Contains(err.Error(), noProcess) {
			t.Errorf("session %d failing: %v; want the session's error", session, err)
		}
		if got := f.n.Load(); session == 4 && got != 4 {
			t.Errorf("a trash ran %d sessions, want 4", got)
		}
		if err := f.box.Trash(context.Background(), "unread"); !errors.Is(err, nUnknown) {
			t.Errorf("trash of a mail never read: %v, want %v", err, nUnknown)
		}
	}
}
