package imapconn

// REQ: VRB-2, KRN-2

import (
	"bytes"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
)

// addrCanary is in every header field and body the op must not read.
const addrCanary = "canary-addr-imap-3422"

func addrMail(n string) string {
	return "From: <a@" + n + ".test>\nTo: <owner@example.test>\nCc: <c@" + n + ".test>\nSubject: " + addrCanary +
		"\nMessage-ID: <" + addrCanary + "-" + n + "@x.test>\n\n" + addrCanary + "\n"
}

// sent records what the client writes to the server.
type sent struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *sent) Write(b []byte) (int, error) {
	s.mu.Lock()
	s.buf.Write(b)
	s.mu.Unlock()
	return s.Conn.Write(b)
}

func (s *sent) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func signedIn(t *testing.T, srv *imaptest.Server) (*client.Client, *sent) {
	t.Helper()
	nc, err := net.Dial("tcp", srv.IMAP)
	if err != nil {
		t.Fatal(err)
	}
	w := &sent{Conn: nc}
	c, err := client.New(w)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Logout(); nc.Close() })
	if err := c.Login(imaptest.User, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	return c, w
}

func validity(t *testing.T, c *client.Client, folder string) uint32 {
	t.Helper()
	r := Handle(c, imapwire.Request{Op: imapwire.OpUIDs, Folder: folder})
	if r.Err != "" {
		t.Fatal(r.Err)
	}
	return r.Validity
}

// MAIL-world-b1 over the loopback server: OpAddrHeads fetches by BODY.PEEK
// only the From, To and Cc of each UID, with its INTERNALDATE, and leaves
// \Seen as it was.
func TestAddrHeadsPeeksAndLeavesSeenUnchanged(t *testing.T) {
	srv := imaptest.Start(t)
	at := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	srv.DeliverAt("Archive", at, addrMail("one"))
	srv.DeliverAt("Archive", at.Add(time.Hour), addrMail("two"), imap.SeenFlag)
	c, w := signedIn(t, srv)
	v := validity(t, c, "Archive")
	r := Handle(c, imapwire.Request{Op: imapwire.OpAddrHeads, Folder: "Archive", Validity: v, UIDs: []uint32{1, 2}})
	if r.Err != "" {
		t.Fatalf("err %q", r.Err)
	}
	if len(r.Heads) != 2 {
		t.Fatalf("heads %+v", r.Heads)
	}
	for i, h := range r.Heads {
		s := string(h.Header)
		if strings.Contains(s, addrCanary) || !strings.Contains(s, "From:") || !strings.Contains(s, "To:") || !strings.Contains(s, "Cc:") {
			t.Fatalf("head %d read %q, want only From, To and Cc", i, s)
		}
		if !h.Arrived.Equal(at.Add(time.Duration(h.UID-1) * time.Hour)) {
			t.Fatalf("head %d arrived %v", i, h.Arrived)
		}
	}
	if s := w.String(); !strings.Contains(s, "BODY.PEEK[HEADER.FIELDS (From To Cc)]") || strings.Contains(s, " BODY[") || strings.Contains(s, "STORE") {
		t.Fatalf("the client sent %q, want a BODY.PEEK fetch and no store", s)
	}
	ms := srv.Messages("Archive")
	if slices.Contains(ms[0].Flags, imap.SeenFlag) || !slices.Contains(ms[1].Flags, imap.SeenFlag) {
		t.Fatalf("flags changed: %+v", ms)
	}
}

// A UID gone since it was listed fails the batch (unanswered), a stale
// validity fails it before fetching (validity), and a header past HeadMax
// ends it naming its folder and arrival (longheader).
func TestAddrHeadsFailsAPartialAnswer(t *testing.T) {
	srv := imaptest.Start(t)
	at := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	srv.DeliverAt("INBOX", at, addrMail("one"))
	srv.DeliverAt("INBOX", at.Add(time.Hour), "From: <a@long.test>\nTo: <"+strings.Repeat("x", HeadMax)+"@y.test>\n\nbody\n")
	c, _ := signedIn(t, srv)
	v := validity(t, c, "INBOX")

	if r := Handle(c, imapwire.Request{Op: imapwire.OpAddrHeads, Folder: "INBOX", Validity: v, UIDs: []uint32{1, 9}}); r.Err != imapwire.Code(imapwire.ErrUnanswered) {
		t.Fatalf("a UID that did not answer: err %q", r.Err)
	}
	if r := Handle(c, imapwire.Request{Op: imapwire.OpAddrHeads, Folder: "INBOX", Validity: v + 1, UIDs: []uint32{1}}); r.Err != imapwire.Code(imapwire.ErrValidity) || len(r.Heads) != 0 {
		t.Fatalf("a stale validity: %+v", r)
	}
	r := Handle(c, imapwire.Request{Op: imapwire.OpAddrHeads, Folder: "INBOX", Validity: v, UIDs: []uint32{1, 2}})
	if r.Err != imapwire.Code(imapwire.ErrLongHeader) || r.Long == nil || r.Long.Folder != "INBOX" || r.Long.UID != 2 || !r.Long.Arrived.Equal(at.Add(time.Hour)) {
		t.Fatalf("a long header: %+v (%+v)", r, r.Long)
	}
}
