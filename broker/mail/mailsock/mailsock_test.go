package mailsock_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/mail/imapsmtp"
	"github.com/ghbmrk/agentos/broker/mail/mailsock"
	"github.com/ghbmrk/agentos/broker/mail/mailtest"
)

// REQ: CRED-1, CRED-7, OP-3, ADP-2

var ctx = context.Background()

const me = mailtest.User

// frames records what crossed the socket: each request and each reply.
type frames struct {
	mu       sync.Mutex
	req, rep []*bytes.Buffer
}

type recConn struct {
	net.Conn
	req, rep *bytes.Buffer
	mu       *sync.Mutex
}

func (c recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.req.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c recConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.rep.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (f *frames) replies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, b := range f.rep {
		out = append(out, b.String())
	}
	return out
}

func (f *frames) all() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var s strings.Builder
	for i := range f.req {
		s.WriteString(f.req[i].String())
		s.WriteString(f.rep[i].String())
	}
	return s.String()
}

// serve stands in for the vault process: a unix listener whose every
// connection is one mailsock exchange with src, recorded.
func serve(t *testing.T, src mailsock.Source) (string, *frames) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ms")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, mailsock.Socket)
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &frames{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			rc := recConn{Conn: c, req: &bytes.Buffer{}, rep: &bytes.Buffer{}, mu: &f.mu}
			f.mu.Lock()
			f.req, f.rep = append(f.req, rc.req), append(f.rep, rc.rep)
			f.mu.Unlock()
			go mailsock.ServeConn(rc, src)
		}
	}()
	return path, f
}

func account(t *testing.T, srv *mailtest.Server) mailsock.Source {
	t.Helper()
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain,
		From: me, Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: mailtest.User, Secret: mailtest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return func() (mailsock.Account, error) { return mailsock.Account{Store: st, Address: me}, nil }
}

func news(srv *mailtest.Server, folder, id, from string) {
	srv.Deliver(folder, "From: "+from+"\nTo: "+me+"\nSubject: Autumn sale\nDate: Mon, 05 Oct 2026 08:00:00 +0000\nMessage-ID: "+id+
		"\nContent-Type: text/plain; charset=utf-8\n\nTwenty percent off boots.\n")
}

const alertID = "<pw-change@bank.example>"

func rebuild(srv *mailtest.Server, folder string) func() {
	return func() {
		srv.Reset(folder)
		news(srv, folder, alertID, "security@bank.example")
	}
}

func alertUntouched(t *testing.T, srv *mailtest.Server) {
	t.Helper()
	got, flags, ok := srv.Find(alertID)
	if !ok || got != "INBOX" || len(flags) != 0 {
		t.Fatalf("alert changed: in %q (found %v) flags %v", got, ok, flags)
	}
}

// TestClientRefusesAStaleValidity (W1-b): a UID validity change between
// a read and a mutation reaches the client as mail.ErrValidity, the
// sentinel the adapter checks, so M15 behaves as it does in tests.
func TestClientRefusesAStaleValidity(t *testing.T) {
	srv := mailtest.Start(t)
	path, _ := serve(t, account(t, srv))
	c := mailsock.NewClient(path)
	news(srv, "INBOX", "<news-0@shop.example>", "deals@shop.example")
	ms, err := c.Find(ctx, "INBOX", "<news-0@shop.example>")
	if err != nil || len(ms) != 1 || ms[0].Validity == 0 {
		t.Fatalf("find: %+v %v", ms, err)
	}
	r := ms[0].Ref()
	rebuild(srv, "INBOX")()
	if err := c.SetFlags(ctx, r, []string{mail.Seen}, nil); !errors.Is(err, mail.ErrValidity) {
		t.Fatalf("set flags across the reset: %v", err)
	}
	if err := c.Move(ctx, r, "Archive"); !errors.Is(err, mail.ErrValidity) {
		t.Fatalf("move across the reset: %v", err)
	}
	if _, err := c.Fetch(ctx, "INBOX", r.Validity, []uint32{r.UID}); !errors.Is(err, mail.ErrValidity) {
		t.Fatalf("fetch across the reset: %v", err)
	}
	alertUntouched(t, srv)
}

// between runs hook once, just before the named call reaches the client.
type between struct {
	mail.Store
	at   string
	hook func()
}

func (b *between) fire(m string) {
	if b.hook != nil && b.at == m {
		f := b.hook
		b.hook = nil
		f()
	}
}

func (b *between) SetFlags(ctx context.Context, r mail.Ref, add, remove []string) error {
	b.fire("SetFlags")
	return b.Store.SetFlags(ctx, r, add, remove)
}

func (b *between) Move(ctx context.Context, r mail.Ref, to string) error {
	b.fire("Move")
	return b.Store.Move(ctx, r, to)
}

// TestAdapterOverTheClientNeverMutatesAReplacedUID (W1-b): the adapter
// over the socket gives the outcomes it gives over imapsmtp directly
// when the mailbox is rebuilt mid-action (M15).
func TestAdapterOverTheClientNeverMutatesAReplacedUID(t *testing.T) {
	for _, tc := range []struct {
		name, op, at string
		flags        []string
		want         journal.Result
	}{
		{"archive", mail.OpArchive, "SetFlags", nil, journal.ResultNotApplied},
		{"mark read", mail.OpMarkRead, "SetFlags", nil, journal.ResultNotApplied},
		{"move only", mail.OpArchive, "Move", []string{mail.Keyword}, journal.ResultNotApplied},
		{"after flags", mail.OpArchive, "Move", nil, journal.ResultUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := mailtest.Start(t)
			path, _ := serve(t, account(t, srv))
			b := &between{Store: mailsock.NewClient(path)}
			now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
			a, err := mail.New(mail.Config{Account: "mail", Address: me, Store: b,
				InUse: func(string, time.Time) []journal.Use { return nil },
				Now:   func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			id := "<news-0@shop.example>"
			news(srv, "INBOX", id, "Shop <deals@shop.example>")
			if tc.flags != nil {
				srv.SetFlags(id, tc.flags...)
			}
			in := journal.Intent{ID: "agent/1", Origin: "guest:agent", Account: "mail", Action: tc.op,
				Params: map[string]any{mail.ParamRecord: id}, Executor: "mail"}
			if _, err := a.Escalate(ctx, in); err != nil {
				t.Fatal(err)
			}
			b.at, b.hook = tc.at, rebuild(srv, "INBOX")
			a.Escalate(ctx, in)
			out := a.Execute(ctx, in, 1)
			if b.hook != nil {
				t.Fatal("the reset did not happen")
			}
			if out.Result != tc.want || strings.Contains(out.Evidence, id) {
				t.Fatalf("outcome %s %q", out.Result, out.Evidence)
			}
			alertUntouched(t, srv)
		})
	}
}

// nine calls every mail.Store method once.
func nine(s mail.Store) []error {
	r := mail.Ref{Folder: "INBOX", Validity: 1, UID: 1}
	raw := []byte("From: " + me + "\r\nTo: friend@example.test\r\nSubject: hi\r\n\r\nhello\r\n")
	_, e1 := s.Folders(ctx)
	_, _, e2 := s.UIDs(ctx, "INBOX")
	_, e3 := s.Fetch(ctx, "INBOX", 1, []uint32{1})
	_, e4 := s.Find(ctx, "INBOX", "<x@example.test>")
	return []error{e1, e2, e3, e4,
		s.SetFlags(ctx, r, []string{mail.Seen}, nil),
		s.Move(ctx, r, "Archive"),
		s.Ensure(ctx, "Archive"),
		s.Append(ctx, "Sent", []string{mail.Seen}, time.Now(), raw),
		s.Submit(ctx, []string{"friend@example.test"}, raw)}
}

// TestNotConnected (W1-d): with no account set up every method answers
// ErrNotConnected, and no reply carries more than that.
func TestNotConnected(t *testing.T) {
	path, f := serve(t, func() (mailsock.Account, error) { return mailsock.Account{}, mailsock.ErrNotConnected })
	for i, err := range nine(mailsock.NewClient(path)) {
		if !errors.Is(err, mailsock.ErrNotConnected) {
			t.Errorf("method %d: %v", i, err)
		}
	}
	reps := f.replies()
	if len(reps) != 9 {
		t.Fatalf("%d replies", len(reps))
	}
	for _, r := range reps {
		if r != `{"error":"not_connected"}`+"\n" {
			t.Errorf("reply %q", r)
		}
	}
}

// TestLockedAndUnreachable: a locked vault and a vault process that is
// not there are told apart from a missing account.
func TestLockedAndUnreachable(t *testing.T) {
	path, _ := serve(t, func() (mailsock.Account, error) { return mailsock.Account{}, mailsock.ErrLocked })
	for i, err := range nine(mailsock.NewClient(path)) {
		if !errors.Is(err, mailsock.ErrLocked) {
			t.Errorf("locked, method %d: %v", i, err)
		}
	}
	for i, err := range nine(mailsock.NewClient(filepath.Join(t.TempDir(), "none.sock"))) {
		if !errors.Is(err, mailsock.ErrUnreachable) {
			t.Errorf("no socket, method %d: %v", i, err)
		}
	}
}

// TestServerWordsDoNotCross: a failure on the mail server reaches the
// client as the fixed ErrFailed; the server's own text stays behind.
func TestServerWordsDoNotCross(t *testing.T) {
	srv := mailtest.Start(t)
	path, f := serve(t, account(t, srv))
	c := mailsock.NewClient(path)
	srv.FailList("INBOX", true)
	srv.FailSMTP(true)
	if _, _, err := c.UIDs(ctx, "INBOX"); !errors.Is(err, mailsock.ErrFailed) {
		t.Fatalf("uids: %v", err)
	}
	raw := []byte("From: " + me + "\r\nTo: friend@example.test\r\nSubject: hi\r\n\r\nhello\r\n")
	if err := c.Submit(ctx, []string{"friend@example.test"}, raw); !errors.Is(err, mailsock.ErrFailed) {
		t.Fatalf("submit: %v", err)
	}
	for _, r := range f.replies() {
		if r != `{"error":"failed"}`+"\n" {
			t.Errorf("reply %q", r)
		}
	}
	if s := f.all(); strings.Contains(s, mailtest.Password) {
		t.Fatal("credential crossed the socket")
	}
}

// TestSubmitSendsOnlyAsTheAccount: a message whose header names another
// sender is refused before it reaches SMTP.
func TestSubmitSendsOnlyAsTheAccount(t *testing.T) {
	srv := mailtest.Start(t)
	path, _ := serve(t, account(t, srv))
	c := mailsock.NewClient(path)
	body := "To: friend@example.test\r\nSubject: hi\r\n\r\nhello\r\n"
	for _, h := range []string{
		"From: ceo@example.test\r\n",
		"From: " + me + "\r\nFrom: ceo@example.test\r\n",
		"From: " + me + ", ceo@example.test\r\n",
		"From: " + me + "\r\nSender: ceo@example.test\r\n",
		"From: " + me + "\r\nResent-From: ceo@example.test\r\n",
		"From: " + me + "\r\nReply-To: x@example.test\r\nResent-Sender: ceo@example.test\r\n",
		"",
	} {
		if err := c.Submit(ctx, []string{"friend@example.test"}, []byte(h+body)); !errors.Is(err, mailsock.ErrRefused) {
			t.Errorf("%q: %v", h, err)
		}
	}
	if err := c.Submit(ctx, nil, []byte("From: "+me+"\r\n"+body)); !errors.Is(err, mailsock.ErrRefused) {
		t.Errorf("no recipients: %v", err)
	}
	if n := len(srv.Submitted()); n != 0 {
		t.Fatalf("%d submitted", n)
	}
	for _, from := range []string{me, "Owner <" + strings.ToUpper(me) + ">"} {
		if err := c.Submit(ctx, []string{"friend@example.test"}, []byte("From: "+from+"\r\n"+body)); err != nil {
			t.Fatalf("own address %q: %v", from, err)
		}
	}
	if s := srv.Submitted(); len(s) != 2 || s[0].From != me {
		t.Fatalf("submitted %+v", s)
	}
}

// TestClientHonoursItsContext: a vault process that never answers costs
// the caller no more than its own deadline.
func TestClientHonoursItsContext(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	path, _ := serve(t, func() (mailsock.Account, error) { <-block; return mailsock.Account{}, mailsock.ErrNotConnected })
	cx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := mailsock.NewClient(path).Folders(cx); !errors.Is(err, mailsock.ErrUnreachable) {
		t.Fatalf("folders: %v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}
