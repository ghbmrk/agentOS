// Package mailtest is a local IMAP and SMTP server for the mail adapter's
// tests: one account, folders with special-use roles, MOVE, and an SMTP
// sink that records what was submitted. Synthetic data only; it listens on
// loopback and holds no real account.
package mailtest

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/backend/backendutil"
	"github.com/emersion/go-imap/server"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
	"github.com/emersion/go-sasl"
)

type discard struct{}

func (discard) Printf(string, ...interface{}) {}
func (discard) Println(...interface{})        {}

// xoauth is the server side of XOAUTH2.
type xoauth struct {
	s    *Server
	conn server.Conn
}

func (x *xoauth) Next(resp []byte) ([]byte, bool, error) {
	if resp == nil {
		return []byte{}, false, nil
	}
	if string(resp) != "user="+User+"\x01auth=Bearer "+Token+"\x01\x01" {
		return nil, true, errors.New("bad token")
	}
	ctx := x.conn.Context()
	ctx.State = imap.AuthenticatedState
	ctx.User = &usr{x.s}
	x.s.mu.Lock()
	x.s.logins = append(x.s.logins, "XOAUTH2")
	x.s.mu.Unlock()
	return nil, true, nil
}

// Account credentials. They are canaries, not secrets.
const (
	User     = "owner@example.test"
	Password = "canary-mailtest-password"
	Token    = "canary-mailtest-oauth-token"
)

// Server is a running test server.
type Server struct {
	IMAP, SMTP string // host:port

	mu        sync.Mutex
	boxes     map[string]*box
	validity  uint32
	submitted []Submission
	failList  map[string]bool
	hidden    map[string]bool
	logins    []string
	smtpFail  bool
}

// Submission is one message the SMTP sink accepted.
type Submission struct {
	From string
	Rcpt []string
	Raw  []byte
	Auth string
}

type box struct {
	name     string
	attr     string
	next     uint32
	validity uint32
	msgs     []*msg
}

type msg struct {
	uid   uint32
	date  time.Time
	flags []string
	body  []byte
}

// Start runs a server with INBOX and Archive, Drafts, Sent, Trash and Junk
// folders (with their special-use attributes) until the test ends.
func Start(t *testing.T) *Server {
	t.Helper()
	s := &Server{boxes: map[string]*box{}, validity: 1, failList: map[string]bool{}, hidden: map[string]bool{}}
	for name, attr := range map[string]string{"INBOX": "", "Archive": imap.ArchiveAttr, "Drafts": imap.DraftsAttr,
		"Sent": imap.SentAttr, "Trash": imap.TrashAttr, "Junk": imap.JunkAttr} {
		s.boxes[name] = &box{name: name, attr: attr, next: 1, validity: 1}
	}
	il, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(&be{s})
	srv.AllowInsecureAuth = true
	srv.ErrorLog = discard{}
	srv.EnableAuth("XOAUTH2", func(conn server.Conn) sasl.Server { return &xoauth{s, conn} })
	go srv.Serve(il)
	sl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.serveSMTP(sl)
	s.IMAP, s.SMTP = il.Addr().String(), sl.Addr().String()
	t.Cleanup(func() { srv.Close(); sl.Close() })
	return s
}

// AddFolder adds a folder with a special-use attribute (or none).
func (s *Server) AddFolder(name, attr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.boxes[name] = &box{name: name, attr: attr, next: 1, validity: 1}
}

// SetAttr changes a folder's special-use attribute, keeping its messages
// and UID validity (a provider dropping or restoring a role).
func (s *Server) SetAttr(name, attr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.boxes[name].attr = attr
}

// Deliver puts a raw message in folder, as arriving mail would.
func (s *Server) Deliver(folder string, raw string, flags ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[folder]
	b.msgs = append(b.msgs, &msg{uid: b.next, date: time.Now(), flags: flags, body: []byte(strings.ReplaceAll(raw, "\n", "\r\n"))})
	b.next++
}

// Remove deletes the message with this Message-ID from folder, as the
// owner deleting it in their mail app would.
func (s *Server) Remove(folder, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[folder]
	for i, m := range b.msgs {
		if messageID(m.body) == id {
			b.msgs = append(b.msgs[:i], b.msgs[i+1:]...)
			return
		}
	}
}

// Renumber gives folder a new UID validity and new UIDs.
func (s *Server) Renumber(folder string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[folder]
	b.validity += 100
	for _, m := range b.msgs {
		m.uid = b.next
		b.next++
	}
}

// Reset recreates folder empty under a new UID validity, numbering from
// UID 1 again, as a provider rebuilding a mailbox would: a message
// delivered after it can carry a UID an earlier message had.
func (s *Server) Reset(folder string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[folder]
	b.validity += 100
	b.msgs, b.next = nil, 1
}

// FailList makes listing folder fail (or not).
func (s *Server) FailList(folder string, fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failList[folder] = fail
}

// Hide leaves folder out of LIST (or not), as a broken listing would.
func (s *Server) Hide(folder string, hide bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hidden[folder] = hide
}

// FailSMTP makes the SMTP sink refuse DATA (or not).
func (s *Server) FailSMTP(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.smtpFail = fail
}

// Message is a stored message as a test reads it back.
type Message struct {
	UID   uint32
	ID    string
	Flags []string
	Raw   string
}

// Messages returns folder's messages.
func (s *Server) Messages(folder string) []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Message
	for _, m := range s.boxes[folder].msgs {
		f := append([]string(nil), m.flags...)
		sort.Strings(f)
		out = append(out, Message{UID: m.uid, ID: messageID(m.body), Flags: f, Raw: string(m.body)})
	}
	return out
}

// Find returns the folder and flags of the message with this Message-ID.
func (s *Server) Find(id string) (folder string, flags []string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.boxes))
	for n := range s.boxes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, m := range s.boxes[n].msgs {
			if messageID(m.body) == id {
				f := append([]string(nil), m.flags...)
				sort.Strings(f)
				return n, f, true
			}
		}
	}
	return "", nil, false
}

// SetFlags replaces a message's flags, as the owner's mail app would.
func (s *Server) SetFlags(id string, flags ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.boxes {
		for _, m := range b.msgs {
			if messageID(m.body) == id {
				m.flags = flags
			}
		}
	}
}

// Submitted returns what the SMTP sink accepted.
func (s *Server) Submitted() []Submission {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Submission(nil), s.submitted...)
}

// Logins returns the IMAP logins seen, by mechanism.
func (s *Server) Logins() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.logins...)
}

func messageID(body []byte) string {
	h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(body)))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(h.Get("Message-Id"))
}

// IMAP backend.

type be struct{ s *Server }

func (b *be) Login(_ *imap.ConnInfo, user, pass string) (backend.User, error) {
	if user != User || pass != Password {
		return nil, errors.New("bad credentials")
	}
	b.s.mu.Lock()
	b.s.logins = append(b.s.logins, "LOGIN")
	b.s.mu.Unlock()
	return &usr{b.s}, nil
}

type usr struct{ s *Server }

func (u *usr) Username() string { return User }

func (u *usr) ListMailboxes(bool) ([]backend.Mailbox, error) {
	u.s.mu.Lock()
	defer u.s.mu.Unlock()
	var out []backend.Mailbox
	for n := range u.s.boxes {
		if !u.s.hidden[n] {
			out = append(out, &mbox{u.s, n})
		}
	}
	return out, nil
}

func (u *usr) GetMailbox(name string) (backend.Mailbox, error) {
	u.s.mu.Lock()
	defer u.s.mu.Unlock()
	if strings.EqualFold(name, "INBOX") {
		name = "INBOX"
	}
	if _, ok := u.s.boxes[name]; !ok {
		return nil, backend.ErrNoSuchMailbox
	}
	return &mbox{u.s, name}, nil
}

func (u *usr) CreateMailbox(name string) error {
	u.s.mu.Lock()
	defer u.s.mu.Unlock()
	if _, ok := u.s.boxes[name]; ok {
		return errors.New("mailbox exists")
	}
	u.s.boxes[name] = &box{name: name, next: 1, validity: 1}
	return nil
}

func (u *usr) DeleteMailbox(string) error         { return errors.New("not supported") }
func (u *usr) RenameMailbox(string, string) error { return errors.New("not supported") }
func (u *usr) Logout() error                      { return nil }

type mbox struct {
	s    *Server
	name string
}

var _ backend.MoveMailbox = (*mbox)(nil)

func (m *mbox) b() *box { return m.s.boxes[m.name] }

func (m *mbox) Name() string { return m.name }

func (m *mbox) Info() (*imap.MailboxInfo, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	info := &imap.MailboxInfo{Delimiter: "/", Name: m.name}
	if a := m.b().attr; a != "" {
		info.Attributes = []string{a}
	}
	return info, nil
}

func (m *mbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	if m.s.failList[m.name] {
		return nil, errors.New("listing failed")
	}
	b := m.b()
	st := imap.NewMailboxStatus(m.name, items)
	st.Flags = []string{imap.SeenFlag, imap.FlaggedFlag, imap.DraftFlag, imap.DeletedFlag}
	st.PermanentFlags = []string{`\*`}
	for _, it := range items {
		switch it {
		case imap.StatusMessages:
			st.Messages = uint32(len(b.msgs))
		case imap.StatusUidNext:
			st.UidNext = b.next
		case imap.StatusUidValidity:
			st.UidValidity = b.validity
		}
	}
	return st, nil
}

func (m *mbox) SetSubscribed(bool) error { return nil }
func (m *mbox) Check() error             { return nil }

func (m *mbox) ListMessages(uid bool, set *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	defer close(ch)
	m.s.mu.Lock()
	var out []*imap.Message
	for i, x := range m.b().msgs {
		id := uint32(i + 1)
		if uid {
			id = x.uid
		}
		if !set.Contains(id) {
			continue
		}
		f, err := x.fetch(uint32(i+1), items)
		if err == nil {
			out = append(out, f)
		}
	}
	m.s.mu.Unlock()
	for _, f := range out {
		ch <- f
	}
	return nil
}

func (x *msg) fetch(seq uint32, items []imap.FetchItem) (*imap.Message, error) {
	f := imap.NewMessage(seq, items)
	for _, it := range items {
		switch it {
		case imap.FetchFlags:
			f.Flags = append([]string(nil), x.flags...)
		case imap.FetchUid:
			f.Uid = x.uid
		case imap.FetchInternalDate:
			f.InternalDate = x.date
		case imap.FetchRFC822Size:
			f.Size = uint32(len(x.body))
		case imap.FetchEnvelope, imap.FetchBody, imap.FetchBodyStructure:
		default:
			sec, err := imap.ParseBodySectionName(it)
			if err != nil {
				continue
			}
			r := bufio.NewReader(bytes.NewReader(x.body))
			h, err := textproto.ReadHeader(r)
			if err != nil {
				return nil, err
			}
			l, err := backendutil.FetchBodySection(h, r, sec)
			if err != nil {
				return nil, err
			}
			f.Body[sec] = l
		}
	}
	return f, nil
}

func (m *mbox) SearchMessages(uid bool, c *imap.SearchCriteria) ([]uint32, error) {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	if m.s.failList[m.name] {
		return nil, errors.New("listing failed")
	}
	var out []uint32
	for i, x := range m.b().msgs {
		e, err := message.Read(bytes.NewReader(x.body))
		if err != nil && e == nil {
			continue
		}
		ok, _ := backendutil.Match(e, uint32(i+1), x.uid, x.date, x.flags, c)
		if !ok {
			continue
		}
		if uid {
			out = append(out, x.uid)
		} else {
			out = append(out, uint32(i+1))
		}
	}
	return out, nil
}

func (m *mbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	b, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	bx := m.b()
	bx.msgs = append(bx.msgs, &msg{uid: bx.next, date: date, flags: flags, body: b})
	bx.next++
	return nil
}

func (m *mbox) UpdateMessagesFlags(uid bool, set *imap.SeqSet, op imap.FlagsOp, flags []string) error {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	for i, x := range m.b().msgs {
		id := uint32(i + 1)
		if uid {
			id = x.uid
		}
		if set.Contains(id) {
			x.flags = updateFlags(x.flags, op, flags)
		}
	}
	return nil
}

func (m *mbox) CopyMessages(uid bool, set *imap.SeqSet, dest string) error {
	return m.transfer(uid, set, dest, false)
}

func (m *mbox) MoveMessages(uid bool, set *imap.SeqSet, dest string) error {
	return m.transfer(uid, set, dest, true)
}

func (m *mbox) transfer(uid bool, set *imap.SeqSet, dest string, move bool) error {
	m.s.mu.Lock()
	defer m.s.mu.Unlock()
	d, ok := m.s.boxes[dest]
	if !ok {
		return backend.ErrNoSuchMailbox
	}
	src := m.b()
	var keep []*msg
	for i, x := range src.msgs {
		id := uint32(i + 1)
		if uid {
			id = x.uid
		}
		if !set.Contains(id) {
			keep = append(keep, x)
			continue
		}
		c := *x
		c.flags = append([]string(nil), x.flags...)
		c.uid = d.next
		d.next++
		d.msgs = append(d.msgs, &c)
		if !move {
			keep = append(keep, x)
		}
	}
	src.msgs = keep
	return nil
}

func (m *mbox) Expunge() error { return errors.New("the adapter never expunges") }

// SMTP sink: EHLO, AUTH PLAIN or XOAUTH2, MAIL, RCPT, DATA, QUIT.

func (s *Server) serveSMTP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go s.smtpConn(c)
	}
}

func (s *Server) smtpConn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(f string, a ...any) { fmt.Fprintf(c, f+"\r\n", a...) }
	say("220 mailtest ESMTP")
	var sub Submission
	authed := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			say("250-mailtest")
			say("250 AUTH PLAIN XOAUTH2")
		case strings.HasPrefix(up, "AUTH "):
			f := strings.Fields(line)
			if len(f) < 3 {
				say("501 syntax")
				continue
			}
			b, _ := base64.StdEncoding.DecodeString(f[2])
			ok := false
			switch strings.ToUpper(f[1]) {
			case "PLAIN":
				p := strings.Split(string(b), "\x00")
				ok = len(p) == 3 && p[1] == User && p[2] == Password
			case "XOAUTH2":
				ok = string(b) == "user="+User+"\x01auth=Bearer "+Token+"\x01\x01"
			}
			if !ok {
				say("535 authentication failed")
				continue
			}
			authed, sub.Auth = true, strings.ToUpper(f[1])
			say("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			if !authed {
				say("530 authentication required")
				continue
			}
			sub.From = strings.Trim(line[len("MAIL FROM:"):], "<> ")
			if i := strings.Index(sub.From, ">"); i >= 0 {
				sub.From = sub.From[:i]
			}
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			sub.Rcpt = append(sub.Rcpt, strings.Trim(line[len("RCPT TO:"):], "<> "))
			say("250 ok")
		case up == "DATA":
			say("354 go ahead")
			var buf bytes.Buffer
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				buf.WriteString(strings.TrimPrefix(l, "."))
			}
			s.mu.Lock()
			fail := s.smtpFail
			if !fail {
				sub.Raw = buf.Bytes()
				s.submitted = append(s.submitted, sub)
			}
			s.mu.Unlock()
			if fail {
				say("451 try again")
			} else {
				say("250 queued")
			}
			sub = Submission{Auth: sub.Auth}
		case up == "QUIT":
			say("221 bye")
			return
		case up == "RSET", up == "NOOP":
			say("250 ok")
		default:
			say("502 not implemented")
		}
	}
}

// updateFlags applies a STORE. Flags and keywords compare without case,
// as RFC 3501 has them.
func updateFlags(cur []string, op imap.FlagsOp, flags []string) []string {
	in := func(l []string, f string) bool {
		for _, x := range l {
			if strings.EqualFold(x, f) {
				return true
			}
		}
		return false
	}
	var out []string
	switch op {
	case imap.SetFlags:
		return append(out, flags...)
	case imap.AddFlags:
		out = append(out, cur...)
		for _, f := range flags {
			if !in(out, f) {
				out = append(out, f)
			}
		}
	case imap.RemoveFlags:
		for _, f := range cur {
			if !in(flags, f) {
				out = append(out, f)
			}
		}
	}
	return out
}
