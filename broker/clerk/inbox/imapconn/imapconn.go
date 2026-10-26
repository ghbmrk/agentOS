// Package imapconn is the mail clerk's IMAP connection process (KRN-2,
// #2937 gap 2): the only place go-imap parses a mail server's replies. It
// serves one session. The clerk signs in itself, hands over one end of a
// socketpair carrying the signed-in stream, and relays that stream to the
// server; this side reads one typed request at a time from the control
// connection, runs it with go-imap over the stream, and answers typed data
// (imapwire). It holds no credential, dials nothing and links nothing of
// the clerk's: everything it answers, the clerk checks.
//
// It reuses github.com/emersion/go-imap (v1, MIT) as the IMAP client.
package imapconn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
	"unicode"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-imap/commands"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapwire"
)

// maxRequest bounds a request frame; an Append's message is the largest.
const maxRequest = 64 << 20

// Serve serves one session on ctrl: it takes the stream from the first
// message's descriptor, then answers requests until ctrl closes.
func Serve(ctrl *net.UnixConn) error {
	defer ctrl.Close()
	stream, err := recvStream(ctrl)
	if err != nil {
		return err
	}
	defer stream.Close()
	c, err := client.New(stream)
	if err != nil {
		return err
	}
	c.ErrorLog = quiet{}
	for {
		var req imapwire.Request
		if err := imapwire.Read(ctrl, maxRequest, &req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := imapwire.Write(ctrl, Handle(c, req)); err != nil {
			return err
		}
	}
}

// recvStream is the stream end the clerk passed with its first byte.
func recvStream(ctrl *net.UnixConn) (net.Conn, error) {
	b, oob := make([]byte, 1), make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := ctrl.ReadMsgUnix(b, oob)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		return nil, errors.New("imapconn: no stream was passed")
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		return nil, errors.New("imapconn: no stream was passed")
	}
	f := os.NewFile(uintptr(fds[0]), "imap-stream")
	defer f.Close()
	return net.FileConn(f)
}

// Pipe serves each session on a goroutine of this process, over a
// socketpair, for tests, the eval runner and the old core (CLK-1's process
// launch is the clerk main's, #2995).
func Pipe() func(context.Context) (*net.UnixConn, error) {
	return func(context.Context) (*net.UnixConn, error) {
		mine, theirs, err := Socketpair()
		if err != nil {
			return nil, err
		}
		go Serve(theirs)
		return mine, nil
	}
}

// Socketpair is a connected pair of stream Unix sockets.
func Socketpair() (*net.UnixConn, *net.UnixConn, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	var out [2]*net.UnixConn
	for i, fd := range fds {
		f := os.NewFile(uintptr(fd), "socketpair")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			if i == 1 {
				out[0].Close()
			} else {
				syscall.Close(fds[1])
			}
			return nil, nil, err
		}
		out[i] = c.(*net.UnixConn)
	}
	return out[0], out[1], nil
}

type quiet struct{}

func (quiet) Printf(string, ...interface{}) {}
func (quiet) Println(...interface{})        {}

// Handle runs one request on a signed-in client: Serve's step, exported
// so the clerk's fuzz target (imapsmtp.FuzzIMAPReplies) can drive it over a
// pipe.
func Handle(c *client.Client, q imapwire.Request) (r imapwire.Response) {
	var err error
	switch q.Op {
	case imapwire.OpFolders:
		r.Folders, err = folders(c)
	case imapwire.OpUIDs:
		r.Validity, r.UIDs, err = uids(c, q.Folder)
	case imapwire.OpFetch:
		if err = selectAt(c, q.Folder, true, q.Validity); err == nil {
			r.Messages, err = fetch(c, q.Folder, q.Validity, q.UIDs, q.MaxFetch)
		}
	case imapwire.OpSeenSearch:
		var st *imap.MailboxStatus
		if st, err = c.Select(q.Folder, true); err == nil && st.Messages > 0 {
			r.UIDs, err = readUIDs(c, nil)
		}
	case imapwire.OpSeenBatch:
		r.Heads, r.Long, err = seenBatch(c, q.Folder, q.UIDs)
	case imapwire.OpSubject:
		r.Subject = subject(c, firstUID(q.UIDs))
	case imapwire.OpNext:
		r.Validity, r.Next, err = next(c, q.Folder)
	case imapwire.OpFind:
		r.Validity, r.Messages, err = find(c, q.Folder, q.Validity, q.From, q.ID, q.MaxFetch)
	case imapwire.OpSetFlags:
		err = setFlags(c, imapwire.Ref{Folder: q.Folder, Validity: q.Validity, UID: firstUID(q.UIDs)}, q.Add, q.Remove)
	case imapwire.OpMove:
		err = move(c, imapwire.Ref{Folder: q.Folder, Validity: q.Validity, UID: firstUID(q.UIDs)}, q.To)
	case imapwire.OpMarks:
		r.Marks, err = marks(c)
	case imapwire.OpEnsure:
		err = ensure(c, q.Folder)
	case imapwire.OpDates:
		if err = selectAt(c, q.Folder, true, q.Validity); err == nil {
			r.Heads, err = dates(c, q.UIDs)
		}
	case imapwire.OpPlanHeads:
		if err = selectAt(c, q.Folder, true, q.Validity); err == nil {
			r.Heads, err = planHeads(c, q.UIDs)
		}
	case imapwire.OpAppend:
		err = c.Append(q.Folder, q.Flags, q.Date, bytes.NewBuffer(q.Raw))
	default:
		err = errors.New("imapconn: unknown request")
	}
	r.Err = imapwire.Code(err)
	return r
}

func firstUID(u []uint32) uint32 {
	if len(u) != 1 {
		return 0
	}
	return u[0]
}

// folders lists the selectable folders in session c.
func folders(c *client.Client) ([]imapwire.Folder, error) {
	var out []imapwire.Folder
	ch := make(chan *imap.MailboxInfo, 32)
	done := make(chan error, 1)
	go func() { done <- c.List("", "*", ch) }()
	for m := range ch {
		if has(m.Attributes, imap.NoSelectAttr) {
			continue
		}
		out = append(out, imapwire.Folder{Name: m.Name, Role: role(m)})
	}
	return out, <-done
}

func role(m *imap.MailboxInfo) imapwire.Role {
	if strings.EqualFold(m.Name, "INBOX") {
		return imapwire.Inbox
	}
	for a, r := range map[string]imapwire.Role{imap.ArchiveAttr: imapwire.Archive, imap.DraftsAttr: imapwire.Drafts,
		imap.SentAttr: imapwire.Sent, imap.TrashAttr: imapwire.Trash, imap.JunkAttr: imapwire.Junk, imap.AllAttr: imapwire.All} {
		if has(m.Attributes, a) {
			return r
		}
	}
	return ""
}

func has(l []string, s string) bool {
	for _, x := range l {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// uids lists every message in folder.
func uids(c *client.Client, folder string) (uint32, []uint32, error) {
	st, err := c.Select(folder, true)
	if err != nil {
		return 0, nil, err
	}
	if st.Messages == 0 {
		return st.UidValidity, nil, nil
	}
	u, err := c.UidSearch(imap.NewSearchCriteria())
	return st.UidValidity, u, err
}

// selectAt selects folder and refuses (ErrValidity) unless its UID
// validity is the expected one: under another validity the UIDs the
// caller holds may name other messages. The check and what follows run
// in this one selected session.
func selectAt(c *client.Client, folder string, readOnly bool, validity uint32) error {
	st, err := c.Select(folder, readOnly)
	if err != nil {
		return err
	}
	if validity == 0 || st.UidValidity != validity {
		return imapwire.ErrValidity
	}
	return nil
}

// fetch reads messages with BODY.PEEK, so none is marked read, each up to
// max bytes.
func fetch(c *client.Client, folder string, validity uint32, uids []uint32, max int) ([]imapwire.Message, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	set := new(imap.SeqSet)
	set.AddNum(uids...)
	sec := &imap.BodySectionName{Peek: true, Partial: []int{0, max}}
	items := []imap.FetchItem{imap.FetchUid, imap.FetchFlags, sec.FetchItem()}
	ch := make(chan *imap.Message, 16)
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(set, items, ch) }()
	// Only the first response with a body for each requested UID is kept,
	// so a server that repeats or invents messages cannot grow out, and an
	// unsolicited FLAGS-only response does not take the slot (SR3-mail-k18b).
	want := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		want[u] = true
	}
	var out []imapwire.Message
	for m := range ch {
		if !want[m.Uid] || len(m.Body) == 0 {
			continue
		}
		delete(want, m.Uid)
		var raw []byte
		for _, l := range m.Body {
			if l != nil {
				raw, _ = io.ReadAll(l)
				break
			}
		}
		out = append(out, imapwire.Message{Ref: imapwire.Ref{Folder: folder, Validity: validity, UID: m.Uid},
			Flags: append([]string(nil), m.Flags...), Raw: raw})
	}
	return out, <-done
}

// HeadMax bounds the From and Message-ID headers a Seen batch reads of each
// message, and SubjectMax the Subject a LongHeaderError reads.
const (
	HeadMax    = 8 << 10
	SubjectMax = 1 << 10
)

// seenBatch reads the From and Message-ID headers of uids in the selected
// folder, with BODY.PEEK[HEADER.FIELDS (FROM MESSAGE-ID)] so nothing is
// marked read, and each one's INTERNALDATE, in the order the server sends
// them. A header longer than HeadMax ends the batch; the clerk then asks
// for its Subject (OpSubject) within the batch's budget and timeout. A searched message that did not answer is searched for again,
// and only one the owner deleted or marked unread since is let go.
func seenBatch(c *client.Client, folder string, uids []uint32) ([]imapwire.Head, *imapwire.LongHeaderError, error) {
	sec := &imap.BodySectionName{Peek: true, Partial: []int{0, HeadMax + 1},
		BodyPartName: imap.BodyPartName{Specifier: imap.HeaderSpecifier, Fields: []string{"From", "Message-Id"}}}
	items := []imap.FetchItem{imap.FetchUid, imap.FetchInternalDate, sec.FetchItem()}
	want := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		want[u] = true
	}
	set := new(imap.SeqSet)
	set.AddNum(uids...)
	ch := make(chan *imap.Message, 16)
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(set, items, ch) }()
	// As in fetch: one header per requested UID, so a server that repeats
	// or invents messages adds nothing.
	var out []imapwire.Head
	var long *imapwire.LongHeaderError
	for m := range ch {
		if long != nil || !want[m.Uid] {
			continue
		}
		for _, l := range m.Body {
			if l == nil {
				continue
			}
			delete(want, m.Uid)
			h, _ := io.ReadAll(io.LimitReader(l, HeadMax+1))
			if len(h) > HeadMax {
				long = &imapwire.LongHeaderError{Folder: folder, Arrived: m.InternalDate, UID: m.Uid}
			} else {
				out = append(out, imapwire.Head{UID: m.Uid, Header: h, Arrived: m.InternalDate})
			}
			break
		}
	}
	if err := <-done; err != nil {
		return out, nil, err
	}
	if long != nil {
		return out, long, imapwire.ErrLongHeader
	}
	if len(want) > 0 {
		left, err := readUIDs(c, want)
		if err != nil {
			return out, nil, err
		}
		if len(left) > 0 {
			return out, nil, imapwire.ErrUnanswered
		}
	}
	return out, nil, nil
}

// dates is the INTERNALDATE of each of uids in the selected folder: what
// the account plan orders mails by across folders, read with no body.
func dates(c *client.Client, uids []uint32) ([]imapwire.Head, error) {
	return heads(c, uids, []imap.FetchItem{imap.FetchUid, imap.FetchInternalDate}, nil)
}

// planHeads is the From and Authentication-Results header fields of each
// of uids in the selected folder, with BODY.PEEK[HEADER.FIELDS (FROM
// AUTHENTICATION-RESULTS)] so nothing is marked read: all the account plan
// reads of a mail (TN-account-plan). A mail whose fields pass HeadMax is
// left out, as is one gone since it was listed: the plan skips both.
func planHeads(c *client.Client, uids []uint32) ([]imapwire.Head, error) {
	sec := &imap.BodySectionName{Peek: true, Partial: []int{0, HeadMax + 1},
		BodyPartName: imap.BodyPartName{Specifier: imap.HeaderSpecifier, Fields: []string{"From", "Authentication-Results"}}}
	return heads(c, uids, []imap.FetchItem{imap.FetchUid, sec.FetchItem()}, sec)
}

// heads fetches items of uids in the selected folder: one Head per
// requested UID, the first the server sends, so a server that repeats or
// invents messages adds nothing. With sec, the one section items ask for, a
// Head holds it, and a message that sent none, or more than HeadMax bytes
// of it, has no Head.
func heads(c *client.Client, uids []uint32, items []imap.FetchItem, sec *imap.BodySectionName) ([]imapwire.Head, error) {
	if len(uids) == 0 {
		return nil, nil
	}
	set := new(imap.SeqSet)
	set.AddNum(uids...)
	want := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		want[u] = true
	}
	ch := make(chan *imap.Message, 16)
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(set, items, ch) }()
	var out []imapwire.Head
	for m := range ch {
		if !want[m.Uid] {
			continue
		}
		if sec == nil {
			delete(want, m.Uid)
			out = append(out, imapwire.Head{UID: m.Uid, Arrived: m.InternalDate})
			continue
		}
		var l imap.Literal
		for _, b := range m.Body {
			if b != nil {
				l = b
				break
			}
		}
		if l == nil {
			continue
		}
		delete(want, m.Uid)
		if h, _ := io.ReadAll(io.LimitReader(l, HeadMax+1)); len(h) <= HeadMax {
			out = append(out, imapwire.Head{UID: m.Uid, Header: h})
		}
	}
	return out, <-done
}

// subject is mail uid's Subject header, unfolded and decoded, read with
// BODY.PEEK under SubjectMax bytes; one cut there ends in "…". A failed read
// leaves it empty: the error it names stands without it.
func subject(c *client.Client, uid uint32) string {
	sec := &imap.BodySectionName{Peek: true, Partial: []int{0, SubjectMax + 1},
		BodyPartName: imap.BodyPartName{Specifier: imap.HeaderSpecifier, Fields: []string{"Subject"}}}
	set := new(imap.SeqSet)
	set.AddNum(uid)
	ch := make(chan *imap.Message, 4)
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(set, []imap.FetchItem{imap.FetchUid, sec.FetchItem()}, ch) }()
	// The client passes on only answers for uid; the first stands.
	var h []byte
	for m := range ch {
		for _, l := range m.Body {
			if l != nil && h == nil {
				h, _ = io.ReadAll(io.LimitReader(l, SubjectMax+1))
			}
		}
	}
	if <-done != nil {
		return ""
	}
	cut := len(h) > SubjectMax
	v := string(h[:min(len(h), SubjectMax)])
	if name, rest, ok := strings.Cut(v, ":"); !ok || !strings.EqualFold(strings.TrimSpace(name), "Subject") {
		return ""
	} else {
		v = rest
	}
	// A cut inside an encoded word, =?charset?encoding?text?=, leaves it
	// undecodable: it goes, rather than show the owner its raw form.
	if i := strings.LastIndex(v, "=?"); cut && i >= 0 {
		if p := strings.SplitN(v[i+2:], "?", 4); len(p) < 4 || !strings.HasPrefix(p[3], "=") {
			v = v[:i]
		}
	}
	if d, err := new(mime.WordDecoder).DecodeHeader(v); err == nil {
		v = d
	}
	v = Plain(v)
	if cut {
		v += "…"
	}
	return v
}

// Plain is v as one line the owner can read: valid UTF-8, no control or
// bidi character (the sender wrote it, so none may break or reorder the
// owner's line), runs of space as one. The clerk applies it again to what
// this process answers.
func Plain(v string) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return ' '
		}
		return r
	}, strings.ToValidUTF8(v, ""))
	return strings.Join(strings.Fields(v), " ")
}

// readUIDs searches the selected folder for its read mail: all of it, or,
// given only, those of its UIDs still there and still read.
func readUIDs(c *client.Client, only map[uint32]bool) ([]uint32, error) {
	crit := imap.NewSearchCriteria()
	crit.WithFlags = []string{imap.SeenFlag}
	if only != nil {
		crit.Uid = new(imap.SeqSet)
		for u := range only {
			crit.Uid.AddNum(u)
		}
	}
	uids, err := c.UidSearch(crit)
	if only == nil || err != nil {
		return uids, err
	}
	return slices.DeleteFunc(uids, func(u uint32) bool { return !only[u] }), nil
}

// next is folder's UID validity and the UID its next message will take.
func next(c *client.Client, folder string) (uint32, uint32, error) {
	st, err := c.Select(folder, true)
	if err != nil {
		return 0, 0, err
	}
	if st.UidValidity == 0 || st.UidNext == 0 {
		return 0, 0, imapwire.ErrNoUIDNext
	}
	return st.UidValidity, st.UidNext, nil
}

// find returns the folder's validity and the messages in it whose
// Message-ID header holds id, from UID from on under validity unless
// validity is 0. Servers match a header search by substring; the clerk
// checks the whole value.
func find(c *client.Client, folder string, validity, from uint32, id string, max int) (uint32, []imapwire.Message, error) {
	st, err := c.Select(folder, true)
	if err != nil {
		return 0, nil, err
	}
	if validity != 0 && st.UidValidity != validity {
		return 0, nil, imapwire.ErrValidity
	}
	crit := imap.NewSearchCriteria()
	crit.Header.Add("Message-Id", id)
	if validity != 0 {
		crit.Uid = new(imap.SeqSet)
		crit.Uid.AddRange(max32(from, 1), 0)
	}
	uids, err := c.UidSearch(crit)
	// from:* holds the folder's last UID even when it is below from.
	uids = slices.DeleteFunc(uids, func(u uint32) bool { return u < from })
	if err != nil || len(uids) == 0 {
		return st.UidValidity, nil, err
	}
	ms, err := fetch(c, folder, st.UidValidity, uids, max)
	return st.UidValidity, ms, err
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

// setFlags adds and removes flags on one message, only while its folder
// has the UID validity m was read under. The clerk checked the flags.
func setFlags(c *client.Client, m imapwire.Ref, add, remove []string) error {
	if err := selectAt(c, m.Folder, false, m.Validity); err != nil {
		return err
	}
	set := new(imap.SeqSet)
	set.AddNum(m.UID)
	for _, x := range []struct {
		op    imap.FlagsOp
		flags []string
	}{{imap.AddFlags, add}, {imap.RemoveFlags, remove}} {
		if len(x.flags) == 0 {
			continue
		}
		v := make([]interface{}, len(x.flags))
		for i, f := range x.flags {
			v[i] = f
		}
		if err := c.UidStore(set, imap.FormatFlagsOp(x.op, true), v, nil); err != nil {
			return err
		}
	}
	return nil
}

// move moves one message. Servers without MOVE are refused rather than
// emulated with COPY, flag and EXPUNGE: an EXPUNGE would also remove
// anything else the owner had marked deleted in that folder. Like
// setFlags it acts only under the UID validity m was read under.
func move(c *client.Client, m imapwire.Ref, to string) error {
	if ok, _ := c.Support("MOVE"); !ok {
		return imapwire.ErrNoMove
	}
	if err := selectAt(c, m.Folder, false, m.Validity); err != nil {
		return err
	}
	set := new(imap.SeqSet)
	set.AddNum(m.UID)
	// UID MOVE itself, never go-imap's COPY, STORE and EXPUNGE fallback.
	st, err := c.Execute(&commands.Uid{Cmd: &commands.Move{SeqSet: set, Mailbox: to}}, nil)
	if err != nil {
		return err
	}
	return st.Err()
}

// marks is the Mark of each selectable folder, sorted by name, listed and
// read in one session.
func marks(c *client.Client) ([]imapwire.Mark, error) {
	fs, err := folders(c)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(fs))
	for i, f := range fs {
		names[i] = f.Name
	}
	slices.Sort(names)
	items := []imap.StatusItem{imap.StatusUidValidity, imap.StatusUidNext, imap.StatusMessages, imap.StatusUnseen}
	if ok, _ := c.Support("CONDSTORE"); ok {
		items = append(items, "HIGHESTMODSEQ")
	}
	var out []imapwire.Mark
	for _, f := range names {
		st, err := c.Status(f, items)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			if _, ok := st.Items[it]; !ok {
				return nil, fmt.Errorf("%w: %s in %q", imapwire.ErrPartialStatus, it, f)
			}
		}
		m := imapwire.Mark{Folder: f, Validity: st.UidValidity, Next: st.UidNext, Messages: st.Messages, Unseen: st.Unseen}
		if v := st.Items["HIGHESTMODSEQ"]; v != nil {
			m.ModSeq = fmt.Sprint(v)
		}
		out = append(out, m)
	}
	return out, nil
}

// ensure creates folder if it does not exist.
func ensure(c *client.Client, folder string) error {
	ch := make(chan *imap.MailboxInfo, 4)
	done := make(chan error, 1)
	go func() { done <- c.List("", folder, ch) }()
	found := false
	for m := range ch {
		found = found || m.Name == folder
	}
	if err := <-done; err != nil {
		return err
	}
	if found {
		return nil
	}
	return c.Create(folder)
}
