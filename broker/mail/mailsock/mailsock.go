// Package mailsock carries mail.Store over the vault process's mail
// socket, so the mailbox credential and the IMAP and SMTP clients stay in
// agentos-egress and agentosd links neither (M1).
//
// The framing is one JSON request and one JSON reply per unix
// connection. sms.sock's framing is HTTP, and this package may not link
// net/http (W1-c); it keeps SMS's convention of fixed error codes, so no
// reply carries a credential or the mail server's own words.
package mailsock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	netmail "net/mail"
	"net/textproto"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/mail"
)

// Socket is the mail socket's name in the run directory.
const Socket = "mail.sock"

// The client's errors. mail.ErrValidity comes back as itself.
var (
	ErrNotConnected = errors.New("mailsock: no mail account is set up")
	ErrLocked       = errors.New("mailsock: the vault is locked")
	ErrUnreachable  = errors.New("mailsock: the vault process did not answer")
	ErrFailed       = errors.New("mailsock: the mailbox refused or did not answer")
	ErrRefused      = errors.New("mailsock: the vault process refused the request")
)

// The wire's error codes; anything else reads as ErrUnreachable.
var codes = map[string]error{
	"not_connected": ErrNotConnected,
	"locked":        ErrLocked,
	"validity":      mail.ErrValidity,
	"failed":        ErrFailed,
	"refused":       ErrRefused,
}

func codeOf(err error) string {
	for _, c := range []string{"not_connected", "locked", "validity", "refused"} {
		if errors.Is(err, codes[c]) {
			return c
		}
	}
	return "failed"
}

const (
	maxRequest = 32 << 20 // an Append or Submit of a large message, base64
	maxReply   = 64 << 20 // a Fetch of many bounded messages
	// callTimeout bounds one call in the vault process; imapsmtp's own
	// per-operation timeout is 60 s.
	callTimeout = 90 * time.Second
	// readTimeout bounds how long a connection may take to send its
	// request.
	readTimeout = 10 * time.Second
)

type request struct {
	Op       string    `json:"op"`
	Folder   string    `json:"folder,omitempty"`
	Validity uint32    `json:"validity,omitempty"`
	UIDs     []uint32  `json:"uids,omitempty"`
	ID       string    `json:"id,omitempty"`
	Ref      mail.Ref  `json:"ref"`
	Add      []string  `json:"add,omitempty"`
	Remove   []string  `json:"remove,omitempty"`
	To       string    `json:"to,omitempty"`
	Flags    []string  `json:"flags,omitempty"`
	Date     time.Time `json:"date"`
	Raw      []byte    `json:"raw,omitempty"`
	Rcpt     []string  `json:"rcpt,omitempty"`
}

type reply struct {
	Error    string         `json:"error,omitempty"`
	Folders  []mail.Folder  `json:"folders,omitempty"`
	Validity uint32         `json:"validity,omitempty"`
	UIDs     []uint32       `json:"uids,omitempty"`
	Messages []mail.Message `json:"messages,omitempty"`
}

// Account is the mailbox the vault process serves: a Store holding the
// credential, and the owner's address, the only one Submit sends as.
type Account struct {
	Store   mail.Store
	Address string
}

// Source returns the account for one call. It fails with ErrNotConnected
// when none is set up and ErrLocked while the vault is locked.
type Source func() (Account, error)

// ServeConn answers one request on conn from src's account and closes
// conn. It runs in the vault process.
func ServeConn(conn net.Conn, src Source) {
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	var req request
	if err := json.NewDecoder(io.LimitReader(conn, maxRequest)).Decode(&req); err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	conn.SetWriteDeadline(time.Now().Add(callTimeout + readTimeout))
	json.NewEncoder(conn).Encode(answer(ctx, req, src))
}

// answer is call's reply as the wire carries it. A panic in the Store
// costs only its own call, answered "failed" without its value, so the
// vault process keeps serving.
func answer(ctx context.Context, req request, src Source) (rep reply) {
	defer func() {
		if recover() != nil {
			rep = reply{Error: codeOf(ErrFailed)}
		}
	}()
	rep, err := call(ctx, req, src)
	if err != nil {
		rep = reply{Error: codeOf(err)}
	}
	return rep
}

func call(ctx context.Context, req request, src Source) (reply, error) {
	acct, err := src()
	if err != nil {
		return reply{}, err
	}
	s := acct.Store
	var rep reply
	switch req.Op {
	case "folders":
		rep.Folders, err = s.Folders(ctx)
	case "uids":
		rep.Validity, rep.UIDs, err = s.UIDs(ctx, req.Folder)
	case "fetch":
		rep.Messages, err = s.Fetch(ctx, req.Folder, req.Validity, req.UIDs)
	case "find":
		rep.Messages, err = s.Find(ctx, req.Folder, req.ID)
	case "set_flags":
		err = s.SetFlags(ctx, req.Ref, req.Add, req.Remove)
	case "move":
		err = s.Move(ctx, req.Ref, req.To)
	case "ensure":
		err = s.Ensure(ctx, req.Folder)
	case "append":
		err = s.Append(ctx, req.Folder, req.Flags, req.Date, req.Raw)
	case "submit":
		if !ownSender(req.Raw, acct.Address) || len(req.Rcpt) == 0 {
			return reply{}, ErrRefused
		}
		err = s.Submit(ctx, req.Rcpt, req.Raw)
	default:
		return reply{}, ErrRefused
	}
	return rep, err
}

// ownSender reports whether raw's header sends as address alone: one
// From field naming only it, any Sender naming only it, and no Resent-
// fields, so the agent cannot send as another address through the
// owner's account. Every field name must be plain ftext in canonical
// form, and no value may hold a CR, LF or NUL: net/mail keys "From :"
// apart from From and keeps "a\rFrom: x" as one value, but a lax reader
// downstream may take either for a second From.
func ownSender(raw []byte, address string) bool {
	m, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil || address == "" {
		return false
	}
	for k, vs := range m.Header {
		if k == "" || k != textproto.CanonicalMIMEHeaderKey(k) {
			return false
		}
		for _, v := range vs {
			if strings.ContainsAny(v, "\r\n\x00") {
				return false
			}
		}
		for i := 0; i < len(k); i++ {
			if k[i] <= ' ' || k[i] >= 0x7f {
				return false
			}
		}
	}
	only := func(field string, need bool) bool {
		vs := m.Header[field]
		if len(vs) == 0 {
			return !need
		}
		if len(vs) != 1 {
			return false
		}
		as, err := netmail.ParseAddressList(vs[0])
		return err == nil && len(as) == 1 && strings.EqualFold(as[0].Address, address)
	}
	for k := range m.Header {
		if strings.HasPrefix(k, "Resent-") {
			return false
		}
	}
	return only("From", true) && only("Sender", false)
}

// Client is a mail.Store over the mail socket. Each call is one
// connection, so a call cancelled mid-way leaves nothing behind.
type Client struct{ path string }

var _ mail.Store = (*Client)(nil)

// NewClient returns a Client for the mail socket at path.
func NewClient(path string) *Client { return &Client{path: path} }

// defaultTimeout bounds a call whose context has no deadline.
const defaultTimeout = callTimeout + readTimeout

func (c *Client) do(ctx context.Context, req request) (reply, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.path)
	if err != nil {
		return reply{}, ErrUnreachable
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return reply{}, ErrUnreachable
	}
	var rep reply
	if err := json.NewDecoder(io.LimitReader(conn, maxReply)).Decode(&rep); err != nil {
		return reply{}, ErrUnreachable
	}
	if rep.Error != "" {
		if e, ok := codes[rep.Error]; ok {
			return reply{}, e
		}
		return reply{}, ErrUnreachable
	}
	return rep, nil
}

func (c *Client) Folders(ctx context.Context) ([]mail.Folder, error) {
	rep, err := c.do(ctx, request{Op: "folders"})
	return rep.Folders, err
}

func (c *Client) UIDs(ctx context.Context, folder string) (uint32, []uint32, error) {
	rep, err := c.do(ctx, request{Op: "uids", Folder: folder})
	return rep.Validity, rep.UIDs, err
}

func (c *Client) Fetch(ctx context.Context, folder string, validity uint32, uids []uint32) ([]mail.Message, error) {
	rep, err := c.do(ctx, request{Op: "fetch", Folder: folder, Validity: validity, UIDs: uids})
	return rep.Messages, err
}

func (c *Client) Find(ctx context.Context, folder, id string) ([]mail.Message, error) {
	rep, err := c.do(ctx, request{Op: "find", Folder: folder, ID: id})
	return rep.Messages, err
}

func (c *Client) SetFlags(ctx context.Context, m mail.Ref, add, remove []string) error {
	_, err := c.do(ctx, request{Op: "set_flags", Ref: m, Add: add, Remove: remove})
	return err
}

func (c *Client) Move(ctx context.Context, m mail.Ref, to string) error {
	_, err := c.do(ctx, request{Op: "move", Ref: m, To: to})
	return err
}

func (c *Client) Ensure(ctx context.Context, folder string) error {
	_, err := c.do(ctx, request{Op: "ensure", Folder: folder})
	return err
}

func (c *Client) Append(ctx context.Context, folder string, flags []string, date time.Time, raw []byte) error {
	_, err := c.do(ctx, request{Op: "append", Folder: folder, Flags: flags, Date: date, Raw: raw})
	return err
}

func (c *Client) Submit(ctx context.Context, rcpt []string, raw []byte) error {
	_, err := c.do(ctx, request{Op: "submit", Rcpt: rcpt, Raw: raw})
	return err
}
