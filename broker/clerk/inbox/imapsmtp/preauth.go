package imapsmtp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
)

// The pre-auth reader is the only IMAP this side reads (CLK-1, KRN-2): the
// greeting, a CAPABILITY listing and the sign-in's tagged answer. It reads
// lines of at most preauthLine bytes, at most preauthLines of them, accepts
// no literal and decodes no challenge: an XOAUTH2 failure challenge is
// answered with an empty line, unread.
const (
	preauthLine  = 8 << 10
	preauthLines = 256
)

var (
	errPreauthLine    = errors.New("imapsmtp: the server's line before sign-in is too long")
	errPreauthLiteral = errors.New("imapsmtp: the server sent a literal before sign-in")
	errPreauthLines   = errors.New("imapsmtp: the server sent too many lines before sign-in")
	errGreeting       = errors.New("imapsmtp: the server did not greet the session")
	errNoSay          = errors.New("imapsmtp: the server did not say how to sign in")
)

// preauth reads and writes one connection before sign-in.
type preauth struct {
	w    io.Writer
	r    *bufio.Reader
	n    int
	caps map[string]bool // upper-cased; nil until the server lists them
	// authed is set once the sign-in is sent, and fresh once the server
	// lists its capabilities after that.
	authed, fresh bool
}

// line is the server's next line without its CRLF.
func (p *preauth) line() (string, error) {
	if p.n++; p.n > preauthLines {
		return "", errPreauthLines
	}
	b, err := p.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errPreauthLine
	}
	if err != nil {
		return "", err
	}
	if _, ok := literal(b); ok {
		return "", errPreauthLiteral
	}
	return string(bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r"))), nil
}

// capsFrom records the capabilities a "[CAPABILITY ...]" code or a
// "* CAPABILITY ..." line lists in s.
func (p *preauth) capsFrom(list string) {
	p.fresh = p.authed
	p.caps = map[string]bool{}
	for _, c := range strings.Fields(list) {
		p.caps[strings.ToUpper(c)] = true
	}
}

// code is the response code that opens text, "[CODE args]", as its name
// and arguments.
func code(text string) (string, string) {
	if !strings.HasPrefix(text, "[") {
		return "", ""
	}
	c, _, ok := strings.Cut(text[1:], "]")
	if !ok {
		return "", ""
	}
	name, args, _ := strings.Cut(c, " ")
	return strings.ToUpper(name), args
}

// exchange sends a tagged command and reads to its tagged answer, recording
// any capability listing and answering each continuation with cont. It is
// the answer's status (OK, NO or BAD) and the rest of its line.
func (p *preauth) exchange(tag, cmd string, cont func() error) (string, string, error) {
	if _, err := io.WriteString(p.w, tag+" "+cmd+"\r\n"); err != nil {
		return "", "", err
	}
	for {
		l, err := p.line()
		if err != nil {
			return "", "", err
		}
		switch {
		case strings.HasPrefix(l, tag+" "):
			status, text, _ := strings.Cut(l[len(tag)+1:], " ")
			if name, args := code(text); name == "CAPABILITY" {
				p.capsFrom(args)
			}
			return strings.ToUpper(status), text, nil
		case l == "+" || strings.HasPrefix(l, "+ "):
			if cont == nil {
				return "", "", errSignIn
			}
			if err := cont(); err != nil {
				return "", "", err
			}
		case len(l) > 13 && strings.EqualFold(l[:13], "* CAPABILITY "):
			p.capsFrom(l[13:])
		}
	}
}

// signIn reads the greeting and signs in on conn as the account's login
// asks: XOAUTH2 for a token; LOGIN for a password, or AUTHENTICATE PLAIN
// where the server says LOGINDISABLED. It is ErrNoSignIn when the server
// offers neither, before any login is sent, and ErrLoginRefused when the
// server refused it: a NO or BAD other than UNAVAILABLE (RFC 5530: the
// server is down for now). Any other failure passes with time.
//
// It returns the server's capabilities as of the signed-in state, which
// go-imap is handed in the synthetic greeting and the filter reads
// (LITERAL+): from the sign-in's answer, or a CAPABILITY sent after it,
// or, where the server answers neither, the list from before.
func (s *Store) signIn(ctx context.Context, conn io.Writer, br *bufio.Reader) (map[string]bool, error) {
	p := &preauth{w: conn, r: br}
	if err := s.authenticate(ctx, p); err != nil {
		return nil, err
	}
	if !p.fresh {
		p.authed = true
		if _, _, err := p.exchange("A3", "CAPABILITY", nil); err != nil {
			return nil, err
		}
	}
	return p.caps, nil
}

// authenticate is signIn's greeting and sign-in on p.
func (s *Store) authenticate(ctx context.Context, p *preauth) error {
	conn := p.w
	g, err := p.line()
	if err != nil {
		return err
	}
	kind, text, _ := strings.Cut(strings.TrimPrefix(g, "* "), " ")
	if !strings.HasPrefix(g, "* ") || !strings.EqualFold(kind, "OK") && !strings.EqualFold(kind, "PREAUTH") {
		return errGreeting
	}
	if name, args := code(text); name == "CAPABILITY" {
		p.capsFrom(args)
	}
	if strings.EqualFold(kind, "PREAUTH") {
		p.fresh = true
		return nil
	}
	if p.caps == nil {
		if st, _, err := p.exchange("A1", "CAPABILITY", nil); err != nil || st != "OK" || p.caps == nil {
			return errNoSay
		}
	}
	l, err := s.cfg.Credential(ctx)
	if err != nil {
		return errors.New("imapsmtp: no credential")
	}
	p.authed = true
	var cmd string
	var ir []byte
	switch {
	case l.OAuth && p.caps["AUTH=XOAUTH2"]:
		cmd, ir = "AUTHENTICATE XOAUTH2", xoauth2{l.User, l.Secret}.ir()
	case !l.OAuth && p.caps["LOGINDISABLED"] && p.caps["AUTH=PLAIN"]:
		cmd, ir = "AUTHENTICATE PLAIN", []byte("\x00"+l.User+"\x00"+l.Secret)
	case !l.OAuth && !p.caps["LOGINDISABLED"]:
		return s.login(p, l)
	default:
		return stand{side(ErrNoSignIn, Reading)}
	}
	enc := base64.StdEncoding.EncodeToString(ir)
	sent := p.caps["SASL-IR"]
	if sent {
		cmd += " " + enc
	}
	conts := 0
	st, text, err := p.exchange("A2", cmd, func() error {
		// The initial response if the server asked for it; then the empty
		// line that ends a failed exchange, its challenge unread.
		if conts++; conts > 2 {
			return errSignIn
		}
		answer := "\r\n"
		if !sent {
			answer, sent = enc+"\r\n", true
		}
		_, err := io.WriteString(conn, answer)
		return err
	})
	return signedIn(st, text, err)
}

// login signs in with LOGIN, both arguments quoted strings, or both
// synchronizing literals where one holds a byte a quoted string cannot.
func (s *Store) login(p *preauth, l Login) error {
	if !quotable(l.User) || !quotable(l.Secret) {
		return s.loginLiterals(p, l)
	}
	q := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	st, text, err := p.exchange("A2", `LOGIN "`+q.Replace(l.User)+`" "`+q.Replace(l.Secret)+`"`, nil)
	return signedIn(st, text, err)
}

// loginLiterals sends LOGIN with both arguments as synchronizing literals.
func (s *Store) loginLiterals(p *preauth, l Login) error {
	if _, err := io.WriteString(p.w, "A2 LOGIN {"+strconv.Itoa(len(l.User))+"}\r\n"); err != nil {
		return err
	}
	step := 0
	for {
		ln, err := p.line()
		if err != nil {
			return signedIn("", "", err)
		}
		switch {
		case strings.HasPrefix(ln, "A2 "):
			status, text, _ := strings.Cut(ln[3:], " ")
			return signedIn(strings.ToUpper(status), text, nil)
		case ln == "+" || strings.HasPrefix(ln, "+ "):
			var out string
			switch step {
			case 0:
				out = l.User + " {" + strconv.Itoa(len(l.Secret)) + "}\r\n"
			case 1:
				out = l.Secret + "\r\n"
			default:
				return errSignIn
			}
			step++
			if _, err := io.WriteString(p.w, out); err != nil {
				return err
			}
		}
	}
}

// quotable says whether a can go as an IMAP quoted string: 7-bit, with
// no NUL, CR or LF.
func quotable(a string) bool {
	for i := 0; i < len(a); i++ {
		if c := a[i]; c == 0 || c == '\r' || c == '\n' || c >= 0x80 {
			return false
		}
	}
	return true
}

// signedIn is the sign-in's error from its tagged answer.
func signedIn(status, text string, err error) error {
	switch {
	case err != nil:
		return errSignIn
	case status == "OK":
		return nil
	case status == "NO" || status == "BAD":
		if name, _ := code(text); name == "UNAVAILABLE" {
			return errSignIn
		}
		return stand{side(ErrLoginRefused, Reading)}
	}
	return errSignIn
}
