package imapsmtp

// REQ: VRB-2 (assumption MIG-4-mail-reader-5)

import (
	"bufio"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const imapGreet, smtpGreet = "* OK [CAPABILITY IMAP4rev1] ready\r\n", "220 x.test ready\r\n"

// script is what a mail server says to one connection: greet, the AUTH
// mechanisms its EHLO offers, the capabilities an IMAP CAPABILITY lists
// ("NO" refuses it, "drop" closes the connection), its answer to the sign-in
// (a LOGIN, AUTHENTICATE or AUTH line; an IMAP answer goes after the
// command's tag), and its answer to an SMTP QUIT. A sign-in answer "drop" closes the
// connection, "stall" leaves it unanswered, and "challenge:" sends an
// error challenge first and the rest after the client's response. A quit
// "stall" leaves a QUIT or an IMAP LOGOUT unanswered.
type script struct {
	greet, mechs, caps, signIn, quit string
}

// serve takes one connection and plays sc: an SMTP server answers NOOP,
// cancels a sign-in on "*" and takes a mail; an IMAP server ends at LOGOUT.
func serve(t *testing.T, sc script) string {
	t.Helper()
	if sc.quit == "" {
		sc.quit = "221 bye"
	}
	l := listenLoopback(t)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		w := bufio.NewWriter(c)
		say := func(s string) { w.WriteString(s); w.Flush() }
		say(sc.greet)
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			f := strings.Fields(line)
			switch {
			case len(f) > 1 && strings.EqualFold(f[1], "LOGOUT"):
				if sc.quit == "stall" {
					r.ReadString('\n')
					return
				}
				say("* BYE\r\n" + f[0] + " OK bye\r\n")
				return
			case len(f) > 1 && strings.EqualFold(f[1], "CAPABILITY"):
				switch sc.caps {
				case "drop":
					return
				case "NO":
					say(f[0] + " NO not now\r\n")
				default:
					say("* CAPABILITY " + sc.caps + "\r\n" + f[0] + " OK listed\r\n")
				}
			case len(f) > 0 && strings.EqualFold(f[0], "EHLO"):
				if sc.mechs == "" {
					say("250 x.test\r\n")
				} else {
					say("250-x.test\r\n250 AUTH " + sc.mechs + "\r\n")
				}
			case len(f) > 1 && (strings.EqualFold(f[1], "LOGIN") || strings.EqualFold(f[1], "AUTHENTICATE") || strings.EqualFold(f[0], "AUTH")):
				smtp := strings.EqualFold(f[0], "AUTH")
				answer := sc.signIn
				switch answer {
				case "drop":
					return
				case "stall":
					r.ReadString('\n')
					return
				}
				if rest, ok := strings.CutPrefix(answer, "challenge:"); ok {
					if smtp {
						say("334 eyJzdGF0dXMiOiI0MDEifQ==\r\n")
					} else {
						say("+ eyJzdGF0dXMiOiI0MDEifQ==\r\n")
					}
					if l, _ := r.ReadString('\n'); l != "\r\n" {
						say("bad response " + l)
						return
					}
					answer = rest
				}
				if smtp {
					say(answer + "\r\n")
				} else {
					say(f[0] + " " + answer + "\r\n")
				}
			case len(f) > 0 && strings.EqualFold(f[0], "NOOP"):
				say("250 ok\r\n")
			case strings.TrimSpace(line) == "*":
				say("501 5.0.0 cancelled\r\n")
			case len(f) > 0 && (strings.EqualFold(f[0], "MAIL") || strings.EqualFold(f[0], "RCPT")):
				say("250 ok\r\n")
			case len(f) > 0 && strings.EqualFold(f[0], "DATA"):
				say("354 go on\r\n")
				for l, err := r.ReadString('\n'); err == nil && l != ".\r\n"; l, err = r.ReadString('\n') {
				}
				say("250 queued\r\n")
			case len(f) > 0 && strings.EqualFold(f[0], "QUIT"):
				if sc.quit == "stall" {
					r.ReadString('\n')
					return
				}
				say(sc.quit + "\r\n")
				return
			}
		}
	}()
	return l.Addr().String()
}

// signInStore is hostileStore signing in with a token when oauth is set.
func signInStore(t *testing.T, addr string, timeout time.Duration, oauth bool) *Store {
	s := hostileStore(t, addr, timeout)
	if oauth {
		s.cfg.Credential = func(context.Context) (Login, error) {
			return Login{User: "canary-user", Secret: "canary-token", OAuth: true}, nil
		}
	}
	return s
}

// signInCall reads or sends, as greet says which server it is.
func signInCall(ctx context.Context, s *Store, greet string) error {
	if strings.HasPrefix(greet, "* ") {
		_, _, err := s.UIDs(ctx, "INBOX")
		return err
	}
	return s.Submit(ctx, []string{"a@example.test"}, []byte("Subject: x\r\n\r\nx\r\n"))
}

// A sign-in is ErrLoginRefused only when the server answered it as a
// refusal, a token's included, so the host stops signing in only then, and
// ErrNoSignIn when the server offers no sign-in the clerk supports for the
// login; either names the side it failed on, in its text and to SideOf, and
// stands however the connection then ends. A server down for now, a dropped
// connection, a temporary SMTP failure or a CAPABILITY the server would not
// answer passes with time and has no side. Capability and mechanism names
// are case-insensitive.
func TestOnlyARefusalIsALoginRefused(t *testing.T) {
	const (
		oauthGreet = "* OK [CAPABILITY IMAP4rev1 AUTH=XOAUTH2 SASL-IR] ready\r\n"
		bareGreet  = "* OK ready\r\n"
		refusal    = "NO [AUTHENTICATIONFAILED] wrong"
		disabled   = "* OK [CAPABILITY IMAP4rev1 LOGINDISABLED] ready\r\n"
	)
	for name, c := range map[string]struct {
		sc    script
		oauth bool
		want  error // nil: neither ErrLoginRefused nor ErrNoSignIn
	}{
		"imap NO":                {script{greet: imapGreet, signIn: refusal}, false, ErrLoginRefused},
		"imap BAD":               {script{greet: imapGreet, signIn: "BAD no"}, false, ErrLoginRefused},
		"imap UNAVAILABLE":       {script{greet: imapGreet, signIn: "NO [UNAVAILABLE] down for now"}, false, nil},
		"imap drop":              {script{greet: imapGreet, signIn: "drop"}, false, nil},
		"imap disabled":          {script{greet: disabled, signIn: "OK in"}, false, ErrNoSignIn},
		"imap disabled, cut":     {script{greet: disabled, signIn: "OK in", quit: "stall"}, false, ErrNoSignIn},
		"imap disabled, lower":   {script{greet: "* OK [CAPABILITY imap4rev1 logindisabled] ready\r\n", signIn: "OK in"}, false, ErrNoSignIn},
		"imap disabled, PLAIN":   {script{greet: "* OK [CAPABILITY IMAP4rev1 LOGINDISABLED AUTH=PLAIN SASL-IR] ready\r\n", signIn: refusal}, false, ErrLoginRefused},
		"imap token":             {script{greet: oauthGreet, signIn: "challenge:" + refusal}, true, ErrLoginRefused},
		"imap token, lower":      {script{greet: "* OK [CAPABILITY imap4rev1 auth=xoauth2 sasl-ir] ready\r\n", signIn: "challenge:" + refusal}, true, ErrLoginRefused},
		"imap token, bare greet": {script{greet: bareGreet, caps: "IMAP4rev1 AUTH=XOAUTH2 SASL-IR", signIn: "challenge:" + refusal}, true, ErrLoginRefused},
		"imap CAPABILITY NO":     {script{greet: bareGreet, caps: "NO", signIn: refusal}, true, nil},
		"imap CAPABILITY drop":   {script{greet: bareGreet, caps: "drop", signIn: refusal}, true, nil},
		"imap no XOAUTH2":        {script{greet: imapGreet, signIn: "OK in"}, true, ErrNoSignIn},
		"imap no XOAUTH2, cut":   {script{greet: imapGreet, signIn: "OK in", quit: "stall"}, true, ErrNoSignIn},
		"imap refused, cut":      {script{greet: imapGreet, signIn: refusal, quit: "stall"}, false, ErrLoginRefused},
		"smtp 535":               {script{greet: smtpGreet, mechs: "PLAIN", signIn: "535 5.7.8 wrong"}, false, ErrLoginRefused},
		"smtp 454":               {script{greet: smtpGreet, mechs: "PLAIN", signIn: "454 4.7.0 Temporary authentication failure"}, false, nil},
		"smtp drop":              {script{greet: smtpGreet, mechs: "PLAIN", signIn: "drop"}, false, nil},
		"smtp token":             {script{greet: smtpGreet, mechs: "PLAIN XOAUTH2", signIn: "challenge:535 5.7.8 invalid token"}, true, ErrLoginRefused},
		"smtp token, lower":      {script{greet: smtpGreet, mechs: "plain xoauth2", signIn: "challenge:535 5.7.8 invalid token"}, true, ErrLoginRefused},
		"smtp no AUTH":           {script{greet: smtpGreet, signIn: "235 ok"}, false, ErrNoSignIn},
		"smtp no AUTH, cut":      {script{greet: smtpGreet, signIn: "235 ok", quit: "stall"}, false, ErrNoSignIn},
		"smtp no XOAUTH2":        {script{greet: smtpGreet, mechs: "PLAIN LOGIN", signIn: "235 ok"}, true, ErrNoSignIn},
		"smtp refused, cut":      {script{greet: smtpGreet, mechs: "PLAIN", signIn: "535 5.7.8 wrong", quit: "stall"}, false, ErrLoginRefused},
	} {
		err := signInCall(context.Background(), signInStore(t, serve(t, c.sc), 500*time.Millisecond, c.oauth), c.sc.greet)
		refused, none := errors.Is(err, ErrLoginRefused), errors.Is(err, ErrNoSignIn)
		on := Sending
		if strings.HasPrefix(c.sc.greet, "* ") {
			on = Reading
		}
		if c.want == nil {
			on = ""
		}
		if err == nil || c.want == nil && (refused || none) || c.want != nil && (!errors.Is(err, c.want) || !strings.HasSuffix(err.Error(), string(on))) || SideOf(err) != on {
			t.Errorf("%s: err %v, want %v, %s", name, err, c.want, on)
		}
	}
}

// A caller that stops a sign-in is told so, not that the login was refused.
func TestASignInTheCallerStopsIsNotRefused(t *testing.T) {
	for _, sc := range []script{{greet: imapGreet, signIn: "stall"}, {greet: smtpGreet, mechs: "PLAIN", signIn: "stall"}} {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		if err := signInCall(ctx, hostileStore(t, serve(t, sc), 5*time.Second), sc.greet); !errors.Is(err, context.Canceled) {
			t.Errorf("%q: err %v, want the caller's cancel", sc.greet, err)
		}
	}
}

// A mail the server took is sent, even if its QUIT is then cut off: failing
// it would have the caller send it twice.
func TestAMailTakenIsSentWhateverItsQuit(t *testing.T) {
	sc := script{greet: smtpGreet, mechs: "PLAIN", signIn: "235 2.7.0 ok", quit: "stall"}
	if err := signInCall(context.Background(), hostileStore(t, serve(t, sc), 500*time.Millisecond), sc.greet); err != nil {
		t.Fatalf("err %v, want the mail sent", err)
	}
}

// A sign-in the server leaves unanswered past the timeout says so, not that
// the login was refused, reading or sending.
func TestAStalledSignInTimesOut(t *testing.T) {
	for _, sc := range []script{{greet: imapGreet, signIn: "stall"}, {greet: smtpGreet, mechs: "PLAIN", signIn: "stall"}} {
		if err := signInCall(context.Background(), hostileStore(t, serve(t, sc), 500*time.Millisecond), sc.greet); !errors.Is(err, ErrTimeout) {
			t.Errorf("%q: err %v, want ErrTimeout", sc.greet, err)
		}
	}
}
