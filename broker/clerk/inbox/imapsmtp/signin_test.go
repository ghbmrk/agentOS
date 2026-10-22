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

// signInServer takes one connection, greets it, answers an SMTP EHLO with
// AUTH PLAIN, ends at an IMAP LOGOUT or SMTP QUIT, cancels an SMTP sign-in
// on "*", and answers the sign-in, a LOGIN or AUTH line, with answer
// (an IMAP answer after the command's tag); "drop" closes the connection
// and "stall" leaves it unanswered.
func signInServer(t *testing.T, greet, answer string) string {
	return mailServer(t, greet, answer, "221 bye")
}

// mailServer is signInServer that also takes an SMTP mail and answers QUIT
// with quit ("stall" leaves it unanswered).
func mailServer(t *testing.T, greet, answer, quit string) string {
	t.Helper()
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
		say(greet)
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			f := strings.Fields(line)
			switch {
			case len(f) > 1 && strings.EqualFold(f[1], "LOGOUT"):
				say("* BYE\r\n" + f[0] + " OK bye\r\n")
				return
			case len(f) > 0 && strings.EqualFold(f[0], "EHLO"):
				say("250-x.test\r\n250 AUTH PLAIN\r\n")
			case len(f) > 1 && (strings.EqualFold(f[1], "LOGIN") || strings.EqualFold(f[0], "AUTH")):
				switch answer {
				case "drop":
					return
				case "stall":
					r.ReadString('\n')
					return
				}
				if strings.EqualFold(f[0], "AUTH") {
					say(answer + "\r\n")
				} else {
					say(f[0] + " " + answer + "\r\n")
				}
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
				if quit == "stall" {
					r.ReadString('\n')
					return
				}
				say(quit + "\r\n")
				return
			}
		}
	}()
	return l.Addr().String()
}

// A sign-in is ErrLoginRefused only when the server answered it as a
// refusal, or would refuse it unsent (LOGINDISABLED), so the host stops
// signing in only then: a server down for now,
// a dropped connection or a temporary SMTP failure passes with time.
func TestOnlyARefusalIsALoginRefused(t *testing.T) {
	const imapGreet, smtpGreet = "* OK [CAPABILITY IMAP4rev1] ready\r\n", "220 x.test ready\r\n"
	for name, c := range map[string]struct {
		greet, answer string
		refused       bool
	}{
		"imap NO":          {imapGreet, "NO [AUTHENTICATIONFAILED] wrong", true},
		"imap BAD":         {imapGreet, "BAD no", true},
		"imap UNAVAILABLE": {imapGreet, "NO [UNAVAILABLE] down for now", false},
		"imap drop":        {imapGreet, "drop", false},
		"imap disabled":    {"* OK [CAPABILITY IMAP4rev1 LOGINDISABLED] ready\r\n", "OK in", true},
		"smtp 535":         {smtpGreet, "535 5.7.8 wrong", true},
		"smtp 454":         {smtpGreet, "454 4.7.0 Temporary authentication failure", false},
		"smtp drop":        {smtpGreet, "drop", false},
	} {
		s := hostileStore(t, signInServer(t, c.greet, c.answer), 5*time.Second)
		var err error
		if strings.HasPrefix(c.greet, "* ") {
			_, _, err = s.UIDs(context.Background(), "INBOX")
		} else {
			err = s.Submit(context.Background(), []string{"a@example.test"}, []byte("x"))
		}
		if err == nil || errors.Is(err, ErrLoginRefused) != c.refused {
			t.Errorf("%s: err %v, refused %v", name, err, c.refused)
		}
	}
}

// A caller that stops a sign-in is told so, not that the login was refused.
func TestASignInTheCallerStopsIsNotRefused(t *testing.T) {
	for greet, call := range map[string]func(*Store, context.Context) error{
		"* OK [CAPABILITY IMAP4rev1] ready\r\n": func(s *Store, ctx context.Context) error { _, _, err := s.UIDs(ctx, "INBOX"); return err },
		"220 x.test ready\r\n": func(s *Store, ctx context.Context) error {
			return s.Submit(ctx, []string{"a@example.test"}, []byte("x"))
		},
	} {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		if err := call(hostileStore(t, signInServer(t, greet, "stall"), 5*time.Second), ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("%q: err %v, want the caller's cancel", greet, err)
		}
	}
}

// A mail the server took is sent, even if its QUIT is then cut off: failing
// it would have the caller send it twice.
func TestAMailTakenIsSentWhateverItsQuit(t *testing.T) {
	addr := mailServer(t, "220 x.test ready\r\n", "235 2.7.0 ok", "stall")
	if err := hostileStore(t, addr, 500*time.Millisecond).Submit(context.Background(), []string{"a@example.test"}, []byte("Subject: x\r\n\r\nx\r\n")); err != nil {
		t.Fatalf("err %v, want the mail sent", err)
	}
}

// A sign-in the server leaves unanswered past the timeout says so, not that
// the login was refused, reading or sending.
func TestAStalledSignInTimesOut(t *testing.T) {
	for greet, call := range map[string]func(*Store) error{
		"* OK [CAPABILITY IMAP4rev1] ready\r\n": func(s *Store) error { _, _, err := s.UIDs(context.Background(), "INBOX"); return err },
		"220 x.test ready\r\n":                  func(s *Store) error { return s.Submit(context.Background(), []string{"a@example.test"}, []byte("x")) },
	} {
		if err := call(hostileStore(t, signInServer(t, greet, "stall"), 500*time.Millisecond)); !errors.Is(err, ErrTimeout) {
			t.Errorf("%q: err %v, want ErrTimeout", greet, err)
		}
	}
}
