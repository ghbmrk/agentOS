package mailsock_test

// REQ: CRED-1, CRED-8

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/mail/imapsmtp"
	"github.com/ghbmrk/agentos/broker/mail/mailsock"
	"github.com/ghbmrk/agentos/broker/mail/mailtest"
)

// bareFetchServer is a raw IMAP server that logs in, selects with UID
// validity 7 and answers a UID FETCH with a bare "* 1 FETCH", which
// panics go-imap v1.2.1's reader goroutine unless it is guarded
// (SR3-mail-k18). It holds the connection open after that.
func bareFetchServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(30 * time.Second))
				w := bufio.NewWriter(c)
				say := func(s string) { w.WriteString(s); w.Flush() }
				say("* OK [CAPABILITY IMAP4rev1] ready\r\n")
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					f := strings.Fields(line)
					if err != nil || len(f) < 2 {
						return
					}
					switch tag, cmd := f[0], strings.ToUpper(f[1]); cmd {
					case "LOGIN":
						say(tag + " OK done\r\n")
					case "SELECT", "EXAMINE":
						say("* 1 EXISTS\r\n* OK [UIDVALIDITY 7] v\r\n" + tag + " OK done\r\n")
					case "UID":
						say("* 1 FETCH\r\n")
					default:
						say(tag + " BAD unknown\r\n")
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

// TestReaderPanicAnswersFailedAndServesNext (T3): a panic in go-imap's
// reader goroutine costs only its own call, answered "failed", and the
// next call on the same mailsock listener is answered normally.
func TestReaderPanicAnswersFailedAndServesNext(t *testing.T) {
	bad, err := imapsmtp.New(imapsmtp.Config{IMAP: bareFetchServer(t), SMTP: "127.0.0.1:1", IMAPSec: imapsmtp.Plain,
		SMTPSec: imapsmtp.Plain, From: me, Timeout: 30 * time.Second,
		Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: "canary-user", Secret: "canary-secret"}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	srv := mailtest.Start(t)
	good := account(t, srv)
	var hostile atomic.Bool
	path, _ := serve(t, func() (mailsock.Account, error) {
		if hostile.Load() {
			return mailsock.Account{Store: bad, Address: me, Generation: testGen}, nil
		}
		return good()
	})
	c := bound(t, path)

	hostile.Store(true)
	start := time.Now()
	if _, err := c.Fetch(ctx, "INBOX", 7, []uint32{1}); !errors.Is(err, mailsock.ErrFailed) {
		t.Fatalf("hostile fetch: %v, want ErrFailed", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("hostile fetch took %v: it waited out a timeout", d)
	}

	hostile.Store(false)
	news(srv, "INBOX", "<after@shop.example>", "deals@shop.example")
	ms, err := c.Find(ctx, "INBOX", "<after@shop.example>")
	if err != nil || len(ms) != 1 {
		t.Fatalf("the next call was not answered normally: %+v %v", ms, err)
	}
}
