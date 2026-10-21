package imapsmtp

// REQ: VRB-2 (assumption MIG-4-mail-reader-5)

import (
	"bufio"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// seenServer is a raw IMAP server for SeenFrom: each connection logs in and
// selects with the next UID validity of validities, a UID SEARCH answers
// UIDs 1 and 2, and a UID FETCH answers fetch ("NO" fails it).
func seenServer(t *testing.T, validities []int, fetch string) string {
	t.Helper()
	l := listenLoopback(t)
	go func() {
		for _, v := range validities {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.SetDeadline(time.Now().Add(10 * time.Second))
			w := bufio.NewWriter(c)
			say := func(s string) { w.WriteString(s); w.Flush() }
			say("* OK [CAPABILITY IMAP4rev1] ready\r\n")
			r := bufio.NewReader(c)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					break
				}
				f := strings.Fields(line)
				if len(f) < 2 {
					continue
				}
				tag, cmd := f[0], strings.ToUpper(f[1])
				switch {
				case cmd == "LOGIN":
					say(tag + " OK done\r\n")
				case cmd == "SELECT" || cmd == "EXAMINE":
					say("* 2 EXISTS\r\n* OK [UIDVALIDITY " + strconv.Itoa(v) + "] v\r\n" + tag + " OK [READ-ONLY] done\r\n")
				case cmd == "UID" && len(f) > 2 && strings.EqualFold(f[2], "SEARCH"):
					say("* SEARCH 1 2\r\n" + tag + " OK done\r\n")
				case cmd == "UID" && fetch == "NO":
					say(tag + " NO failed\r\n")
				case cmd == "UID":
					say(fetch + tag + " OK done\r\n")
				case cmd == "LOGOUT":
					say("* BYE\r\n" + tag + " OK done\r\n")
				default:
					say(tag + " OK done\r\n")
				}
			}
			c.Close()
		}
	}()
	return l.Addr().String()
}

func header(uid int, from string) string {
	h := "From: " + from + "\r\n\r\n"
	return "* " + strconv.Itoa(uid) + " FETCH (UID " + strconv.Itoa(uid) + " BODY[HEADER.FIELDS (FROM)]<0> {" + strconv.Itoa(len(h)) + "}\r\n" + h + ")\r\n"
}

// One header per UID the search found: a repeated or invented response adds
// nothing.
func TestSeenFromKeepsOneHeaderPerSearchedUID(t *testing.T) {
	addr := seenServer(t, []int{7, 7}, header(1, "a@x.test")+header(1, "b@x.test")+header(9, "c@x.test")+header(2, "d@x.test"))
	got, err := hostileStore(t, addr, 5*time.Second).SeenFrom(context.Background(), "INBOX")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !strings.Contains(string(got[0]), "a@x.test") || !strings.Contains(string(got[1]), "d@x.test") {
		t.Fatalf("headers %q", got)
	}
}

// A folder renumbered between the search and the fetch is refused: its UIDs
// may name other messages.
func TestSeenFromRefusesAFolderRenumberedBetweenSessions(t *testing.T) {
	addr := seenServer(t, []int{7, 8}, header(1, "a@x.test"))
	if _, err := hostileStore(t, addr, 5*time.Second).SeenFrom(context.Background(), "INBOX"); !errors.Is(err, ErrValidity) {
		t.Fatalf("err %v, want ErrValidity", err)
	}
}

// A fetch the server fails fails the call: the headers it did not send would
// make their senders look never opened.
func TestSeenFromFailsWhenTheFetchFails(t *testing.T) {
	addr := seenServer(t, []int{7, 7}, "NO")
	if got, err := hostileStore(t, addr, 5*time.Second).SeenFrom(context.Background(), "INBOX"); err == nil {
		t.Fatalf("headers %q with no error", got)
	}
}
