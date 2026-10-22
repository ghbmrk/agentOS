package imapsmtp

// REQ: CLK-2

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// statusServer is a raw IMAP server with one folder, INBOX, that answers
// every STATUS with items, offering CONDSTORE when condstore is set. It
// stands in for servers the test server cannot be: one with CONDSTORE, and
// one whose STATUS reply leaves out an item asked for, against RFC 3501.
func statusServer(t *testing.T, condstore bool, items func() string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	caps := "IMAP4rev1"
	if condstore {
		caps += " CONDSTORE"
	}
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
				say("* OK [CAPABILITY " + caps + "] ready\r\n")
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					f := strings.Fields(line)
					if len(f) < 2 {
						return
					}
					tag, cmd := f[0], strings.ToUpper(f[1])
					switch cmd {
					case "LOGIN":
						say(tag + " OK done\r\n")
					case "CAPABILITY":
						say("* CAPABILITY " + caps + "\r\n" + tag + " OK done\r\n")
					case "LIST":
						say("* LIST () \"/\" INBOX\r\n" + tag + " OK done\r\n")
					case "STATUS":
						say("* STATUS INBOX (" + items() + ")\r\n" + tag + " OK done\r\n")
					case "LOGOUT":
						say("* BYE bye\r\n" + tag + " OK done\r\n")
						return
					default:
						say(tag + " BAD unknown\r\n")
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

// A STATUS reply that leaves out an item asked for gives no mark: a count
// missing would read as 0, which is a count, and the mark would stay the
// same however the folder changed.
func TestMarksFailClosedOnAPartialStatus(t *testing.T) {
	full := []string{"UIDVALIDITY 3", "UIDNEXT 9", "MESSAGES 4", "UNSEEN 1"}
	for i := range full {
		items := strings.Join(append(append([]string(nil), full[:i]...), full[i+1:]...), " ")
		s := hostileStore(t, statusServer(t, false, func() string { return items }), 5*time.Second)
		if m, err := s.Marks(context.Background()); !errors.Is(err, ErrPartialStatus) || m != nil {
			t.Fatalf("without %s: marks %+v, err %v; want ErrPartialStatus", full[i], m, err)
		}
	}
	s := hostileStore(t, statusServer(t, true, func() string { return strings.Join(full, " ") }), 5*time.Second)
	if m, err := s.Marks(context.Background()); !errors.Is(err, ErrPartialStatus) || m != nil {
		t.Fatalf("CONDSTORE without HIGHESTMODSEQ: marks %+v, err %v; want ErrPartialStatus", m, err)
	}
}

// Where the server has CONDSTORE, the mark carries HIGHESTMODSEQ, so a flag
// change that leaves every count as it was still changes the mark.
func TestMarksCarryHighestModSeqUnderCondstore(t *testing.T) {
	seq := "17"
	s := hostileStore(t, statusServer(t, true, func() string {
		return "UIDVALIDITY 3 UIDNEXT 9 MESSAGES 4 UNSEEN 1 HIGHESTMODSEQ " + seq
	}), 5*time.Second)
	m, err := s.Marks(context.Background())
	if err != nil || len(m) != 1 || m[0] != (Mark{Folder: "INBOX", Validity: 3, Next: 9, Messages: 4, Unseen: 1, ModSeq: "17"}) {
		t.Fatalf("marks %+v, err %v", m, err)
	}
	seq = "18"
	if again, err := s.Marks(context.Background()); err != nil || again[0].ModSeq != "18" {
		t.Fatalf("after a flag change: marks %+v, err %v", again, err)
	}
}
