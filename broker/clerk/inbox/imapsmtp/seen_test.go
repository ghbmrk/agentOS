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
	return seenSearch(t, validities, "* SEARCH 1 2\r\n", fetch)
}

// seenSearch is seenServer with the UID SEARCH's untagged answer ("NO" fails
// it).
func seenSearch(t *testing.T, validities []int, search, fetch string) string {
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
				case cmd == "UID" && len(f) > 2 && strings.EqualFold(f[2], "SEARCH") && search == "NO":
					say(tag + " NO failed\r\n")
				case cmd == "UID" && len(f) > 2 && strings.EqualFold(f[2], "SEARCH"):
					say(search + tag + " OK done\r\n")
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

// seenFrom collects what SeenFrom hands over.
func seenFrom(s *Store, folder string) ([][]byte, error) {
	var out [][]byte
	err := s.SeenFrom(context.Background(), folder, func(h []byte) error {
		out = append(out, h)
		return nil
	})
	return out, err
}

func header(uid int, from string) string {
	h := "From: " + from + "\r\n\r\n"
	return "* " + strconv.Itoa(uid) + " FETCH (UID " + strconv.Itoa(uid) + " BODY[HEADER.FIELDS (FROM)]<0> {" + strconv.Itoa(len(h)) + "}\r\n" + h + ")\r\n"
}

// One header per UID the search found: a repeated or invented response adds
// nothing.
func TestSeenFromKeepsOneHeaderPerSearchedUID(t *testing.T) {
	addr := seenServer(t, []int{7, 7}, header(1, "a@x.test")+header(1, "b@x.test")+header(9, "c@x.test")+header(2, "d@x.test"))
	got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX")
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
	if _, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); !errors.Is(err, ErrValidity) {
		t.Fatalf("err %v, want ErrValidity", err)
	}
}

// A fetch the server fails fails the call: the headers it did not send would
// make their senders look never opened.
func TestSeenFromFailsWhenTheFetchFails(t *testing.T) {
	addr := seenServer(t, []int{7, 7}, "NO")
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err == nil {
		t.Fatalf("headers %q with no error", got)
	}
}

// A search the server fails fails the call: it is not a folder with no read
// mail.
func TestSeenFromFailsWhenTheSearchFails(t *testing.T) {
	addr := seenSearch(t, []int{7}, "NO", "")
	if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); err == nil {
		t.Fatalf("headers %q with no error", got)
	}
}

// A FETCH that answers OK without a header for every searched message fails
// the call, and so does a From header longer than fromMax, which the server
// cut or would have to: either leaves a sender out.
func TestSeenFromFailsWhenAHeaderIsMissingOrCut(t *testing.T) {
	long := "a@x.test (" + strings.Repeat("x", fromMax) + ")"
	for name, c := range map[string]struct {
		fetch string
		want  error
	}{
		"missing": {header(1, "a@x.test"), ErrUnanswered},
		"cut":     {header(1, long) + header(2, "d@x.test"), ErrLongHeader},
	} {
		addr := seenServer(t, []int{7, 7}, c.fetch)
		if got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); !errors.Is(err, c.want) {
			t.Fatalf("%s: headers %q, err %v; want %v", name, got, err, c.want)
		}
	}
}

// Each batch of seenBatch UIDs is fetched in its own session, under the same
// UID validity: a folder renumbered before a later batch is refused. The
// batch, not the search, sizes each session's read budget (M21; the bound is
// checked in tests/test_egress_memory.py).
func TestSeenFromFetchesEachBatchInItsOwnSession(t *testing.T) {
	var search, fetch strings.Builder
	search.WriteString("* SEARCH")
	for u := 1; u <= seenBatch+1; u++ {
		search.WriteString(" " + strconv.Itoa(u))
		fetch.WriteString(header(u, "a@x.test"))
	}
	search.WriteString("\r\n")
	addr := seenSearch(t, []int{7, 7, 7}, search.String(), fetch.String())
	got, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX")
	if err != nil || len(got) != seenBatch+1 {
		t.Fatalf("%d headers, err %v; want %d", len(got), err, seenBatch+1)
	}
	addr = seenSearch(t, []int{7, 7, 8}, search.String(), fetch.String())
	if _, err := seenFrom(hostileStore(t, addr, 5*time.Second), "INBOX"); !errors.Is(err, ErrValidity) {
		t.Fatalf("a renumbered second batch: err %v, want ErrValidity", err)
	}
}

// An error from each stops the call with that error.
func TestSeenFromStopsOnTheCallersError(t *testing.T) {
	stop := errors.New("stop")
	addr := seenServer(t, []int{7, 7}, header(1, "a@x.test")+header(2, "d@x.test"))
	n := 0
	err := hostileStore(t, addr, 5*time.Second).SeenFrom(context.Background(), "INBOX", func([]byte) error { n++; return stop })
	if !errors.Is(err, stop) || n != 1 {
		t.Fatalf("err %v after %d headers, want stop after 1", err, n)
	}
}
