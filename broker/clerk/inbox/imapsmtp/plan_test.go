package imapsmtp

// REQ: TN-account-plan-2, CLK-9, DEV-8

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

// planCanary is in every header field the plan must not read.
const planCanary = "canary-plan-imap-5c1e"

func planStore(t *testing.T, srv *imaptest.Server) *Store {
	t.Helper()
	st, err := New(Config{Conn: imapconn.Pipe(), IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: Plain, SMTPSec: Plain, From: imaptest.User,
		Credential: func(context.Context) (Login, error) {
			return Login{User: imaptest.User, Secret: imaptest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// planMail is mail n, with two Authentication-Results fields (the topmost
// names n), and the canary in its Subject, Message-ID and body.
func planMail(n string) string {
	return "Authentication-Results: top-" + n + "; dkim=pass header.i=@" + n + ".test\n" +
		"Received: from x by y\nAuthentication-Results: below-" + n + "; dkim=pass\n" +
		"From: <a@" + n + ".test>\nSubject: " + planCanary + "\nMessage-ID: <" + planCanary + "-" + n + "@x.test>\n\n" + planCanary + "\n"
}

func planHeads(t *testing.T, st *Store, n int) []string {
	t.Helper()
	var got []string
	if err := st.PlanHeads(context.Background(), n, func(h []byte) error {
		got = append(got, string(h))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

// TN-account-plan-2 over IMAP (#3220): PlanHeads reads the newest n mails by
// INTERNALDATE across every folder but junk and trash, and of each only its
// From and Authentication-Results fields, in message order, with nothing
// marked read.
func TestPlanHeadsReadsTheNewestAcrossFoldersButJunkAndTrash(t *testing.T) {
	srv := imaptest.Start(t)
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i, d := range []struct{ folder, name string }{
		{"INBOX", "old"}, {"Archive", "mid"}, {"Junk", "spam"}, {"Trash", "trash"}, {"INBOX", "new"}, {"Sent", "newest"},
	} {
		srv.DeliverAt(d.folder, at.Add(time.Duration(i)*time.Hour), planMail(d.name))
	}
	got := planHeads(t, planStore(t, srv), 3)
	var names []string
	for _, h := range got {
		if strings.Contains(h, planCanary) || strings.Contains(strings.ToLower(h), "received") {
			t.Fatalf("a field the plan does not read: %q", h)
		}
		if a, b := strings.Index(h, "top-"), strings.Index(h, "below-"); a < 0 || b < a {
			t.Fatalf("the Authentication-Results fields out of message order: %q", h)
		}
		f := strings.SplitN(strings.SplitN(h, "top-", 2)[1], ";", 2)[0]
		names = append(names, f)
	}
	slices.Sort(names)
	if want := []string{"mid", "new", "newest"}; !slices.Equal(names, want) {
		t.Fatalf("read %v, want the newest three outside junk and trash %v", names, want)
	}
	for _, f := range []string{"INBOX", "Archive", "Sent"} {
		for _, m := range srv.Messages(f) {
			if slices.Contains(m.Flags, imap.SeenFlag) {
				t.Fatalf("a mail in %s marked read", f)
			}
		}
	}
}

// At most n headers are read, however many mails the folders hold, and a
// mail whose fields pass headMax is skipped while the rest are read.
func TestPlanHeadsReadsAtMostNAndSkipsALongHeader(t *testing.T) {
	srv := imaptest.Start(t)
	srv.AddFolder("Lists", "")
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	k := 0
	for _, f := range []string{"INBOX", "Archive", "Lists"} {
		for i := 0; i < 30; i++ {
			k++
			srv.DeliverAt(f, at.Add(time.Duration(k)*time.Minute), planMail(fmt.Sprintf("m%d", k)))
		}
	}
	long := "Authentication-Results: top-long; " + strings.Repeat("x", headMax) + "\nFrom: <a@long.test>\n\nbody\n"
	srv.DeliverAt("Lists", at.Add(time.Hour*24), long)
	got := planHeads(t, planStore(t, srv), 10)
	if len(got) != 9 {
		t.Fatalf("read %d headers, want the newest ten less the long one", len(got))
	}
	for _, h := range got {
		if strings.Contains(h, "top-long") {
			t.Fatal("a header past headMax was handed on")
		}
		var n int
		if _, err := fmt.Sscanf(strings.SplitN(h, "top-m", 2)[1], "%d", &n); err != nil || n <= 90-9 {
			t.Fatalf("read %q, not among the newest", h)
		}
	}
}
