package inbox

// REQ: VRB-2

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

// A folder's AddrHeads call that fails after it has answered part of its
// UIDs merges nothing into the record (MAIL-world-b2-i3): the mail is
// removed, or the folder renumbered, after the first batch of a read over
// more fresh UIDs than one batch holds. The step fails and the record is as
// it was, senders, contacts and progress; the next step reads the folder.
func TestAFailedSendersReadMergesNothing(t *testing.T) {
	const fresh = 403 // more than imapsmtp's 400-UID batch
	for _, tc := range []struct {
		name    string
		change  func(*imaptest.Server)
		want    error
		fetches int // a renumbered folder fails the second batch's SELECT
	}{
		{"removed", func(s *imaptest.Server) { s.Remove("Archive", "<m402@x.test>") }, imapsmtp.ErrUnanswered, 2},
		{"renumbered", func(s *imaptest.Server) { s.Renumber("Archive") }, imapsmtp.ErrValidity, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := imaptest.Start(t)
			at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
			srv.DeliverAt("Archive", at, rawMail("<m0@x.test>", "s0@x.test", "Hi"))
			srv.DeliverAt("Sent", at, "From: owner@example.test\nTo: pat@example.test\nSubject: Hi\n\nsynthetic body\n")
			l := NewLive(liveStore(t, srv))
			var r SendersRecord
			if more, err := l.SendersStep(context.Background(), &r, 500); err != nil || more || len(r.Senders) != 1 || !r.Sent["pat@example.test"] {
				t.Fatalf("first step: more %v, err %v, record %+v", more, err, r)
			}
			for i := 1; i <= fresh; i++ {
				srv.DeliverAt("Archive", at.Add(time.Duration(i)*time.Minute), rawMail(fmt.Sprintf("<m%d@x.test>", i), fmt.Sprintf("s%d@x.test", i), "Hi"))
			}
			before := SendersRecord{Sources: maps.Clone(r.Sources), Senders: maps.Clone(r.Senders), Sent: maps.Clone(r.Sent)}
			fetches := 0
			srv.AfterFetch(func(folder string) {
				if folder == "Archive" {
					if fetches++; fetches == 1 {
						tc.change(srv)
					}
				}
			})
			_, err := l.SendersStep(context.Background(), &r, 500)
			srv.AfterFetch(nil)
			if !errors.Is(err, tc.want) || fetches != tc.fetches {
				t.Fatalf("step over a folder changed after the first batch: err %v after %d fetches; want %v after %d", err, fetches, tc.want, tc.fetches)
			}
			if !reflect.DeepEqual(r, before) {
				t.Fatalf("the failed step changed the record: %d senders, sources %+v; want %d, %+v", len(r.Senders), r.Sources, len(before.Senders), before.Sources)
			}
			if more, err := l.SendersStep(context.Background(), &r, 500); err != nil || more || len(r.Senders) < fresh {
				t.Fatalf("next step: more %v, err %v, %d senders", more, err, len(r.Senders))
			}
		})
	}
}
