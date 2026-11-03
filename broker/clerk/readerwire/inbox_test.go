package readerwire_test

// REQ: PLN-2, D-154

// inbox imports readerwire (RES-5-readerwire-reason, #4846), so the tests of
// inbox.Read over the frame live in this external package: an in-package
// test that imported inbox would be an import cycle.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/readerwire"
)

// serve runs a reader over model on a fresh socket that admits this uid, and
// returns the mail clerk's Ask to it.
func serve(t *testing.T, model readerwire.Ask) inbox.Ask {
	t.Helper()
	dir, err := os.MkdirTemp("", "rw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := readerwire.Listen(filepath.Join(dir, "s"), os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go readerwire.Serve(ln, model)
	return inbox.Ask(readerwire.Dial(filepath.Join(dir, "s"), os.Getuid(), 5*time.Second))
}

// inbox.Read over the frame classes the mail by the model's reply.
func TestInboxReadOverTheFrame(t *testing.T) {
	var got string
	ask := serve(t, func(_ context.Context, p string) (string, error) {
		got = p
		return " Spam\n", nil
	})
	mails := inbox.Read(context.Background(), ask, []inbox.Mail{{Raw: []byte("Subject: win\r\n\r\nbuy now")}})
	if len(mails) != 1 || mails[0].Class != "spam" || mails[0].Why != "" {
		t.Fatalf("inbox.Read over the frame: %+v", mails)
	}
	if !strings.HasSuffix(got, "buy now") {
		t.Fatalf("the reader did not get the mail: %q", got)
	}
}

// A model error never classes the mail, and the reason inbox keeps is the
// frame's word, never the error's text: unavailable, or refused for a
// refused route.
func TestAModelErrorLeavesTheMailUnclassifiedWithTheFramesWord(t *testing.T) {
	for _, c := range []struct {
		err error
		why string
	}{
		{errors.New("spam"), "unavailable"},
		{errors.New("the prompt was: Subject: hi"), "unavailable"},
		{errors.New("no route: " + readerwire.ErrRefused.Error()), "unavailable"},
		{readerwire.ErrRefused, "refused"},
	} {
		ask := serve(t, func(context.Context, string) (string, error) { return "spam", c.err })
		mails := inbox.Read(context.Background(), ask, []inbox.Mail{{Raw: []byte("Subject: hi\r\n\r\n")}})
		if mails[0].Class != "" || mails[0].Why != c.why {
			t.Errorf("model error %q: class %q, why %q; want unclassified, %q", c.err, mails[0].Class, mails[0].Why, c.why)
		}
	}
}
