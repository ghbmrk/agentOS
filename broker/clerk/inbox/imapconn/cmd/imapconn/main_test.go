package main

// REQ: KRN-2, CLK-1, DEV-2

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapconn"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
)

// TestTheBinaryServesOneSession: the built connection process, started as
// a child through childproc with an empty environment and its control
// connection on fd 3, serves one read and exits when the clerk closes it.
func TestTheBinaryServesOneSession(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "imapconn")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", "Message-ID: <a@example.test>\nSubject: x\n\nhello\n")
	exited := make(chan error, 1)
	conn := func(ctx context.Context) (*net.UnixConn, error) {
		mine, theirs, err := imapconn.Socketpair()
		if err != nil {
			return nil, err
		}
		f, err := theirs.File()
		theirs.Close()
		if err != nil {
			return nil, err
		}
		defer f.Close()
		cmd := childproc.Command(context.Background(), childproc.NewEnv(), childproc.Options{ExtraFiles: []*os.File{f}}, bin)
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		go func() { exited <- cmd.Wait() }()
		return mine, nil
	}
	s, err := imapsmtp.New(imapsmtp.Config{Conn: conn, IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain,
		From: imaptest.User, Timeout: 20 * time.Second, Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: imaptest.User, Secret: imaptest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	v, uids, err := s.UIDs(context.Background(), "INBOX")
	if err != nil || v == 0 || len(uids) != 1 {
		t.Fatalf("read through the child: %d %v %v", v, uids, err)
	}
	select {
	case err := <-exited:
		var ee *childproc.ExitError
		if err != nil && !errors.As(err, &ee) {
			t.Fatalf("the child: %v", err)
		}
		if err != nil {
			t.Fatalf("the child exited %d", ee.ExitCode())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the child did not exit after its session")
	}
}

// A descriptor 3 that is not a socket ends the process with an error,
// never serving.
func TestTheBinaryNeedsItsControlSocket(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "imapconn")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = childproc.Command(context.Background(), childproc.NewEnv(), childproc.Options{ExtraFiles: []*os.File{f}}, bin).Run()
	if err == nil {
		t.Fatal("the process served on a descriptor that is not a socket")
	}
}
