package imapsmtp

// REQ: DEV-2, REV-5, ARC-6

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/netguard"
)

type answers []string

func (a answers) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range a {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func guarded(ans answers, dialed *atomic.Int32) *netguard.Policy {
	return netguard.New(netguard.Config{
		Resolver: ans,
		Connect: func(context.Context, string, string) (net.Conn, error) {
			dialed.Add(1)
			return nil, errors.New("synthetic: not connected")
		},
	})
}

func TestMailDialsRefusePrivateAndReboundAnswers(t *testing.T) {
	for name, ans := range map[string]answers{
		"private":   {"192.168.1.20"},
		"rebinding": {"8.8.8.8", "10.0.0.9"},
		"mapped":    {"::ffff:10.0.0.9"},
	} {
		var dialed atomic.Int32
		s, err := New(Config{
			IMAP: "mail.example:993", SMTP: "mail.example:465", IMAPSec: TLS, SMTPSec: TLS,
			Credential: func(context.Context) (Login, error) { return Login{}, nil },
			From:       "owner@example.test",
			Guard:      guarded(ans, &dialed),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Folders(context.Background()); !errors.Is(err, netguard.ErrDenied) {
			t.Fatalf("%s: IMAP: %v", name, err)
		}
		if err := s.Submit(context.Background(), []string{"a@example.test"}, []byte("x")); !errors.Is(err, netguard.ErrDenied) {
			t.Fatalf("%s: SMTP: %v", name, err)
		}
		if dialed.Load() != 0 {
			t.Fatalf("%s: a refused answer was connected", name)
		}
	}
}
