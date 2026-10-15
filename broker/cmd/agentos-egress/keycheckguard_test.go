package main

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, DEV-2

// rebindResolver answers every name with one address and records the
// names it was asked.
type rebindResolver struct {
	to    netip.Addr
	mu    sync.Mutex
	asked []string
}

func (r *rebindResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.asked = append(r.asked, host)
	r.mu.Unlock()
	return []netip.Addr{r.to}, nil
}

// #1357 (Security S1 on #1343): setup's own key check, the path with no
// keyCheck seam, sends through the process's netguard policy. A provider
// name that resolves into the home network is refused before any connect:
// the setup call answers 502, stores nothing, and the address never sees
// a connection, so the key cannot reach a home-network host (CRED-1,
// DEV-2). The policy's resolver must be the one asked: a bare transport,
// or a fresh policy in place of custody's, would ask another.
func TestSetupKeyCheckSendsThroughTheGuard(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()

	for _, to := range []string{"127.0.0.1", "192.168.1.40", "10.0.0.7"} {
		r := providerRig(t)
		r.c.confirm(r.unlock(t), r.code())
		res := &rebindResolver{to: netip.MustParseAddr(to)}
		var connects, denied atomic.Int32
		r.c.guard = netguard.New(netguard.Config{
			Resolver: res,
			OnDeny: func(e netguard.DenyEvent) {
				if e.Addr.String() == to && e.Port == 443 {
					denied.Add(1)
				}
			},
			// Every connect the policy lets through lands on the listener.
			Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
				connects.Add(1)
				var d net.Dialer
				return d.DialContext(ctx, network, ln.Addr().String())
			},
			Timeout: 5 * time.Second,
		})
		r.c.keyCheck = nil

		key := synthetic(t, "sk-canary-")
		w := setupCall(t, r.c, "POST", "/setup/providers/key", keyBody("openai", key))
		if w.Code != http.StatusBadGateway {
			t.Fatalf("%s: setup answered %d %s, want 502", to, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), key) {
			t.Fatalf("%s: answer carries the key: %s", to, w.Body)
		}
		if hasKind(r.c.v, "openai", vault.KindAPIKey) {
			t.Fatalf("%s: key stored after a refused check", to)
		}
		res.mu.Lock()
		asked := append([]string(nil), res.asked...)
		res.mu.Unlock()
		if len(asked) == 0 || asked[0] != "api.openai.com" {
			t.Fatalf("%s: custody's guard resolved %v, want api.openai.com: the check bypassed the guard", to, asked)
		}
		if denied.Load() == 0 {
			t.Fatalf("%s: the guard refused nothing", to)
		}
		if n := connects.Load(); n != 0 {
			t.Fatalf("%s: %d connects after the guard's refusal", to, n)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("the home-network listener saw %d connections", n)
	}
}
