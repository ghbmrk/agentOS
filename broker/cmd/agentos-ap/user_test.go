package main

// REQ: ARC-1, CH-7, DEV-net-h

import (
	"errors"
	"os/user"
	"testing"
)

// hostapd runs as its own user (#1426): the loader looks it up at each
// start and refuses to run hostapd as root, or at all without the user.
func TestNewHostapdRunsHostapdAsItsUser(t *testing.T) {
	lookup := func(u *user.User, err error) func(string) (*user.User, error) {
		return func(name string) (*user.User, error) {
			if name != hostapdUser {
				t.Fatalf("looked up %q, want %q", name, hostapdUser)
			}
			return u, err
		}
	}
	h, err := newHostapd("/run/agentos-ap", lookup(&user.User{Uid: "991", Gid: "990"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if h.User == nil || h.User.UID != 991 || h.User.GID != 990 || h.Dir != "/run/agentos-ap" {
		t.Fatalf("newHostapd = %+v (user %+v), want uid 991 gid 990", h, h.User)
	}
	for name, l := range map[string]func(string) (*user.User, error){
		"missing":  lookup(nil, user.UnknownUserError(hostapdUser)),
		"failing":  lookup(nil, errors.New("nss down")),
		"root uid": lookup(&user.User{Uid: "0", Gid: "990"}, nil),
		"root gid": lookup(&user.User{Uid: "991", Gid: "0"}, nil),
		"bad uid":  lookup(&user.User{Uid: "x", Gid: "990"}, nil),
		"bad gid":  lookup(&user.User{Uid: "991", Gid: "-1"}, nil),
	} {
		if h, err := newHostapd("/run/agentos-ap", l); err == nil {
			t.Errorf("%s: newHostapd = %+v, nil; want an error", name, h)
		}
	}
}
