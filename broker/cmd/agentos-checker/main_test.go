package main

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// REQ: CH-4, ARC-1

func TestParseKeepsEachSideApart(t *testing.T) {
	ok := []string{"-dir", "/run/x", "-state", "/var/x", "-hand-uid", "1", "-verify-uid", "2", "-redeem-uid", "3", "-redeem-uid", "4"}
	c, err := parse(ok, io.Discard)
	if err != nil || len(c.redeemUIDs) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	for name, args := range map[string][]string{
		"no state":             {"-dir", "/run/x", "-hand-uid", "1", "-verify-uid", "2", "-redeem-uid", "3"},
		"no redeem uid":        {"-dir", "/run/x", "-state", "/var/x", "-hand-uid", "1", "-verify-uid", "2"},
		"broker redeems":       {"-dir", "/run/x", "-state", "/var/x", "-hand-uid", "1", "-verify-uid", "2", "-redeem-uid", "2"},
		"broker hands":         {"-dir", "/run/x", "-state", "/var/x", "-hand-uid", "2", "-verify-uid", "2", "-redeem-uid", "3"},
		"holder hands":         {"-dir", "/run/x", "-state", "/var/x", "-hand-uid", "3", "-verify-uid", "2", "-redeem-uid", "3"},
		"negative redeem uid":  {"-dir", "/run/x", "-state", "/var/x", "-hand-uid", "1", "-verify-uid", "2", "-redeem-uid", "-3"},
		"one holder uid twice": {"-dir", "/run/x", "-state", "/var/x", "-hand-uid", "1", "-verify-uid", "2", "-redeem-uid", "3", "-redeem-uid", "3"},
	} {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The checker never runs as one of its peers (SIM-split R3).
func TestRunRefusesItsPeerUID(t *testing.T) {
	me := os.Getuid()
	u := func(d int) string { return strconv.Itoa(me + d) }
	for _, ids := range [][3]string{{u(0), u(1), u(2)}, {u(1), u(0), u(2)}, {u(1), u(2), u(0)}} {
		dir := t.TempDir()
		args := []string{"-dir", filepath.Join(dir, "run"), "-state", filepath.Join(dir, "state.json"),
			"-hand-uid", ids[0], "-verify-uid", ids[1], "-redeem-uid", ids[2]}
		if err := run(args, io.Discard); err == nil || !strings.Contains(err.Error(), "peer uid") {
			t.Errorf("uids %v: %v", ids, err)
		}
	}
}
