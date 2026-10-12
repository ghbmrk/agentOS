package main

import (
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

// REQ: CRED-1, ADP-10

func TestParseRefusesWhatAHolderCannotKeep(t *testing.T) {
	ok := []string{"-dir", "/run/x", "-credential", "openai", "-adapter", "openai", "-request-uid", "1", "-hand-uid", "2"}
	c, err := parse(ok, io.Discard)
	if err != nil || len(c.adapters) != 1 || c.adapters[0].Credential != "openai" {
		t.Fatalf("%+v %v", c, err)
	}
	for name, args := range map[string][]string{
		"no uid":          {"-dir", "/run/x", "-credential", "k", "-adapter", "openai"},
		"one uid for two": {"-dir", "/run/x", "-credential", "k", "-adapter", "openai", "-request-uid", "1", "-hand-uid", "1"},
		"unknown adapter": {"-dir", "/run/x", "-credential", "k", "-adapter", "gmail", "-request-uid", "1", "-hand-uid", "2"},
		"no adapter":      {"-dir", "/run/x", "-credential", "k", "-request-uid", "1", "-hand-uid", "2"},
	} {
		if _, err := parse(args, io.Discard); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A holder never runs as one of its peers: the uid check would admit
// anything under its own uid (SIM-split R3).
func TestRunRefusesItsPeerUID(t *testing.T) {
	me := strconv.Itoa(os.Getuid())
	other := strconv.Itoa(os.Getuid() + 1)
	for _, uids := range [][]string{{me, other}, {other, me}} {
		args := []string{"-dir", t.TempDir(), "-credential", "k", "-adapter", "openai", "-request-uid", uids[0], "-hand-uid", uids[1]}
		if err := run(args, io.Discard); err == nil || !strings.Contains(err.Error(), "peer uid") {
			t.Errorf("uids %v: %v", uids, err)
		}
	}
}
