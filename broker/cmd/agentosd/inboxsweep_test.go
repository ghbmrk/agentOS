package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/guest"
)

// A .durable-* temp a crash left beside the guest inbox holds the outbox
// as it stood, reply text included. Start-up removes it before the guest
// store opens, so after a forget the reply text is on no file (#2373).
func TestStartSweepsCrashLeftInboxTemp(t *testing.T) {
	// REQ: CAP-3
	dir := t.TempDir()
	inbox := filepath.Join(dir, "guest-inbox.json")
	canary := []byte("CANARY-guest-reply-2373")
	if err := os.WriteFile(filepath.Join(dir, durable.TempPrefix+"123456"), canary, 0o600); err != nil {
		t.Fatal(err)
	}
	sweepInboxTemps(inbox)
	plane, err := guest.New(guest.Config{Dir: t.TempDir(), InboxPath: inbox, Machines: oneLineage{}, Effects: canaryEffects{}})
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Shutdown()
	names, err := filepath.Glob(filepath.Join(dir, durable.TempPrefix+"*"))
	if err != nil || len(names) != 0 {
		t.Fatalf("temps left beside the inbox: %v %v", names, err)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, canary) {
			t.Fatalf("%s still holds the canary", e.Name())
		}
	}
}

// The sweep is safe only while none of agentosd's own writes is in
// flight, so main runs it straight after the flags parse: before setup
// mode, the held restore mode and the guest plane, all of which write in
// the inbox's directory.
func TestInboxSweepRunsBeforeAnyWrite(t *testing.T) {
	// REQ: CAP-3
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	parse := strings.Index(s, "\tflag.Parse()\n")
	sweep := strings.Index(s, "\tsweepInboxTemps(inboxPath)\n")
	if parse < 0 || sweep < 0 {
		t.Fatalf("flag.Parse at %d, sweepInboxTemps at %d", parse, sweep)
	}
	for _, line := range strings.Split(strings.TrimSpace(s[parse+len("\tflag.Parse()\n"):sweep]), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "//") {
			t.Fatalf("%q runs between flag.Parse() and the sweep", line)
		}
	}
	for _, later := range []string{"heldMode{", "setupMode{", "openGuestPlane(m,"} {
		if i := strings.Index(s, later); i < 0 || i < sweep {
			t.Fatalf("%q at %d, not after the sweep at %d", later, i, sweep)
		}
	}
}

// With a crash-left temp the sweep cannot remove (here a non-empty
// directory with the prefix), start-up goes on: the temp is logged.
func TestInboxSweepFailureIsNotFatal(t *testing.T) {
	// REQ: CAP-3
	dir := t.TempDir()
	stage := filepath.Join(dir, durable.TempPrefix+"stage")
	if err := os.MkdirAll(filepath.Join(stage, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	sweepInboxTemps(filepath.Join(dir, "guest-inbox.json"))
	sweepInboxTemps("")
}

// With no inbox configured the sweep touches nothing: without the guard,
// filepath.Dir("") is ".", and a temp in the working directory would go.
func TestInboxSweepSkipsWithoutInbox(t *testing.T) {
	// REQ: CAP-3
	dir := t.TempDir()
	t.Chdir(dir)
	temp := filepath.Join(dir, durable.TempPrefix+"654321")
	if err := os.WriteFile(temp, []byte("CANARY-cwd-2373"), 0o600); err != nil {
		t.Fatal(err)
	}
	sweepInboxTemps("")
	if _, err := os.Stat(temp); err != nil {
		t.Fatalf("sweep with no inbox removed a temp in the working directory: %v", err)
	}
}
