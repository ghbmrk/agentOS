// Command agentos-checker is the CH-4 checker (SIM-split): it holds the
// owner's code-generator seed apart from the broker, the vault process and
// the key holders, and turns a verified owner code into one-time approvals
// for the exact high-risk requests it was given (package checker).
//
//	agentos-checker -dir /run/agentos-checker -state /var/lib/agentos-checker/state.json \
//	    -hand-uid 992 -verify-uid 990 -redeem-uid 993 -redeem-uid 994
//
// It listens on dir/hand.sock for the unlock step (hand-uid), on
// dir/verify.sock for the broker (verify-uid) and on dir/redeem.sock for
// the key holders (each redeem-uid), and starts with no seed: the unlock
// step's keeper hands it, and hands it again after a restart. The state
// file keeps only the last spent step. It refuses to run as any peer uid
// and makes itself non-dumpable.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/checker"
	"github.com/ghbmrk/agentos/broker/sockets"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stderr); err != nil {
		log.Fatal(err)
	}
}

type uids []int

func (u *uids) String() string {
	s := make([]string, len(*u))
	for i, v := range *u {
		s[i] = strconv.Itoa(v)
	}
	return strings.Join(s, ",")
}

func (u *uids) Set(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fmt.Errorf("bad uid %q", v)
	}
	*u = append(*u, n)
	return nil
}

// config is a parsed command line.
type config struct {
	dir, state         string
	handUID, verifyUID int
	redeemUIDs         uids
}

func (c config) peers() []int {
	return append([]int{c.handUID, c.verifyUID}, c.redeemUIDs...)
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-checker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.dir, "dir", "", "run directory for the three sockets")
	fs.StringVar(&c.state, "state", "", "state file: the last spent step, never the seed")
	fs.IntVar(&c.handUID, "hand-uid", -1, "uid of the unlock step, the only peer on hand.sock")
	fs.IntVar(&c.verifyUID, "verify-uid", -1, "uid of the broker, the only peer on verify.sock")
	fs.Var(&c.redeemUIDs, "redeem-uid", "uid of a key holder, a peer on redeem.sock (repeatable)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case c.dir == "" || c.state == "":
		return c, errors.New("-dir and -state are required")
	case c.handUID < 0 || c.verifyUID < 0 || len(c.redeemUIDs) == 0:
		return c, errors.New("-hand-uid, -verify-uid and -redeem-uid are required")
	}
	// Each side is its own uid: the broker never redeems what it verified,
	// and no holder verifies a code or hands the seed.
	seen := map[int]bool{}
	for _, u := range c.peers() {
		if seen[u] {
			return c, fmt.Errorf("uid %d is on two sides; each peer needs its own uid", u)
		}
		seen[u] = true
	}
	return c, nil
}

func run(args []string, stderr io.Writer) error {
	c, err := parse(args, stderr)
	if err != nil {
		return err
	}
	if err := sockets.Isolate(c.peers()...); err != nil {
		return err
	}
	chk, err := checker.New(checker.Config{StatePath: c.state})
	if err != nil {
		return err
	}
	if err := runDir(c.dir); err != nil {
		return err
	}
	hand, err := checker.Listen(filepath.Join(c.dir, checker.HandSocket), c.handUID)
	if err != nil {
		return err
	}
	verify, err := checker.Listen(filepath.Join(c.dir, checker.VerifySocket), c.verifyUID)
	if err != nil {
		hand.Close()
		return err
	}
	redeem, err := checker.Listen(filepath.Join(c.dir, checker.RedeemSocket), c.redeemUIDs...)
	if err != nil {
		hand.Close()
		verify.Close()
		return err
	}
	return chk.Serve(hand, verify, redeem)
}

// runDir creates dir 0711, or checks that an existing one is a directory
// owned by this uid and resets its mode.
func runDir(dir string) error {
	if err := os.Mkdir(dir, 0o711); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a directory owned by uid %d", dir, os.Getuid())
	}
	return os.Chmod(dir, 0o711)
}
