// Command agentos-checker is the CH-4 checker (D-226, MIG-4-exit-c2): the
// one process that holds the owner's code-generator seed (CLK-1
// exceptions), and turns a verified owner code into one signed approval of
// the exact held steps it was given (package clerk/codecheck).
//
//	agentos-checker -dir /run/agentos-checker -state /var/lib/agentos-checker/state.json \
//	    -seed /run/credentials/agentos-checker.service/seed -verify-uid 990
//
// At each start of its unit the kernel hands it its clerk key on descriptor
// 3, as it hands every clerk its key (clerkkey.FD), and -seed is the unlock
// step's root-only hand-off of the seed, sealed under that key, which the
// unit loads for it. With no -seed file (a store enrolled before
// MIG-4-exit-c2) it starts holding no seed and verifies nothing. It listens
// on dir/verify.sock for the owner channel (verify-uid) alone. The state
// file keeps only the last spent step. It refuses to run as its peer uid
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
	"syscall"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/codecheck"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/procguard"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stderr, os.NewFile(clerkkey.FD, "clerk-key")); err != nil {
		log.Fatal(err)
	}
}

// config is a parsed command line.
type config struct {
	dir, state, seed string
	verifyUID        int
}

func parse(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("agentos-checker", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.dir, "dir", "", "run directory for verify.sock")
	fs.StringVar(&c.state, "state", "", "state file: the last spent step, never the seed")
	fs.StringVar(&c.seed, "seed", "", "the unlock step's sealed seed, as the unit loads it")
	fs.IntVar(&c.verifyUID, "verify-uid", -1, "uid of the owner channel, the only peer on verify.sock")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	switch {
	case fs.NArg() != 0:
		return c, fmt.Errorf("unexpected arguments: %q", fs.Args())
	case !filepath.IsAbs(c.dir) || !filepath.IsAbs(c.state) || !filepath.IsAbs(c.seed):
		return c, errors.New("absolute -dir, -state and -seed are required")
	case c.verifyUID < 0:
		return c, errors.New("-verify-uid is required")
	}
	return c, nil
}

func run(args []string, stderr io.Writer, keyFile *os.File) error {
	c, err := parse(args, stderr)
	if err != nil {
		keyFile.Close()
		return err
	}
	if err := procguard.Isolate(c.verifyUID); err != nil {
		keyFile.Close()
		return err
	}
	chk, err := start(c, stderr, keyFile)
	if err != nil {
		return err
	}
	if err := runDir(c.dir); err != nil {
		return err
	}
	ln, err := codecheck.Listen(filepath.Join(c.dir, codecheck.VerifySocket), c.verifyUID)
	if err != nil {
		return err
	}
	return chk.Serve(ln)
}

// start reads the checker's key from keyFile and opens the seed at c.seed
// under it. No key starts nothing; no seed file starts a checker that
// verifies nothing, with one line on stderr.
func start(c config, stderr io.Writer, keyFile *os.File) (*codecheck.Checker, error) {
	k, err := clerkkey.Read(keyFile, handoff.CheckerName)
	if err != nil {
		return nil, fmt.Errorf("agentos-checker: my key from the kernel: %w", err)
	}
	sealer, err := k.Sealer()
	if err != nil {
		k.Wipe()
		return nil, err
	}
	defer clear(sealer)
	sign, err := k.Signer()
	k.Wipe()
	if err != nil {
		return nil, err
	}
	defer clear(sign)
	chk, err := codecheck.New(codecheck.Config{StatePath: c.state})
	if err != nil {
		return nil, err
	}
	blob, err := readSeed(c.seed)
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "agentos-checker: my store holds no code seed, so I verify no code")
		return chk, nil
	}
	if err != nil {
		return nil, err
	}
	if err := chk.Open(sealer, sign, blob); err != nil {
		return nil, fmt.Errorf("agentos-checker: the code seed the unlock step handed me: %w", err)
	}
	return chk, nil
}

// readSeed reads path: a regular file, never through a link, of at most
// handoff.MaxSealedSeed bytes.
func readSeed(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("agentos-checker: %s is not a file", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(handoff.MaxSealedSeed)+1))
	if err == nil && len(b) > handoff.MaxSealedSeed {
		err = fmt.Errorf("agentos-checker: %s is over %d bytes", path, handoff.MaxSealedSeed)
	}
	return b, err
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
