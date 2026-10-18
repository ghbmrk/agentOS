package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/durable"
)

// modemEnvFile is where agentos-modem.service reads the owner's number
// (OWNER_NUMBER), after the image's /usr/lib/agentos/modem.env. The bridge
// reads it only at start; agentos-modem-env.path restarts the bridge when
// the file changes (P2-2w c4c r1), since agentosd may not start a process
// (ARC-2).
const modemEnvFile = "/etc/agentos/modem.env"

// maxModemEnv bounds the file read: it holds a few short variables.
const maxModemEnv = 64 << 10

// ownerKey is the variable the bridge reads the owner's number from.
const ownerKey = "OWNER_NUMBER"

// Errors carry the path at most, never the number (P2-2w c4c r1).
var (
	errOwnerNotE164   = errors.New("modem.env: the owner's number is not E.164; nothing written")
	errModemEnvKind   = errors.New("modem.env: not a regular file; refused")
	errModemEnvDir    = errors.New("modem.env: its directory is not a directory; refused")
	errModemEnvTooBig = errors.New("modem.env: larger than 64 KiB; refused")
)

// writeOwnerEnv makes modem.env name the owner, logging the outcome without
// the number. A failure leaves the bridge without an owner until the next
// start retries it; it never stops agentosd.
func writeOwnerEnv(path, owner string, logf func(string, ...any)) {
	wrote, err := setOwnerNumber(path, owner)
	switch {
	case err != nil:
		logf("setup: owner's number not given to the modem bridge: %v", err)
	case wrote:
		logf("setup: %s names the owner; agentos-modem-env.path restarts the bridge", path)
	}
}

// setOwnerNumber makes path hold exactly one OWNER_NUMBER=<owner> line,
// keeping every other line in order, as a root-owned 0600 file written
// atomically and durably; /etc/agentos is made 0755 if missing. It reports
// whether it wrote: a file that already holds the line, alone, at 0600 is
// left as it is, so the bridge is not restarted for nothing.
func setOwnerNumber(path, owner string) (bool, error) {
	if !bridgeproto.ValidNumber(owner) {
		return false, errOwnerNotE164
	}
	dir := filepath.Dir(path)
	if err := ensureDir(dir); err != nil {
		return false, err
	}
	old, mode, err := readModemEnv(path)
	if err != nil {
		return false, err
	}
	want := ownerKey + "=" + owner
	kept, owners := splitOwnerLines(old)
	if mode == 0o600 && len(owners) == 1 && owners[0] == want {
		return false, nil
	}
	// The owner's line goes first, where no line before it can continue
	// onto it.
	var b strings.Builder
	b.WriteString(want)
	b.WriteByte('\n')
	for _, l := range kept {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	if err := durable.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		return false, fmt.Errorf("modem.env: write: %w", err)
	}
	return true, nil
}

// ensureDir makes dir (0755) if missing, and refuses one that is a link or
// not a directory, so the write cannot be steered elsewhere.
func ensureDir(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return fmt.Errorf("modem.env: make its directory: %w", err)
		}
		// Mkdir's mode is masked by the umask.
		if err := os.Chmod(dir, 0o755); err != nil {
			return fmt.Errorf("modem.env: its directory: %w", err)
		}
		if err := durable.SyncDir(filepath.Dir(dir)); err != nil {
			return fmt.Errorf("modem.env: its directory: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("modem.env: its directory: %w", err)
	}
	if !fi.IsDir() {
		return errModemEnvDir
	}
	return nil
}

// readModemEnv reads path without following a link or blocking on a pipe,
// and refuses anything but a regular file. A missing file reads as empty.
func readModemEnv(path string) (string, os.FileMode, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return "", 0, nil
	}
	if err != nil {
		// O_NOFOLLOW fails on a link (ELOOP); name it without syscall's
		// errno, which ARC-2's import check does not grant agentosd.
		if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return "", 0, errModemEnvKind
		}
		return "", 0, fmt.Errorf("modem.env: read: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("modem.env: read: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return "", 0, errModemEnvKind
	}
	b, err := io.ReadAll(io.LimitReader(f, maxModemEnv+1))
	if err != nil {
		return "", 0, fmt.Errorf("modem.env: read: %w", err)
	}
	if len(b) > maxModemEnv {
		return "", 0, errModemEnvTooBig
	}
	return string(b), fi.Mode().Perm(), nil
}

// splitOwnerLines splits an environment file into the lines that are not
// OWNER_NUMBER assignments and those that are. As systemd reads it, a line
// ending in a backslash continues onto the next, which is then part of that
// value, not a key of its own; an OWNER_NUMBER line's continuations go
// with it.
func splitOwnerLines(s string) (kept, owners []string) {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil, nil
	}
	cont, dropping := false, false
	for _, l := range strings.Split(s, "\n") {
		key, _, isVar := strings.Cut(strings.TrimLeft(l, " \t"), "=")
		switch {
		case cont && dropping:
			owners = append(owners, l)
		case !cont && isVar && strings.TrimRight(key, " \t") == ownerKey:
			owners, dropping = append(owners, l), true
		default:
			kept, dropping = append(kept, l), false
		}
		cont = strings.HasSuffix(l, "\\")
	}
	return kept, owners
}
