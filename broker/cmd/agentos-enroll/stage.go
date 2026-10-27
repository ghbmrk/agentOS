package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/pageca"
)

// -stage-page-ca makes the first-boot page authority before the Owner Card
// is shown (HW-1, CH-9; brief OWN-card-flow decision 2): its sealed form
// (pageca.Marshal) at -page-ca-file, root's alone, and its certificate's DER
// at -page-ca-cert, which the owner page reads to print the fingerprint.
// Enrollment later stores exactly the staged pair (putPageCA), so the
// fingerprint on the card is the authority the kernel serves under.

// maxPublished bounds the published certificate the owner side and
// enrollment read: a P-256 certificate is under 1 KiB.
const maxPublished = 4 << 10

var (
	errPublishedAlone = errors.New("agentos-enroll: a page certificate is published without its staged authority; I change nothing")
	errPageCAPair     = errors.New("agentos-enroll: the staged page authority and the published certificate are not one pair; I change nothing")
	errPageCARead     = errors.New("agentos-enroll: the staged page authority does not read; I change nothing")
	errPublished      = errors.New("agentos-enroll: the published page certificate is not a file only root can write; I change nothing")
)

// stagePageCA stages the authority, or finishes or checks an earlier
// staging. Both files present and one pair: nothing to do. The staged pair
// alone (a crash between the two writes): publish its certificate. The
// certificate alone: refuse, so a certificate never gets a second key.
// Neither: make the authority and write both. No file is ever overwritten
// or seen part-written under its final name (writeOnce).
func stagePageCA(staged, published string, built time.Time) error {
	hasStaged, err := exists(staged)
	if err != nil {
		return err
	}
	hasPublished, err := exists(published)
	if err != nil {
		return err
	}
	switch {
	case hasStaged && hasPublished:
		v, err := readStaged(staged, published)
		if err != nil {
			return err
		}
		clear(v)
		return nil
	case hasPublished:
		return errPublishedAlone
	case hasStaged:
		a, err := readStagedAuthority(staged)
		if err != nil {
			return err
		}
		return writeOnce(published, a.Certificate(), 0o644)
	}
	a, err := pageca.New(pageca.DefaultName, built, nil)
	if err != nil {
		return err
	}
	v, err := pageca.Marshal(a)
	if err != nil {
		return err
	}
	defer clear(v)
	if err := writeOnce(staged, v, 0o600); err != nil {
		return err
	}
	return writeOnce(published, a.Certificate(), 0o644)
}

// readStaged reads the staged pair and the published certificate and
// returns the staged bytes once they are one pair: the staged form opens
// under pageca's load checks (its key is its certificate's) and its
// certificate is the published one, byte for byte. The caller wipes them.
func readStaged(staged, published string) ([]byte, error) {
	a, v, err := readStagedPair(staged)
	if err != nil {
		return nil, err
	}
	der, err := readPublished(published)
	if err != nil {
		clear(v)
		return nil, err
	}
	if !bytes.Equal(a.Certificate(), der) {
		clear(v)
		return nil, errPageCAPair
	}
	return v, nil
}

func readStagedAuthority(staged string) (*pageca.Authority, error) {
	a, v, err := readStagedPair(staged)
	clear(v)
	return a, err
}

func readStagedPair(staged string) (*pageca.Authority, []byte, error) {
	v, err := readSecretMax(staged, pageca.MaxSealed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errPageCARead, err)
	}
	a, err := pageca.Unmarshal(v)
	if err != nil {
		clear(v)
		return nil, nil, fmt.Errorf("%w: %w", errPageCARead, err)
	}
	return a, v, nil
}

// readPublished reads the published certificate through its open
// descriptor, never a symlink: a regular file of root's (this process's
// euid) that no one else can write, at most maxPublished bytes.
func readPublished(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, errPublished
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, errPublished
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || !fi.Mode().IsRegular() || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
		return nil, errPublished
	}
	b, err := io.ReadAll(io.LimitReader(f, maxPublished+1))
	if err != nil || len(b) == 0 || len(b) > maxPublished {
		return nil, errPublished
	}
	return b, nil
}

// writeOnce writes data to path with mode, never over a file there and
// never through a symlink: to a hidden temporary name in the same
// directory (O_CREAT|O_EXCL|O_NOFOLLOW), synced, then linked to path, which
// fails if path exists; the temporary name is removed and the directory
// synced. So path holds either nothing or all of data.
func writeOnce(path string, data []byte, mode os.FileMode) error {
	dir, base := filepath.Dir(path), filepath.Base(path)
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer unix.Close(dfd)
	var r [8]byte
	if _, err := rand.Read(r[:]); err != nil {
		return err
	}
	tmp := "." + base + "." + hex.EncodeToString(r[:])
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return &os.PathError{Op: "create", Path: filepath.Join(dir, tmp), Err: err}
	}
	defer unix.Unlinkat(dfd, tmp, 0)
	f := os.NewFile(uintptr(fd), tmp)
	// The unit's UMask= would narrow a public file's mode.
	err = f.Chmod(mode.Perm())
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return &os.PathError{Op: "write", Path: filepath.Join(dir, tmp), Err: err}
	}
	if err := unix.Linkat(dfd, tmp, dfd, base, 0); err != nil {
		return &os.PathError{Op: "link", Path: path, Err: err}
	}
	return unix.Fsync(dfd)
}
