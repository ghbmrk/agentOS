package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// requireBlock refuses a target that is not a block device; tests write
// to files.
var requireBlock = true

// Where the kernel lists mounted file systems and active swap.
var mountsPath, swapsPath = "/proc/self/mounts", "/proc/swaps"

// write copies image to dev and reads every byte back (A1). It refuses an
// image that does not match sums, and a target that is mounted, used as
// swap, held open exclusively by the kernel, or smaller than the image,
// before writing anything.
func write(image, sums, dev string, log io.Writer) error {
	want, err := sumFor(image, sums)
	if err != nil {
		return err
	}
	if got, err := fileSum(image); err != nil {
		return err
	} else if !bytes.Equal(got, want) {
		return fmt.Errorf("%s does not match its line in %s", image, sums)
	}
	real, err := filepath.EvalSymlinks(dev)
	if err != nil {
		return err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return err
	}
	block := fi.Mode()&os.ModeDevice != 0 && fi.Mode()&os.ModeCharDevice == 0
	if requireBlock && !block {
		return fmt.Errorf("%s is not a block device", dev)
	}
	if err := notInUse(real); err != nil {
		return err
	}
	src, err := os.Open(image)
	if err != nil {
		return err
	}
	defer src.Close()
	si, err := src.Stat()
	if err != nil {
		return err
	}
	size := si.Size()

	flags := os.O_WRONLY
	if block {
		// On Linux, O_EXCL on a block device fails while the kernel holds
		// it (a mount, swap, RAID or device-mapper member).
		flags |= unix.O_EXCL
	}
	dst, err := os.OpenFile(real, flags, 0)
	if err != nil {
		return err
	}
	defer dst.Close()
	room, err := dst.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if room < size {
		return fmt.Errorf("%s holds %d bytes, the image needs %d", dev, room, size)
	}
	if _, err := dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	fmt.Fprintf(log, "writing %s to %s (%d bytes)\n", image, dev, size)
	buf := make([]byte, 4<<20)
	if _, err := io.CopyBuffer(struct{ io.Writer }{dst}, src, buf); err != nil {
		return err
	}
	if err := dst.Sync(); err != nil {
		return err
	}
	if block {
		// Drop the device's buffer cache so the read-back comes from the
		// disk, not from what was just written.
		if err := unix.IoctlSetInt(int(dst.Fd()), unix.BLKFLSBUF, 0); err != nil {
			return fmt.Errorf("flushing %s's cache: %w", dev, err)
		}
	}
	if err := dst.Close(); err != nil {
		return err
	}
	fmt.Fprintf(log, "reading %s back\n", dev)
	if err := verify(real, size, want); err != nil {
		return err
	}
	fmt.Fprintf(log, "%s holds the image\n", dev)
	return nil
}

// verify checks that dev's first size bytes have SHA-256 want.
func verify(dev string, size int64, want []byte) error {
	f, err := os.Open(dev)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = unix.Fadvise(int(f.Fd()), 0, size, unix.FADV_DONTNEED)
	h := sha256.New()
	if _, err := io.CopyN(h, f, size); err != nil {
		return fmt.Errorf("reading %s back: %w", dev, err)
	}
	if !bytes.Equal(h.Sum(nil), want) {
		return fmt.Errorf("%s does not hold the image after writing", dev)
	}
	return nil
}

// notInUse refuses dev when it or one of its partitions is mounted or
// used as swap.
func notInUse(dev string) error {
	for _, l := range []struct{ path, what string }{{mountsPath, "mounted"}, {swapsPath, "used as swap"}} {
		srcs, err := firstFields(l.path)
		if err != nil {
			return err
		}
		for _, s := range srcs {
			if r, err := filepath.EvalSymlinks(s); err == nil {
				s = r
			}
			if s == dev || isPartition(dev, s) {
				return fmt.Errorf("%s is %s (%s): unmount it first", dev, l.what, s)
			}
		}
	}
	return nil
}

var (
	digitPart  = regexp.MustCompile(`^p[0-9]+$`) // nvme0n1p2, mmcblk0p1, loop0p1
	letterPart = regexp.MustCompile(`^[0-9]+$`)  // sda2
)

// isPartition reports whether p names a partition of dev, by the kernel's
// naming: a "p" before the number when dev's name ends in a digit.
func isPartition(dev, p string) bool {
	rest, ok := strings.CutPrefix(p, dev)
	if !ok || rest == "" {
		return false
	}
	if c := dev[len(dev)-1]; c >= '0' && c <= '9' {
		return digitPart.MatchString(rest)
	}
	return letterPart.MatchString(rest)
}

// firstFields is each line's first field, unescaped, from a /proc table;
// a missing table lists nothing.
func firstFields(p string) ([]string, error) {
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fs := strings.Fields(sc.Text()); len(fs) > 0 {
			out = append(out, unescape(fs[0]))
		}
	}
	return out, sc.Err()
}

// unescape undoes /proc's octal escapes (\040 for a space).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
