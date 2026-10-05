// Package quota sets hard disk quotas on directory trees with Linux project
// quotas (SPEC RES-4): every file created under a directory tagged with a
// project ID counts against that project's limits, and a write past them
// fails with EDQUOT. The file system must be ext4 or XFS mounted with
// project quotas on (prjquota).
//
// ext4 lets a writer holding CAP_SYS_RESOURCE past a hard limit, and
// agentosd runs as root with it. So whatever writes into a limited tree on
// the broker's behalf (the overlay mount, whose writes to its upper layer
// use the credentials it was mounted with) is set up inside Enforced.
//
// It uses quotactl_fd(2) on a descriptor of the directory itself, so it
// needs no block device path, and FS_IOC_FSSETXATTR to tag the directory.
// Both need CAP_SYS_ADMIN, which agentosd has.
package quota

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// ErrUnsupported: the file system holding the directory has no project
// quotas (not ext4 or XFS, or mounted without prjquota, or a kernel built
// without CONFIG_QUOTA).
var ErrUnsupported = errors.New("quota: project quotas are not on for this file system (mount it with prjquota)")

// Usage is a project's use and hard limits. Bytes are bytes, not blocks.
type Usage struct {
	Bytes, Inodes           int64
	LimitBytes, LimitInodes int64
}

// FS is the file system holding a directory, with project quotas on.
type FS struct {
	dir string
}

// Open checks that dir's file system enforces project quotas.
func Open(dir string) (*FS, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := getInfo(f); err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrUnsupported, dir, err)
	}
	return &FS{dir: dir}, nil
}

// Limit tags the empty directory dir with project id, so everything later
// created beneath it counts against id, and sets id's hard limits. A zero
// limit means none for that resource. dir must be on this file system.
func (q *FS) Limit(dir string, id uint32, bytes, inodes int64) error {
	if id == 0 {
		return errors.New("quota: project 0 is every untagged file")
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := setProject(f, id, true); err != nil {
		return fmt.Errorf("quota: tag %s with project %d: %w", dir, id, err)
	}
	if err := setLimits(f, id, bytes, inodes); err != nil {
		return fmt.Errorf("quota: limits for project %d: %w", id, err)
	}
	return nil
}

// Tag tags every directory and regular file in the tree at root with
// project id, so all of it counts against id and nothing beneath it
// escapes: a tree copied, restored or written before it was tagged keeps
// project 0, which no hard limit covers, and retagging a directory does not
// retag what it already holds. Symlinks are not followed (they cannot be
// tagged, and cannot grow); V17 keeps other kinds out of layers. root must
// be on this file system. With quotas on, the kernel moves each file's use
// to id as it is tagged.
func (q *FS) Tag(root string, id uint32) error {
	if id == 0 {
		return errors.New("quota: project 0 is every untagged file")
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := setProject(f, id, d.IsDir()); err != nil {
			return fmt.Errorf("quota: tag %s with project %d: %w", p, id, err)
		}
		return nil
	})
}

// Project reports the project path is tagged with, without following a
// final symlink.
func Project(path string) (uint32, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return getProject(f)
}

// Usage reports project id's use and limits.
func (q *FS) Usage(id uint32) (Usage, error) {
	f, err := os.Open(q.dir)
	if err != nil {
		return Usage{}, err
	}
	defer f.Close()
	return getQuota(f, id)
}

// Enforced runs fn on one OS thread with CAP_SYS_RESOURCE dropped from the
// thread's effective set, so the file system enforces hard quotas on what
// fn writes, or on a mount fn makes, whose later writes carry the
// credentials it was made with. The capability is restored afterwards. fn
// must do its work on the calling goroutine.
func Enforced(fn func() error) error { return enforced(fn) }

// Clear removes project id's limits, for a machine destroyed.
func (q *FS) Clear(id uint32) error {
	f, err := os.Open(q.dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return setLimits(f, id, 0, 0)
}
