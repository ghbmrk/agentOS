package requal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/apply/bootab"
	"github.com/ghbmrk/agentos/broker/childproc"
	"github.com/ghbmrk/agentos/broker/update"
)

// VerityImages is the production Images (UPD-5r-b2). A candidate's /usr
// image and hash tree are fetched through the release's own signed
// hashes (update.Verified.Fetch), opened by dm-verity under the root hash
// its manifest signs (UPD-1a) and mounted read-only, so every block the
// sandbox reads is checked against that hash. The installed release's
// /usr is the running one, already under dm-verity at boot: it is bound
// read-only only when the booted usrhash is the installed release's.
type VerityImages struct {
	// Source is where a candidate's files are fetched from: the source
	// that checked it.
	Source update.Source
	// Staging holds a private directory per mount for the fetched files.
	Staging string
	// Installed is the installed release's /usr root hash (the update
	// store's Installed.UsrRootHash); Booted is the running boot's
	// (apply.Activator.Booted).
	Installed func(ctx context.Context) (string, error)
	Booted    func(ctx context.Context) (string, error)
	// Usr is the running /usr; "" is "/usr".
	Usr string

	// run, mount and unmount are the tools; nil uses childproc and the
	// mount system calls.
	run     func(ctx context.Context, name string, arg ...string) error
	mount   func(src, dst, fstype string, flags uintptr) error
	unmount func(dst string) error
}

const (
	veritysetup = "/usr/sbin/veritysetup"
	toolPath    = "PATH=/usr/sbin:/usr/bin"
	// usrFlags are every mount's: read-only, no set-id, no devices.
	usrFlags = syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV
)

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (v *VerityImages) tool(ctx context.Context, name string, arg ...string) error {
	if v.run != nil {
		return v.run(ctx, name, arg...)
	}
	var stderr bytes.Buffer
	err := childproc.Command(ctx, childproc.NewEnv(toolPath), childproc.Options{Stderr: &stderr}, name, arg...).Run()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(arg, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (v *VerityImages) mnt(src, dst, fstype string, flags uintptr) error {
	if v.mount != nil {
		return v.mount(src, dst, fstype, flags)
	}
	return syscall.Mount(src, dst, fstype, flags, "")
}

func (v *VerityImages) umnt(dst string) error {
	if v.unmount != nil {
		return v.unmount(dst)
	}
	return syscall.Unmount(dst, 0)
}

// Mount mounts rel's /usr read-only at at.
func (v *VerityImages) Mount(ctx context.Context, rel *update.Verified, at string) (func() error, error) {
	if rel == nil {
		return v.installed(ctx, at)
	}
	m, err := rel.Manifest()
	if err != nil {
		return nil, err
	}
	if !hashRE.MatchString(m.UsrRootHash) {
		return nil, errors.New("requal: release has no /usr root hash")
	}
	name, err := randomName()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(v.Staging, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	data, hash := filepath.Join(dir, "usr.img"), filepath.Join(dir, "usr.verity")
	clean := func() error {
		var errs []error
		for _, p := range []string{data, hash, dir} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		}
		return errors.Join(errs...)
	}
	if err := rel.Fetch(v.Source, bootab.DataFile, data); err != nil {
		clean()
		return nil, err
	}
	if err := rel.Fetch(v.Source, bootab.VerityFile, hash); err != nil {
		clean()
		return nil, err
	}
	dev := "agentos-" + name
	closeDev := func() error {
		// Its own context: the run's may have ended.
		return v.tool(context.Background(), veritysetup, "close", dev)
	}
	if err := v.tool(ctx, veritysetup, "open", data, dev, hash, m.UsrRootHash); err != nil {
		// An open cut off by its context may have made the device.
		closeDev()
		clean()
		return nil, err
	}
	if err := v.mnt("/dev/mapper/"+dev, at, "erofs", usrFlags); err != nil {
		closeDev()
		clean()
		return nil, err
	}
	return func() error {
		if err := v.umnt(at); err != nil {
			return err
		}
		if err := closeDev(); err != nil {
			return err
		}
		return clean()
	}, nil
}

// installed binds the running /usr read-only at at, only when the booted
// usrhash is the installed release's.
func (v *VerityImages) installed(ctx context.Context, at string) (func() error, error) {
	if v.Installed == nil || v.Booted == nil {
		return nil, errors.New("requal: no installed release to compare")
	}
	in, err := v.Installed(ctx)
	if err != nil {
		return nil, err
	}
	booted, err := v.Booted(ctx)
	if err != nil {
		return nil, err
	}
	if !hashRE.MatchString(in) || in != booted {
		return nil, errors.New("requal: the booted /usr is not the installed release")
	}
	usr := v.Usr
	if usr == "" {
		usr = "/usr"
	}
	if err := v.mnt(usr, at, "", syscall.MS_BIND); err != nil {
		return nil, err
	}
	// A bind takes its flags only on the remount that follows it.
	if err := v.mnt("", at, "", syscall.MS_REMOUNT|syscall.MS_BIND|usrFlags); err != nil {
		v.umnt(at)
		return nil, err
	}
	return func() error { return v.umnt(at) }, nil
}
