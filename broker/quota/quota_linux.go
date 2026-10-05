package quota

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	prjQuota  = 2
	qGetInfo  = 0x800005
	qGetQuota = 0x800007
	qSetQuota = 0x800008

	qifBLimits = 1
	qifILimits = 4

	fsIocFsGetXattr    = 0x801c581f // _IOR('X', 31, struct fsxattr)
	fsIocFsSetXattr    = 0x401c5820 // _IOW('X', 32, struct fsxattr)
	fsXflagProjInherit = 0x00000200
	dqBlockSize        = 1024 // if_dqblk block limits are in 1 KiB units
)

type fsxattr struct {
	Xflags     uint32
	Extsize    uint32
	Nextents   uint32
	Projid     uint32
	Cowextsize uint32
	_          [8]byte
}

type dqblk struct {
	Bhardlimit uint64
	Bsoftlimit uint64
	Curspace   uint64
	Ihardlimit uint64
	Isoftlimit uint64
	Curinodes  uint64
	Btime      uint64
	Itime      uint64
	Valid      uint32
	_          uint32
}

type dqinfo struct {
	Bgrace uint64
	Igrace uint64
	Flags  uint32
	Valid  uint32
}

func qcmd(cmd int) uintptr { return uintptr(cmd<<8 | prjQuota) }

func quotactl(f *os.File, cmd int, id uint32, addr unsafe.Pointer) error {
	_, _, e := unix.Syscall6(unix.SYS_QUOTACTL_FD, f.Fd(), qcmd(cmd), uintptr(id), uintptr(addr), 0, 0)
	if e != 0 {
		return e
	}
	return nil
}

func getInfo(f *os.File) error {
	var i dqinfo
	return quotactl(f, qGetInfo, 0, unsafe.Pointer(&i))
}

func getXattr(f *os.File) (fsxattr, error) {
	var a fsxattr
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), fsIocFsGetXattr, uintptr(unsafe.Pointer(&a))); e != 0 {
		return a, e
	}
	return a, nil
}

func getProject(f *os.File) (uint32, error) {
	a, err := getXattr(f)
	return a.Projid, err
}

// setProject tags f with project id; a directory also passes it on to
// what is made beneath it.
func setProject(f *os.File, id uint32, dir bool) error {
	a, err := getXattr(f)
	if err != nil {
		return err
	}
	a.Projid = id
	if dir {
		a.Xflags |= fsXflagProjInherit
	}
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), fsIocFsSetXattr, uintptr(unsafe.Pointer(&a))); e != 0 {
		return e
	}
	return nil
}

func setLimits(f *os.File, id uint32, bytes, inodes int64) error {
	d := dqblk{Valid: qifBLimits | qifILimits}
	if bytes > 0 {
		d.Bhardlimit = uint64((bytes + dqBlockSize - 1) / dqBlockSize)
	}
	if inodes > 0 {
		d.Ihardlimit = uint64(inodes)
	}
	return quotactl(f, qSetQuota, id, unsafe.Pointer(&d))
}

func getQuota(f *os.File, id uint32) (Usage, error) {
	var d dqblk
	if err := quotactl(f, qGetQuota, id, unsafe.Pointer(&d)); err != nil {
		return Usage{}, err
	}
	return Usage{
		Bytes: int64(d.Curspace), Inodes: int64(d.Curinodes),
		LimitBytes: int64(d.Bhardlimit) * dqBlockSize, LimitInodes: int64(d.Ihardlimit),
	}, nil
}

func enforced(fn func() error) error {
	runtime.LockOSThread()
	h := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var d [2]unix.CapUserData
	if err := unix.Capget(&h, &d[0]); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("quota: capget: %w", err)
	}
	saved := d
	d[unix.CAP_SYS_RESOURCE/32].Effective &^= 1 << (unix.CAP_SYS_RESOURCE % 32)
	if err := unix.Capset(&h, &d[0]); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("quota: drop CAP_SYS_RESOURCE: %w", err)
	}
	ferr := fn()
	if err := unix.Capset(&h, &saved[0]); err != nil {
		// The thread keeps the lowered set; left locked, it ends with this
		// goroutine instead of running other code.
		return errors.Join(ferr, fmt.Errorf("quota: restore capabilities: %w", err))
	}
	runtime.UnlockOSThread()
	return ferr
}
