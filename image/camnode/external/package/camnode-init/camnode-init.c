// camnode-init is the camera node's first process (CAM-node part c, #3513; briefs/CAM-node.md,
// design points 3 and 5). It runs from the initramfs inside the signed boot image and does one
// thing: find the slot the bootloader booted, put the root it holds under dm-verity with the root
// hash the signed command line names, read the whole root once through verity, mount it
// read-only and hand over to systemd. It reads nothing else and takes no input but the command
// line and the bootloader's device-tree node, both of which the bootloader set.
//
// A slot is one partition: the boot FAT the bootloader reads, then the erofs root, then its
// verity hash tree, at the offsets the command line names (image/camnode/ASSUMPTIONS.md,
// CAM-image-2). The same slot image works in either slot, because the partition comes from the
// bootloader (/chosen/bootloader/partition, as agentos-camnode reads it) and not from the image.
//
// Any failure restarts the board with no tryboot flag, so the bootloader boots the default
// slot: a trial image that does not verify is never kept (CAM-b2-2).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include <linux/dm-ioctl.h>

#define BLOCK 4096u
#define CMDLINE_MAX 4096

static void say(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	int fd, n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if (n > (int)sizeof(buf) - 2)
		n = sizeof(buf) - 2;
	buf[n++] = '\n';
	fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		(void)!write(fd, buf, n);
		close(fd);
	}
}

static void fail(const char *what)
{
	say("camnode-init: %s (%s); restarting into the default slot", what, strerror(errno));
	sync();
	reboot(RB_AUTOBOOT);
	for (;;)
		pause();
}

// param returns the value of key=VALUE on the command line, or NULL. Keys are matched whole.
static const char *param(const char *cmdline, const char *key, char *out, size_t outlen)
{
	size_t klen = strlen(key);
	const char *p = cmdline;

	while (*p) {
		while (*p == ' ' || *p == '\n')
			p++;
		const char *end = p;
		while (*end && *end != ' ' && *end != '\n')
			end++;
		if ((size_t)(end - p) > klen && strncmp(p, key, klen) == 0 && p[klen] == '=') {
			size_t n = end - p - klen - 1;
			if (n + 1 > outlen)
				return NULL;
			memcpy(out, p + klen + 1, n);
			out[n] = 0;
			return out;
		}
		p = end;
	}
	return NULL;
}

// number parses a decimal byte count that is a whole number of verity blocks.
static int number(const char *s, uint64_t *v)
{
	char *end;

	if (!s || !*s || *s < '0' || *s > '9')
		return -1;
	errno = 0;
	unsigned long long n = strtoull(s, &end, 10);
	if (errno || *end || n == 0 || n % BLOCK)
		return -1;
	*v = n;
	return 0;
}

static int hex64(const char *s)
{
	if (!s || strlen(s) != 64)
		return -1;
	for (const char *p = s; *p; p++)
		if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')))
			return -1;
	return 0;
}

// booted reads the partition the bootloader booted: one 32-bit big-endian cell.
static int booted(void)
{
	unsigned char b[4];
	int fd = open("/sys/firmware/devicetree/base/chosen/bootloader/partition", O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;
	ssize_t n = read(fd, b, sizeof(b));
	close(fd);
	if (n != 4)
		return -1;
	uint32_t v = (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
	return v >= 1 && v <= 64 ? (int)v : -1;
}

// dm runs one device-mapper ioctl on a buffer that starts with a struct dm_ioctl.
static int dm(int ctl, unsigned long cmd, struct dm_ioctl *io)
{
	return ioctl(ctl, cmd, io);
}

static void dm_init(struct dm_ioctl *io, size_t size, const char *name)
{
	memset(io, 0, size);
	io->version[0] = DM_VERSION_MAJOR;
	io->version[1] = 0;
	io->version[2] = 0;
	io->data_size = size;
	io->data_start = sizeof(*io);
	snprintf(io->name, sizeof(io->name), "%s", name);
}

// target creates the read-only device-mapper device name with one target and returns its
// device number.
static dev_t target(int ctl, const char *name, uint64_t sectors, const char *type, const char *params)
{
	union {
		struct dm_ioctl io;
		char buf[sizeof(struct dm_ioctl) + sizeof(struct dm_target_spec) + 1024];
	} u;
	struct dm_target_spec *spec;
	size_t plen = strlen(params) + 1;

	if (plen > 1024)
		return 0;
	dm_init(&u.io, sizeof(u), name);
	u.io.flags = DM_READONLY_FLAG;
	if (dm(ctl, DM_DEV_CREATE, &u.io) < 0)
		return 0;
	dev_t dev = (dev_t)u.io.dev;

	dm_init(&u.io, sizeof(u), name);
	u.io.flags = DM_READONLY_FLAG;
	u.io.target_count = 1;
	spec = (struct dm_target_spec *)(u.buf + sizeof(struct dm_ioctl));
	spec->sector_start = 0;
	spec->length = sectors;
	spec->status = 0;
	spec->next = 0;
	snprintf(spec->target_type, sizeof(spec->target_type), "%s", type);
	memcpy((char *)(spec + 1), params, plen);
	if (dm(ctl, DM_TABLE_LOAD, &u.io) < 0)
		return 0;

	dm_init(&u.io, sizeof(u), name);
	if (dm(ctl, DM_DEV_SUSPEND, &u.io) < 0) // no DM_SUSPEND_FLAG: resume, making the table live
		return 0;
	return dev;
}

// wait_for waits up to 30 s for path to exist (an mmc or virtio disk probes after init starts).
static int wait_for(const char *path)
{
	struct timespec ts = {0, 100 * 1000 * 1000};
	struct stat st;

	for (int i = 0; i < 300; i++) {
		if (stat(path, &st) == 0 && S_ISBLK(st.st_mode))
			return 0;
		nanosleep(&ts, NULL);
	}
	return -1;
}

int main(void)
{
	static char cmdline[CMDLINE_MAX + 1];
	char disk[32], root[64], hash[32], roothash[80], salt[80], dev[64], params[512];
	uint64_t root_off, root_len, hash_off;
	struct stat st;
	char *colon;
	int fd;

	if (getpid() != 1)
		return 1;
	if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755") < 0 && errno != EBUSY)
		fail("cannot mount /dev");
	if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0)
		fail("cannot mount /proc");
	if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY, NULL) < 0)
		fail("cannot mount /sys");

	fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		fail("cannot read the command line");
	ssize_t n = read(fd, cmdline, CMDLINE_MAX);
	close(fd);
	if (n <= 0 || n == CMDLINE_MAX)
		fail("command line unreadable or too long");
	cmdline[n] = 0;

	errno = EINVAL;
	if (!param(cmdline, "camnode.disk", disk, sizeof(disk)) || !*disk || strchr(disk, '/') || strchr(disk, '.'))
		fail("camnode.disk missing");
	if (!param(cmdline, "camnode.root", root, sizeof(root)) || !(colon = strchr(root, ':')))
		fail("camnode.root missing");
	*colon = 0;
	if (number(root, &root_off) || number(colon + 1, &root_len))
		fail("camnode.root is not OFFSET:LENGTH in whole blocks");
	if (!param(cmdline, "camnode.hash", hash, sizeof(hash)) || number(hash, &hash_off))
		fail("camnode.hash is not an offset in whole blocks");
	if (hash_off < root_off + root_len)
		fail("hash tree overlaps the root");
	if (!param(cmdline, "camnode.roothash", roothash, sizeof(roothash)) || hex64(roothash))
		fail("camnode.roothash is not 64 hex digits");
	if (!param(cmdline, "camnode.salt", salt, sizeof(salt)) || hex64(salt))
		fail("camnode.salt is not 64 hex digits");

	int part = booted();
	if (part < 0)
		fail("bootloader partition unreadable");
	char last = disk[strlen(disk) - 1];
	snprintf(dev, sizeof(dev), "/dev/%s%s%d", disk, (last >= '0' && last <= '9') ? "p" : "", part);
	if (wait_for(dev) < 0)
		fail("slot partition did not appear");
	if (stat(dev, &st) < 0)
		fail("cannot stat the slot partition");
	unsigned int maj = major(st.st_rdev), min = minor(st.st_rdev);

	int ctl = open("/dev/mapper/control", O_RDWR | O_CLOEXEC);
	if (ctl < 0)
		fail("cannot open device-mapper");
	// The root's blocks, at their offset in the slot.
	snprintf(params, sizeof(params), "%u:%u %llu", maj, min, (unsigned long long)(root_off / 512));
	dev_t data = target(ctl, "camnode-data", root_len / 512, "linear", params);
	if (!data)
		fail("cannot map the root");
	// verity over them, with the hash tree from the same slot. A block that fails restarts the
	// board (restart_on_corruption), so a corrupted root never runs.
	snprintf(params, sizeof(params),
		 "1 %u:%u %u:%u %u %u %llu %llu sha256 %s %s 1 restart_on_corruption",
		 major(data), minor(data), maj, min, BLOCK, BLOCK,
		 (unsigned long long)(root_len / BLOCK), (unsigned long long)(hash_off / BLOCK), roothash, salt);
	dev_t verity = target(ctl, "camnode-root", root_len / 512, "verity", params);
	close(ctl);
	if (!verity)
		fail("cannot set up verity");
	if (mknod("/dev/camnode-root", S_IFBLK | 0400, verity) < 0 && errno != EEXIST)
		fail("cannot make the root's node");

	// Read every block once, so a flipped byte anywhere in the root stops this boot, not some
	// later read of the block that holds it.
	fd = open("/dev/camnode-root", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		fail("cannot open the root");
	static char buf[1 << 20];
	uint64_t total = 0;
	for (;;) {
		ssize_t r = read(fd, buf, sizeof(buf));
		if (r < 0)
			fail("root does not verify");
		if (r == 0)
			break;
		total += r;
	}
	close(fd);
	errno = EIO;
	if (total != root_len)
		fail("root is shorter than the command line says");

	if (mount("/dev/camnode-root", "/root", "erofs", MS_RDONLY | MS_NODEV | MS_NOSUID, NULL) < 0)
		fail("cannot mount the root");
	say("camnode-init: slot %d root %s verified, mounted read-only (erofs)", part, roothash);

	if (umount2("/proc", MNT_DETACH) < 0)
		fail("cannot unmount /proc");
	if (umount2("/sys", MNT_DETACH) < 0)
		fail("cannot unmount /sys");
	if (mount("/dev", "/root/dev", NULL, MS_MOVE, NULL) < 0)
		fail("cannot move /dev");
	unlink("/init");
	if (chdir("/root") < 0 || mount(".", "/", NULL, MS_MOVE, NULL) < 0 || chroot(".") < 0 || chdir("/") < 0)
		fail("cannot switch to the root");
	execl("/sbin/init", "/sbin/init", (char *)NULL);
	fail("cannot start systemd");
	return 1;
}
