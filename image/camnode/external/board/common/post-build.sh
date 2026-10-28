#!/usr/bin/env bash
# Post-build (both boards): stage the node binary and the release key, the board's encoder,
# and refuse a root that has a shell, a login path, a getty, a remote shell or a setuid file
# (CAM-node part c; briefs/CAM-node.md, design point 5). Buildroot calls it with the target
# directory and BR2_ROOTFS_POST_SCRIPT_ARGS (the board). build.sh exports CAMNODE_BIN (the
# static agentos-camnode), CAMNODE_RELEASE_PUB (the release signer's public key) and, for the
# QEMU board, CAMNODE_E2E_DIR (the end-to-end stand-ins).
set -euo pipefail
TARGET=$1 BOARD=$2

: "${CAMNODE_BIN:?build.sh sets CAMNODE_BIN}" "${CAMNODE_RELEASE_PUB:?build.sh sets CAMNODE_RELEASE_PUB}"
install -D -m 0755 "$CAMNODE_BIN" "$TARGET/usr/bin/agentos-camnode"
install -D -m 0644 "$CAMNODE_RELEASE_PUB" "$TARGET/usr/share/agentos/camnode-release.pub"

mkdir -p "$TARGET/usr/libexec/camnode"
case $BOARD in
qemu)
	: "${CAMNODE_E2E_DIR:?build.sh sets CAMNODE_E2E_DIR for the QEMU board}"
	install -m 0755 "$CAMNODE_E2E_DIR/e2e-element" "$TARGET/usr/libexec/camnode/e2e-element"
	install -m 0755 "$CAMNODE_E2E_DIR/e2e-button" "$TARGET/usr/libexec/camnode/e2e-button"
	install -m 0755 "$CAMNODE_E2E_DIR/e2e-encoder" "$TARGET/usr/libexec/camnode/encoder"
	;;
cm4)
	[ -x "$TARGET/usr/bin/rpicam-vid" ] || { echo "post-build: rpicam-vid missing" >&2; exit 1; }
	ln -sfn ../../bin/rpicam-vid "$TARGET/usr/libexec/camnode/encoder"
	;;
*)
	echo "post-build: unknown board $BOARD" >&2
	exit 1
	;;
esac

# No console login or shell path: the getty templates, the debug shell and the units that
# would run sulogin go, so nothing can start one even if asked.
for u in getty@.service serial-getty@.service console-getty.service container-getty@.service \
	autovt@.service debug-shell.service emergency.service rescue.service; do
	rm -f "$TARGET/usr/lib/systemd/system/$u" "$TARGET/etc/systemd/system/$u"
done
rm -rf "$TARGET/usr/lib/systemd/system/getty.target.wants" "$TARGET/etc/systemd/system/getty.target.wants"
rm -f "$TARGET/usr/lib/systemd/system-generators/systemd-getty-generator"
# Buildroot's systemd selects util-linux's agetty and sulogin; with no shell they are inert, but
# they go too, so the check below holds for every file.
rm -f "$TARGET/usr/bin/agetty" "$TARGET/usr/bin/getty" "$TARGET/usr/sbin/agetty" "$TARGET/sbin/agetty" \
	"$TARGET/usr/bin/sulogin" "$TARGET/usr/sbin/sulogin" "$TARGET/sbin/sulogin" \
	"$TARGET/usr/lib/systemd/systemd-sulogin-shell"
# systemd's SSH glue (the generator that would open sshd on vsock, its proxy and config) has no
# sshd to start; it goes so nothing in the root names a remote shell.
rm -rf "$TARGET/etc/ssh" "$TARGET/usr/lib/systemd/ssh_config.d" \
	"$TARGET/usr/lib/systemd/system-generators/systemd-ssh-generator" \
	"$TARGET/usr/lib/systemd/systemd-ssh-proxy" "$TARGET/usr/lib/systemd/systemd-ssh-issue" \
	"$TARGET/usr/lib/systemd/system/ssh-access.target" "$TARGET/usr/lib/tmpfiles.d/20-systemd-ssh-generator.conf"
# util-linux installs mount and umount setuid, and dbus its activation helper: only root (systemd)
# mounts and the node activates nothing over D-Bus, so those three lose the bit; any other setuid
# file still fails the check below.
chmod u-s,g-s "$TARGET/usr/bin/mount" "$TARGET/usr/bin/umount"
[ ! -e "$TARGET/usr/libexec/dbus-daemon-launch-helper" ] || chmod u-s,g-s "$TARGET/usr/libexec/dbus-daemon-launch-helper"

# Refuse what the brief bars. Names are matched anywhere in the root, directories too.
bad=$(cd "$TARGET" && find . \( -name sh -o -name bash -o -name dash \
	-o -name ash -o -name zsh -o -name ksh -o -name busybox -o -name toybox -o -name sshd \
	-o -name ssh -o -name dropbear -o -name telnetd -o -name login -o -name agetty \
	-o -name getty -o -name sulogin -o -name su -o -name sudo -o -name nc -o -name socat \
	-o -name 'systemd-sulogin-shell' -o -name 'getty@.service' -o -name 'serial-getty@.service' \
	-o -name 'debug-shell.service' \) | sort)
if [ -n "$bad" ]; then
	echo "post-build: the root may not hold these:" >&2
	echo "$bad" >&2
	exit 1
fi
suid=$(cd "$TARGET" && find . -type f \( -perm -4000 -o -perm -2000 \) | sort)
if [ -n "$suid" ]; then
	echo "post-build: setuid or setgid files in the root:" >&2
	echo "$suid" >&2
	exit 1
fi
