#!/bin/sh
# Offline A/B update from a second drive labelled S7UPD (DEP-4 path). No-op without that drive.
udevadm settle
[ -e /dev/disk/by-label/S7UPD ] || exit 0
mkdir -p /run/s7-updates && mount -o ro /dev/disk/by-label/S7UPD /run/s7-updates
S=$(date +%s)
/usr/lib/systemd/systemd-sysupdate --no-pager update > /run/s7-sysupdate.log 2>&1; RC=$?
sed 's/^/S7U: /' /run/s7-sysupdate.log | tail -8
echo "S7U: update_rc=$RC secs=$(( $(date +%s)-S ))"
lsblk -no NAME,PARTLABEL,SIZE | sed 's/^/S7U: /'
echo "S7U: done"
