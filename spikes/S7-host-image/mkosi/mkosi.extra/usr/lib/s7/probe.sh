#!/bin/sh
# Prints one "S7:" line per fact; the host-side check parses these.
echo "S7: version=$(. /usr/lib/os-release; echo ${IMAGE_VERSION:-unknown})"
echo "S7: secureboot=$(mokutil --sb-state 2>&1 | head -1)"
echo "S7: usr=$(findmnt -no SOURCE /usr)"
echo "S7: usr_ro=$(findmnt -no OPTIONS /usr | tr ',' '\n' | grep -x ro)"
echo "S7: verity=$(veritysetup status usr 2>/dev/null | grep -m1 status | tr -s ' ')"
echo "S7: bootdisk=$(lsblk -no TRAN $(findmnt -no SOURCE / | sed 's/[0-9]*$//') 2>/dev/null | head -1)"
echo "S7: tpm=$(ls /dev/tpmrm0 2>/dev/null)"
echo "S7: mm=$(command -v ModemManager) nm=$(command -v NetworkManager)"
echo "S7: done"
