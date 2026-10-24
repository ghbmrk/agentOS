// Package run runs each credentialed clerk as a process of its own (MIG-4-run,
// #2682; option A): each clerk's process, under its own uid, holds that one
// account's Secrets file and no other (CLK-1, STO-3), and sees the log only
// through the view the kernel sends with each call. The kernel's process is
// broker/kernel/proc, which links none of this package (KRN-2 split, #2892);
// both sides speak its wire.
package run

import "github.com/ghbmrk/agentos/broker/kernel/proc"

// The clerks' errors that cross a socket by their text (proc.WireErrors).
func init() {
	proc.WireErrors(ErrModelCall, ErrNoMailAccount, ErrMailAddress, ErrMailServer, ErrMailUser,
		ErrWeakMailPassword, ErrBadGrant, ErrNoReconnect)
}
