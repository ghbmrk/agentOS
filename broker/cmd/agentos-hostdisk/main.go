// Command agentos-hostdisk reads the host PC's disks without touching them
// (HW-8, HW-8a; package hostdisk).
//
//	agentos-hostdisk classify NAME   udev helper: prints AGENTOS_DRIVE=1 for
//	                                 the AgentOS Drive, AGENTOS_DRIVE=0 else
//	agentos-hostdisk list            the host disks, described, as JSON
//
// It only reads partition tables and volume signatures, opened read-only.
// The image installs it at /usr/lib/agentos/agentos-hostdisk for
// udev/61-agentos-host-disks.rules.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ghbmrk/agentos/broker/hostdisk"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	var s hostdisk.System
	switch {
	case len(args) == 2 && args[0] == "classify":
		// Always exit 0 with a value, so udev records the answer; any
		// failure is AGENTOS_DRIVE=0 and the disk is hidden.
		fmt.Print(s.ClassifyEnv(args[1]))
		return 0
	case len(args) == 1 && args[0] == "list":
		ds, err := s.HostDisks()
		if err != nil {
			fmt.Fprintln(os.Stderr, "agentos-hostdisk:", err)
			return 1
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(ds); err != nil {
			return 1
		}
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: agentos-hostdisk classify NAME | list")
	return 2
}
