//go:build !linux

package quota

import (
	"errors"
	"os"
)

var errNotLinux = errors.New("not Linux")

func getInfo(*os.File) error                         { return errNotLinux }
func setProject(*os.File, uint32) error              { return errNotLinux }
func setLimits(*os.File, uint32, int64, int64) error { return errNotLinux }
func getQuota(*os.File, uint32) (Usage, error)       { return Usage{}, errNotLinux }
func enforced(fn func() error) error                 { return fn() }
