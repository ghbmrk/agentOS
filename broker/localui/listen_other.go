//go:build !linux

package localui

import (
	"context"
	"errors"
	"net"
)

// Listen is Linux only: CH-9 relies on binding to the access point
// interface.
func Listen(context.Context, APConfig, int) (net.Listener, error) {
	return nil, errors.New("localui: the local UI runs only on Linux")
}
