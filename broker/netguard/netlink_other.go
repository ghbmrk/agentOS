//go:build !linux

package netguard

import (
	"context"
	"errors"
)

// WatchNetlink is Linux only; elsewhere the poll alone applies.
func WatchNetlink(context.Context) (<-chan struct{}, error) {
	return nil, errors.New("netguard: netlink is Linux only")
}
