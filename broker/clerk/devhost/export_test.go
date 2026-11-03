package devhost

import (
	"testing"
	"time"
)

// LowerMinSubscription lets a test run instances shorter than
// MinSubscription, until it ends. It only lowers the floor: a d above the
// current floor leaves it as it is.
func LowerMinSubscription(t *testing.T, d time.Duration) {
	old := minSubscription
	minSubscription = min(old, d)
	t.Cleanup(func() { minSubscription = old })
}
