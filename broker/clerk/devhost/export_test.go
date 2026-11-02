package devhost

import (
	"testing"
	"time"
)

// LowerMinSubscription lets a test run instances shorter than
// MinSubscription, until it ends.
func LowerMinSubscription(t *testing.T, d time.Duration) {
	old := minSubscription
	minSubscription = d
	t.Cleanup(func() { minSubscription = old })
}
