package firstboot

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/pageca"
)

var (
	authOnce sync.Once
	authDER  []byte
	authErr  error
)

// testAuthority is one page authority's certificate, shared by this
// package's tests, which give it to every card step (HW-1).
func testAuthority(t testing.TB) []byte {
	t.Helper()
	authOnce.Do(func() {
		var a *pageca.Authority
		if a, authErr = pageca.New(pageca.DefaultName, time.Now(), nil); authErr == nil {
			authDER = a.Certificate()
		}
	})
	if authErr != nil {
		t.Fatal(authErr)
	}
	return bytes.Clone(authDER)
}
