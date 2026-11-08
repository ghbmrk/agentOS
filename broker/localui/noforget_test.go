package localui

import (
	"net/http"
	"strings"
	"testing"
)

// REQ: CAP-3, CH-7

// FORGET's task list is deleted from agentosd (#2781), so nothing backs
// it: home does not list it, and without agentosd's erase ops (the erase
// by name, KRN-forget-c-page, D-284) no Forget page is served: a page that offered to
// ask could only fail and tell the owner to reload, a step that can never
// work (UX on #2827).
func TestNoForgetPageWhileForgetIsDeleted(t *testing.T) {
	a := newApprovalRig(t)
	home := a.get("/home")
	if strings.Contains(home, `href="/forget/"`) || strings.Contains(home, "Forget a task") {
		t.Fatalf("home lists a Forget page:\n%s", home)
	}
	for _, p := range []string{"/forget/", "/forget/ask"} {
		if w := a.do("GET", p, nil); w.Code != http.StatusNotFound {
			t.Fatalf("GET %s: %d, want 404", p, w.Code)
		}
	}
}
