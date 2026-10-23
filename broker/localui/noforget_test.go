package localui

import (
	"net/http"
	"strings"
	"testing"
)

// REQ: CAP-3, CH-7

// FORGET is deleted from agentosd until the kernel's erase brings it back
// (#2781, #2823), so nothing backs a Forget page. The page is not served
// and home does not list it: a page that offered to ask could only fail
// and tell the owner to reload, a step that can never work (UX on #2827).
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
