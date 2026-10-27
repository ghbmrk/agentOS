package card

import (
	"strings"
	"testing"
)

// REQ: HW-1, ONB-7, CH-9
//
// The Owner Card and the rotation card print the box page by the page's
// name over HTTPS, the one name its authority certifies (CH-9), never the
// access point address the core no longer serves (D-178, WIFI-del-c).
func TestCardPrintsThePageByItsName(t *testing.T) {
	if BoxPage != "https://"+PageName+"/" {
		t.Fatalf("BoxPage = %q", BoxPage)
	}
	c := mustGen(t, 7)
	full, err := HTML(c)
	if err != nil {
		t.Fatal(err)
	}
	rot, err := rotationHTML(c, Parts{WiFi: true, Setup: true})
	if err != nil {
		t.Fatal(err)
	}
	for name, page := range map[string]string{"card": string(full), "rotation": string(rot)} {
		if !strings.Contains(page, `<span class="mono">`+BoxPage+`</span>`) {
			t.Fatalf("%s lacks the box page %q", name, BoxPage)
		}
		if strings.Contains(page, "10.42.0.1") || strings.Contains(page, `<span class="mono">http://`) {
			t.Fatalf("%s still names a plain or access point address", name)
		}
	}
}
