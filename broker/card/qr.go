package card

import (
	"fmt"
	"html/template"
	"strings"

	"rsc.io/qr"
)

// QRSVG renders text as a QR code (error correction M) in inline SVG, with
// the standard four-module quiet zone, so a page or card that shows it
// fetches nothing (ONB-1). It scales to its container.
func QRSVG(text string) (template.HTML, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := c.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" shape-rendering="crispEdges" class="qr" role="img" aria-label="QR code"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()), nil
}
