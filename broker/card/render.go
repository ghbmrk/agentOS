package card

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/ghbmrk/agentos/broker/owner"
)

// WaitMinutes is how long the card tells the owner to wait for the box's
// Wi-Fi after power-on. ONB-4's frozen target is set from S1's timings on
// real PCs; this is the provisional value until then.
const WaitMinutes = 3

// BoxAddr is the box's address on its own Wi-Fi, the same in every image,
// and BoxPage the local UI's address printed on the card, so the owner can
// always get back to it (status, STOP, RESUME, sign-in).
const (
	BoxAddr = "10.42.0.1"
	BoxPage = "http://" + BoxAddr + "/"
)

// QuickStart is the card's quick-start, at most five steps (ONB-7).
var QuickStart = []string{
	"Put the SIM in the modem. Plug the drive and the modem into the back of the PC.",
	"Turn the PC on. No screen or keyboard is needed. Your PC's own disks are left untouched.",
	fmt.Sprintf("Wait %d minutes, then point your phone's camera at the Wi-Fi code.", WaitMinutes),
	"Join the Wi-Fi. The setup page opens by itself; follow it.",
	"Done. Text your box any time. Text HELP for commands.",
}

// BootKey is one brand's one-time boot menu key.
type BootKey struct{ Brand, Key string }

// BootKeys are the boot menu keys of major PC brands (ONB-7), pressed
// repeatedly right after power-on. [Inference: vendor documentation; S1
// checks them on real PCs.]
var BootKeys = []BootKey{
	{"Dell", "F12"},
	{"HP", "F9 (or Esc, then F9)"},
	{"Lenovo", "F12 (ThinkPad: F12; some IdeaPads: Novo button)"},
	{"ASUS", "F8 (laptops: Esc)"},
	{"Acer", "F12"},
	{"MSI", "F11"},
	{"Gigabyte", "F12"},
	{"ASRock", "F11"},
	{"Intel NUC", "F10"},
	{"Microsoft Surface", "Hold Volume Down while pressing Power"},
	{"Others", "Try F12, F11, F10, F8 or Esc"},
}

type gridRow struct {
	Row   int
	Cells []string
}

type view struct {
	*Card
	WiFiQR, PassQR template.HTML
	QuickStart     []string
	BootKeys       []BootKey
	WaitMinutes    int
	BoxPage        string
	GridCols       []string
	Grid           []gridRow
	GridCheck      string
}

// HTML renders the card as a printable page: the card itself (front and
// back), the paper grid sheet, and the recovery key sheet. It is fully
// self-contained, with QR codes as inline SVG (ONB-1).
func HTML(c *Card) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	wq, err := QRSVG(WiFiQR(c.WiFiName, c.WiFiPassword))
	if err != nil {
		return nil, err
	}
	pq, err := QRSVG(c.VaultPassphrase)
	if err != nil {
		return nil, err
	}
	v := view{Card: c, WiFiQR: wq, PassQR: pq, QuickStart: QuickStart, BootKeys: BootKeys, WaitMinutes: WaitMinutes, BoxPage: BoxPage,
		GridCols: []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"}, GridCheck: GridCheck(c.GridSeed)}
	labels := owner.GridLabels()
	for r := 0; r < 10; r++ {
		row := gridRow{Row: r + 1}
		for _, l := range labels[r*10 : r*10+10] {
			row.Cells = append(row.Cells, owner.GridCell(c.GridSeed, l))
		}
		v.Grid = append(v.Grid, row)
	}
	var b bytes.Buffer
	if err := cardTmpl.Execute(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

var cardTmpl = template.Must(template.New("card").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AgentOS Owner Card</title>
<style>
@page { margin: 12mm; }
body { font-family: system-ui, sans-serif; color: #000; background: #fff; margin: 0; }
.sheet { page-break-after: always; break-after: page; padding: 4mm; }
.sheet:last-child { page-break-after: auto; break-after: auto; }
.card { border: 1px dashed #000; padding: 6mm; margin-bottom: 6mm; }
h1 { font-size: 18pt; margin: 0 0 3mm; } h2 { font-size: 13pt; margin: 0 0 2mm; }
.row { display: flex; gap: 6mm; align-items: flex-start; }
.qr { width: 38mm; height: 38mm; flex: none; }
.mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12pt; letter-spacing: .04em; }
.big { font-size: 15pt; font-weight: 600; }
.note { font-size: 9pt; }
ol { margin: 0; padding-left: 5mm; } li { margin-bottom: 1mm; }
table { border-collapse: collapse; } td, th { border: 1px solid #000; padding: 1mm 1.5mm; }
.grid td { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 10pt; text-align: center; }
.keys td { font-size: 9pt; }
</style></head><body>

<section class="sheet">
<div class="card">
<h1>AgentOS Owner Card</h1>
<p class="note">Keep this card like a passport, apart from the drive. Anyone with both can read your data.</p>
<div class="row">
{{.WiFiQR}}
<div>
<h2>Box Wi-Fi</h2>
<p>Name: <span class="mono big">{{.WiFiName}}</span><br>
Password: <span class="mono big">{{.WiFiPassword}}</span></p>
<p>Box page: <span class="mono">{{.BoxPage}}</span></p>
<h2>Quick start</h2>
<ol>{{range .QuickStart}}<li>{{.}}</li>{{end}}</ol>
</div></div>
</div>

<div class="card">
<h2>Nothing happened?</h2>
<p>Wait {{.WaitMinutes}} minutes after turning the PC on, then look for the Wi-Fi <span class="mono">{{.WiFiName}}</span>.
Wi-Fi joined but no page? Open <span class="mono">{{.BoxPage}}</span> in your browser.
If the Wi-Fi never appears, the PC did not start from the drive. Turn it off, then on, and press its boot key until a menu appears; choose the USB drive.</p>
<table class="keys">{{range .BootKeys}}<tr><td>{{.Brand}}</td><td>{{.Key}}</td></tr>{{end}}</table>
</div>

<div class="card">
<h2>Setup code</h2>
<p><span class="mono big">{{.SetupCode}}</span> <span class="note">(text it to your box if the setup page asks)</span></p>
<h2>Vault passphrase</h2>
<div class="row">
{{.PassQR}}
<div><p class="mono big">{{.VaultPassphrase}}</p>
<p class="note">Only for starting the box on a PC it does not know: type it on the box page, or scan this code with your phone's camera, tap Copy, and paste it there. Never send it by text or say it on a call.
If this drive was out of your hands, unlock it only on your trusted PC.
The box cannot print this again; keep the card.</p></div>
</div>
</div>
</section>

<section class="sheet">
<h1>Approval code grid</h1>
<p class="note">Tear off and keep apart from the box and from this card. Use it when your phone's code generator is not at hand: the box asks for one cell, such as C7. Each cell works once.</p>
<table class="grid"><tr><th></th>{{range .GridCols}}<th>{{.}}</th>{{end}}</tr>
{{range .Grid}}<tr><th>{{.Row}}</th>{{range .Cells}}<td>{{.}}</td>{{end}}</tr>
{{end}}</table>
<p class="note">Grid check code: <span class="mono">{{.GridCheck}}</span> (the box may ask for it after a new grid).</p>
</section>

<section class="sheet">
<h1>Recovery key</h1>
<p class="note">Tear off and store somewhere safe, apart from the drive and the grid. It restores your box onto new hardware and replaces a lost phone or number. You will rarely need it. The box cannot print this again, so keep this sheet.</p>
<p class="mono big">{{.RecoveryKey}}</p>
<h2>Reset secret</h2>
<p class="note">Only for re-running setup after a reset.</p>
<p class="mono">{{.SetupSecret}}</p>
</section>
</body></html>
`))
