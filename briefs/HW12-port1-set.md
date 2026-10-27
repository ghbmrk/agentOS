# HW12-port1-set: the page's firewall rule admits only port 1

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3377, the release findings of #3350 (WIFI-del-a3): Security 6439499058 point 1 and L3 6439420847 point 1, recorded as the follow-up of netguard ASSUMPTIONS WIFI-del-a3-1. Tier A. No `cmd/agentosd` file (D-111).

**Why.** The inbound table admits the page's TCP 80 and 443 on every interface named `en*`. USB and Thunderbolt Ethernet links (the edge's cable, HW-15, a plugged-in dongle) match, so they answer those ports with a reset from the socket binding instead of dropping at the firewall, and the page's exclusivity rests on `SO_BINDTODEVICE` alone. A port 1 with a kernel `eth*` name is the other failure: the page logs that it listens while the firewall drops every request, and the owner sees a page that never loads with no reason anywhere.

**Design.** The image names port 1 at run time, as the page already does (`localui.Port1`, or `AGENTOS_PAGE_IFACE` in a drop-in); the root side puts that one name in the firewall.
1. **Set.** `netguard.Inbound.Page` renders an empty named set `page` (type ifname) and the rule `iifname @page ip saddr { RFC 1918 } tcp dport { 80, 443 } accept`; no wildcard interface match is left. The shipped `inbound.nft` is regenerated, so the boot loads the set empty: the page's ports are dropped on every interface until port 1 is chosen. `netguard.InboundPageAdmit(iface)` renders `flush set` then `add element` in one `nft -f` transaction, so the set holds exactly one name; it refuses `lo` and any name `ifaceRe` refuses. `netguard.InboundPageClose` renders the flush.
2. **Root step.** `agentos-localui.service` gains `ExecStartPre=+… -admit-port1` (the same binary and the same `settledPort1` the page used, run with full privileges for this one step) and `ExecStopPost=+/usr/sbin/nft flush set inet agentos_inbound page`. The step takes `-iface` or the settled `Port1`, refuses a name that is not a wired Ethernet link in sysfs (`localui.Wired`: it exists, `type` 1, no `wireless` or `phy80211`), so an override cannot open the page on a radio or the access point, loads the set, and writes the name to `/run/agentos-localui/port1` (`RuntimeDirectory=`, removed at every stop; created fresh, `O_EXCL|O_NOFOLLOW`, since root writes into the page user's directory). Any failure exits non-zero with a line naming the cause, and the stop clears the set. Every restart (the watcher's, a crash, a drop-in change) re-runs the step, so the set follows the page.
3. **Page refuses what the rule does not admit.** With `-port1-file`, the page reads the admitted name and serves only if it equals its port 1 (`-iface`, or one `Port1` read). A mismatch, or a missing file, exits with a log line naming both names, instead of listening behind a firewall that drops every request. `eth0` as port 1 is no longer a failure: the set holds whatever name port 1 has.

The CI boot has two NICs, so `Port1` names none and the page's ports are now dropped there too; `image/ci_boot.sh` expects `dropped` on 80 and 443 and I11 says why. The positive path stays with `broker/e2e/boxe2e`, whose drop-in names its veth, which the step admits.

**Requirement IDs:**
- **CH-9**: the page's ports are open at the firewall only on port 1, and closed when the page is not serving.
- **HW-15**: the edge's cable and any other link drop the page's ports at the firewall.
- **HW-12**: port 1 is the core's only owner-facing link.

**Acceptance tests:**
- CH-9, HW-15: `broker/netguard/inbound_test.go::TestInboundAdmitsThePagePortsOnlyOnPort1`. With the set holding `enp1s0`, private sources reach 80 and 443 there; `enx…`, `enp0s20f0u1`, `eno1`, `eth0`, `ap0`, `wlan0`, `usb0` drop; the empty set admits nothing; with `eth0` admitted, `eth0` reaches the page.
- CH-9: `broker/netguard/inbound_test.go::TestInboundPageAdmitHoldsOneName`. The script flushes then adds one element, and refuses `lo` and malformed names; the existing `TestInboundRulesAreValidNft` and `TestInboundImageFileIsTheDefault` cover the render and the shipped file.
- CH-9: `broker/localui/wired_test.go::TestWiredRefusesRadiosAndMissingLinks`.
- CH-9, HW-12: `broker/cmd/agentos-localui/main_test.go::TestAdmitPort1LoadsTheSetAndHandsOverTheName` (the step's nft script and hand-off file, its refusals, and the page's refusal of a port the firewall does not admit) and `::TestUnitAdmitsPort1AsRootAndClosesOnStop` (the unit's `+` step, its stop, `RuntimeDirectory`, `-port1-file`).

**Scope:** `broker/netguard/{inbound.go,inbound_test.go,ASSUMPTIONS.md}`; `image/mkosi/mkosi.extra/usr/lib/agentos/inbound.nft` (regenerated); `broker/localui/{wired.go,wired_test.go}`; `broker/cmd/agentos-localui/{main.go,main_test.go,agentos-localui.service}`; `broker/e2e/boxe2e/main_linux.go` (comment); `image/ci_boot.sh`, `image/ASSUMPTIONS.md` (I11), `tests/test_image.py` (the probe expectation); `image/mkosi/mkosi.finalize` and `tests/test_image_keeper.py` (STO-2c refuses `+` commands but `FULL_PRIVILEGE_EXEMPT`'s; the two commands above are allowed exactly as written, `FULL_PRIVILEGE_COMMANDS`, and any other `+` in the page's unit is still refused).

**Out of scope:** a page state that shows the refusal on the page itself (it serves nothing then; the journal carries the reason); IPv6 on the page's ports.

**Gate:** tier A. L3 on the strongest model and a separate Security accept (inbound firewall, a root step in the page's unit). Estimate: under 120k tokens.
