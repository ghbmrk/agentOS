# WIFI-del-a3: the page on the core's wired port

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3234, slice a3, after a2 (#3340). D-178: the core and the edge never turn Wi-Fi on, so the owner page is served on the core's port 1, its cable to the enforcer (HW-12), which routes the Owner network and its wired admin port to it (CH-9). Serial `cmd/agentosd` slot (D-111; one test file). Tier A.

**Why.** a2 removed agentosd's access point, but `agentos-localui` still listens on `wlan0` at `10.42.0.1/24` and admits only that subnet, so an image built from main serves no page once the access point is gone.

**Design.** The core's wired address comes from DHCP (`20-agentos-uplink.network`) and the Owner network is routed to it from another subnet, so neither a fixed address nor a subnet check works. Four layers replace them:
1. **Interface.** The page serves on one interface, `localui.Page.Iface`. `agentos-localui -iface` names it; empty (the image's default) takes the interface of the box's one IPv4 default route (`UplinkIface`, from `/proc/net/route`), since only port 1 carries the box's internet access (HW-12). No default route, or default routes on two interfaces, is an error: the page exits and its unit restarts it, as it did while the access point was coming up. The listener binds `0.0.0.0` on that interface with `SO_BINDTODEVICE`, so port 2, the edge's cable and any other link never reach it (HW-15: the core never serves the page on the edge's cable).
2. **Source.** Every request's source must be a private IPv4 address (RFC 1918) and not the address it reached, so nothing from the internet and nothing the box sends itself is served.
3. **Host.** Plain HTTP answers the page name (as before) or the IP literal of the address the connection reached, with the port when it is not 80; HTTPS answers the page name only, as before. An IP literal cannot be DNS-rebound, and it keeps the page reachable on a home network whose DNS does not answer the page name yet. The footer and the contact card name the page by its name.
4. **Firewall and unit.** The inbound table (`netguard.Inbound.Page`, loaded by the image as `netguard.Image`) admits TCP 80 and 443 from RFC 1918 sources on any interface not named `wl*`; the socket binding, not the firewall, picks the wired interface, and radios stay dropped since the core never turns Wi-Fi on (the station `wlsta0` while `agentos-ap` ships). The zero value still admits nothing. The unit's `IPAddressAllow` is the three RFC 1918 ranges. The image's boot probe then reads 80 and 443 answered from QEMU's private 10.0.2.2 and every other port dropped.

`APConfig` stays for `agentos-ap` until WIFI-del-b (#3235) deletes it.

**Requirement IDs:**
- **CH-9** (D-178): the page is reached only on the core's port 1, only from private home addresses, under its name or the address the connection reached.
- **HW-15**: the page is not served on the edge's cable or any interface but port 1.
- **ONB-5**: captive-portal checks are still refused with 421 and no redirect (a2's tests, unchanged in meaning).

**Acceptance tests:**
- CH-9, HW-15: `broker/localui/wired_test.go::TestUplinkIsTheOneDefaultRoute`. One up IPv4 default route names its interface; none, a reject or down route, `lo`, or default routes on two interfaces are errors. It catches a page that serves on a guessed interface.
- CH-9: `broker/localui/wired_test.go::TestPageAdmitsOnlyPrivateHomeSources`. A source on another private subnet than the box's is served; a public, loopback, IPv6, malformed source, the box's own address, or a request with no local address is 403.
- CH-9: `broker/localui/wired_test.go::TestPageAnswersItsNameAndTheAddressReached`. Host = the reached address (and `addr:port` off port 80) and the page name are served; another private IP literal is 421.
- CH-9: `broker/localui/wired_test.go::TestPageRefusesABadInterface`. `New` and `Listen` refuse an empty, `lo` or malformed interface and a bad page name.
- CH-9: `broker/netguard/inbound_test.go::TestInboundAdmitsThePagePortsFromPrivateSources` and the existing `TestInboundImageFileIsTheDefault`.
- CH-9, HW-15: `broker/cmd/agentos-localui/main_test.go::TestUnitServesThePageOnTheWiredPort`. The unit names no `wlan0`, no `-addr` and no `10.42.0.0/24`, and allows only the RFC 1918 ranges.

**Scope:** `broker/localui` (`wired.go` and `wired_test.go` new, `listen_linux.go`, `listen_other.go`, `server.go`, `pages.go`, `ap.go` comments, `ASSUMPTIONS.md`, and the tests that build a `Config` or a request: `localui_test.go`, `agent_test.go`, `tls_test.go`, `signout_test.go`, `wifidel_test.go`, `claim_test.go`, `cardwire_test.go`, `rotation_test.go` and every test calling `testAP()`); `broker/cmd/agentos-localui` (`main.go`, `main_test.go`, `agentos-localui.service`); `broker/netguard` (`inbound.go`, `inbound_test.go`, `ASSUMPTIONS.md`); `image/mkosi/mkosi.extra/usr/lib/agentos/inbound.nft` (regenerated), `image/ci_boot.sh` and `tests/test_image.py` (the boot probe's 80 and 443 now answer), `image/ASSUMPTIONS.md` (I11); `broker/e2e/boxe2e/main_linux.go` (the phone reaches the page on a wired veth through the firewall rule, with `AGENTOS_PAGE_IFACE` naming it); `broker/cmd/agentosd/setupclaim_test.go` (its page config).

**Out of scope (findings):** the Owner Card's and claim sticker's printed `http://10.42.0.1/` (`card.BoxAddr`, `cmd/agentos-seller`), which need the enforcer's name and a claim link that survives the HTTPS redirect; IPv6 on the page port.

**Gate:** tier A. L3 on the strongest model. Security, because the PR changes the page's source and host checks, its listener and the inbound firewall (CH-9). Estimate: under 150k tokens.
