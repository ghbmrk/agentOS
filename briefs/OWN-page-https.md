# OWN-page-https: the owner page over HTTPS on the core's name, behind a name-constrained page authority

Work item #3153 (SPEC CH-9, HW-1, §19 risk 30). Tier A. Written 2026-10-25 against main at 460656b. It unblocks turning on `-passkey-rp-id` (#2779a, `briefs/MIG-4-untrusted-reconnect-a.md`), #2779b and #2779c.

## Why

WebAuthn runs only in a secure context, with a domain as its RP ID, and `broker/kernel/ASSUMPTIONS.md` MIG-2-a requires the assertion's origin to be `https://<RP ID>` on a host that serves only the owner page. The local UI today is plain HTTP on the box's address (`broker/localui/ASSUMPTIONS.md` L6, L13), and `agentos-localui` refuses `-passkey-rp-id` while it serves plain HTTP (#2779a, naming #3153). KEY-4 puts every widening behind a passkey tap, and home control is after the first release (A18), so every first-release box needs this page without an enforcer.

## Open point: how the authority reaches the phone without home control

SPEC CH-9 has the enforcer install the core's authority on the phone, in its passkey-enrol step (§12.1 step 4). It gives no install path where home control is not installed, which is every first-release box, and it says that box needs "no domain or public certificate". It goes to Mark as a card. **Slice (b) below waits on the answer; slice (a) does not**, because it is the same under every option.

Recommended answer (the one slice (b) is written for): **the core installs its own authority on its access point.** In §12.1 step 4 on a box without home control, before the first passkey step, the core's page (plain HTTP on its WPA3 access point, the only path before any trust exists) offers the authority certificate for install, shows its fingerprint and the platform's extra trust step. The first install has no fingerprint check, as under home control (risk 30); the attacker must already be on the box's WPA3 network before setup. A reinstall (a new phone, REC-3, or a browser warning) is a CH-7 step on the same page, and the owner checks the fingerprint against the Owner Card first. When home control is added later the enforcer installs only its own certificate. This needs an L1 spec diff to CH-9 and §12.1 step 4.

## Slices

- **(a) this build: authority, serving certificate, HTTPS listener.** Buildable now. With no authority installed on a phone the HTTPS page is simply untrusted there, so nothing turns on early.
- **(b) the install step**, after the card answer: the authority's download and install page and the reinstall step (scope below).
- Follow-on rows for the coordinator to file (outside this brief's scope): the fingerprint and the core's name on the Owner Card (HW-1, which today renders through the vault-backed `localui.CardBox`), the authority key in the backup and its restore (BAK-1, §12.2), the L1 spec diff, and qualification on real phones (the [Inference] items in ASSUMPTIONS rows 3 and 4 below, G1).

## Design (slice a)

1. **The name.** One fixed name, `agentos.internal` (ICANN's private-use TLD, 2024). It is a leaf: nothing is ever served on a subdomain. A TLD is a public suffix to browsers whether or not the public suffix list names it (the list's default rule), so the core's name and any enforcer name under it share no registrable parent or cookie scope (NET-4). It is configuration (`-page-name`, default above) so qualification can change it without code.
2. **Resolution.** `DnsmasqConf` answers the name with the box's access-point address in both modes (`address=/<name>/<addr>`), so it is never forwarded upstream. Today only the captive mode resolves every name to the box.
3. **The authority** (new package `broker/pageca`). ECDSA P-256. Self-signed, `IsCA`, `MaxPathLenZero`, key usage cert-sign only, extended key usage server-auth only. Name constraints marked critical: permitted DNS name exactly the page name; excluded DNS `.<name>` (subdomains); excluded IP ranges `0.0.0.0/0` and `::/0`; no email or URI names. Valid 30 years from a NotBefore fixed one day before the image's build time (an input), never from the clock, so a wrong first-boot clock cannot stamp a 30-year certificate that phones refuse. Its fingerprint is SHA-256 of the DER, rendered as groups for the card.
   - Kept as a sealed secret: `pageca.Store` seals the PKCS#8 key under a `clerk.Sealer` with fixed AAD, writes atomically with no-follow opens (0600, root), and opens it at start. Until STO-2 wires the real store into agentosd, `agentosd` takes the sealer from `-page-ca-sealkey` (a 32-byte key file, `clerk.NewAESSealer`), as #2682's slices do; an empty flag means no authority and no HTTPS (fail closed, logged once with a fixed text).
   - Generated once: at agentosd start when no authority file exists **and** the box is fresh (no claim recorded). If the box is claimed and the file is missing or does not open, agentosd never generates a new one, since the card already carries the old fingerprint: HTTPS stays off and the page says the box must be restored. Generation comes before any Owner Card is made (HW-1).
4. **Who holds what.** The authority key never enters the web-facing process. `agentosd` (root) holds it, through `localsrv`. `agentos-localui` (its own uid) makes its serving key in memory at start, never writes it, and asks over `localui.sock` for a certificate: one new `localapi` op, `certify(pub)`, which returns the leaf and the authority certificate. `pageca.Issue` signs only the page name, only server-auth, ECDSA P-256 public keys only, for `min(825 days, authority NotAfter)`, NotBefore `max(build time, now − 1 day)`. `localui`'s `imports_test.go` stops it importing `pageca`.
5. **Renewal without the owner.** `localui` asks again at every start and every 24 hours, with a fresh key each time, and swaps the certificate through `tls.Config.GetCertificate`. A wrong clock is thereby fixed within a day of being corrected. A failed renewal keeps the current certificate and retries hourly, logged with a fixed text and no error string.
6. **The HTTPS listener.** `localui` listens on 443 on the access point (`Listen` as today: address plus `SO_BINDTODEVICE`), TLS 1.3 only. The handshake is refused unless SNI equals the page name. On 443 a request whose Host is not exactly the page name (port optional) is refused with 421 and never redirected (L6's redirect stays on port 80 only). Every HTTPS response carries `Strict-Transport-Security: max-age=63072000`, so a phone that later sees a bad certificate cannot click through (CH-9: no click-through), and `Referrer-Policy: no-referrer`.
   - Cookies over HTTPS use `__Host-` names with `Secure`, no `Domain`, `Path=/`, `SameSite=Strict`, `HttpOnly` (CH-9). Origin checks accept only `https://<name>` there.
   - The CSP over HTTPS stays L6's (no script, no frames, no outside source) with `form-action 'self'`, `base-uri 'none'`, `frame-ancestors 'none'`; a page that needs a ceremony script adds only its `sha256-` hash, as the unlock page does today. One helper builds it, so #2779a's passkey page uses it.
   - Port 80 keeps serving what it serves today (claim, setup before trust, the captive-portal answers). Any request on port 80 for the page name itself is redirected to `https://<name>/` with the same path, so a phone that trusts the authority never stays on HTTP.
   - The passkey gate: `agentos-localui` accepts `-passkey-rp-id` only when it equals `-page-name` and the HTTPS listener is up; #2779a's start-up refusal changes from "plain HTTP" to that rule. The passkey pages mount on the HTTPS server only.
7. **Firewall.** `NftRules` admits tcp 443 from the access point to the box, beside 80, and nothing else changes.

## Design (slice b, after the card)

On port 80, while setup is open and before the first passkey step, and on 443 from a CH-7 reinstall link: a page that shows the fingerprint and serves the authority as an unsigned iOS configuration profile (`application/x-apple-aspen-config`, one `com.apple.security.root` payload) and as DER (`application/x-x509-ca-cert`) for Android, with the platform's trust steps in fixed text. The reinstall page asks the owner to compare the fingerprint the phone shows with the Owner Card's before trusting it, and to stop on a mismatch. It never serves the key, and it serves nothing once setup has closed except through a reinstall link. Scope: `broker/localui/authority.go` and its test, `pages.go`, `ASSUMPTIONS.md`. Acceptance tests are named in that PR after the card, against the answer.

## Lifecycle matrix (integration owner: this package)

| Stage | Authority | Serving certificate | Page |
|---|---|---|---|
| First boot, fresh box | generated, sealed, before any card | issued at localui start | HTTP as today; HTTPS up, trusted once installed (b) |
| Restart | opened from the sealed file; same fingerprint | new key and certificate | same |
| Claimed box, authority missing or unopenable | never regenerated | none | HTTP only; the restore text; passkey pages off |
| No sealer configured | none | none | HTTP only, logged once; passkey pages off |
| 24 h tick, clock corrected | unchanged | reissued | uninterrupted |
| Restore (follow-on row) | from the backup; same fingerprint | issued | same |

## Scope

`broker/pageca/` (new: `pageca.go`, `store.go`, their tests, `ASSUMPTIONS.md`), `broker/localsrv/{localsrv.go,certify.go,certify_test.go,ASSUMPTIONS.md}`, `broker/localapi/{localapi.go,localapi_test.go}`, `broker/localui/{tls.go,tls_test.go,ap.go,ap_test.go,server.go,pages.go,listen_linux.go,listen_other.go,imports_test.go,ASSUMPTIONS.md}`, `broker/cmd/agentos-localui/{main.go,main_test.go,agentos-localui.service}`, `broker/cmd/agentosd/{main.go,ASSUMPTIONS.md}` (call sites and flags only; this takes a slot in the serial `cmd/agentosd` chain, D-111), `image/mkosi/mkosi.extra/usr/lib/systemd/system/agentosd.service` (the sealer flag), this brief. Slice (b)'s files are listed in its section.

**Guard files:** `tools/risk_tier.py` (`pageca` in `TIER_A_BROKER`), `broker/daemon/arc2_test.go` (the `pageca` import rules: stdlib crypto and `clerk`'s `Sealer` only), `tools/g1_scope_g2.txt` (`pageca`'s coverage). Gate-file PR: it needs the separate Security accept (OPERATING §7).

## Acceptance tests

- CH-9 name constraint: `broker/pageca/pageca_test.go::TestAuthorityVerifiesOnlyThePageName`. A leaf for the name verifies under the authority with `x509.Verify`; leaves for `x.<name>`, another name, an IP and the name plus an extra SAN signed by the same key all fail. It catches a missing or non-critical constraint.
- CH-9 authority shape: `::TestAuthorityShape` (30 years from the build-time NotBefore whatever the clock; path length 0; usages; P-256), catching a clock-stamped or unconstrained root.
- CH-9 serving certificate: `::TestIssueCapsAndRefuses` (825-day cap, never past the authority, refuses a non-P-256 key or any other name), catching a long-lived or wrong-name leaf.
- CH-9 kept like a sealed secret, HW-1 order: `broker/pageca/store_test.go::TestStoreSealsAndReopensSameFingerprint`, `::TestStoreRefusesALinkedFile`, `::TestNeverRegeneratesOnAClaimedBox`, catching a plaintext key, a planted link, or a silent new fingerprint.
- Key custody: `broker/localsrv/certify_test.go::TestCertifyReturnsLeafNeverKey` and `broker/localui/imports_test.go` (`localui` does not link `pageca`), catching the authority key reaching the web-facing uid.
- CH-9 renewal: `broker/localui/tls_test.go::TestRenewsDailyWithAFreshKey`, `::TestFailedRenewalKeepsServing`.
- CH-9 Host and SNI (DNS rebinding): `::TestHTTPSRefusesOtherSNIAndHost`, catching a 443 redirect or a served wrong Host.
- CH-9 cookies, Origin, no click-through: `::TestHTTPSCookiesAreHostPrefixed`, `::TestHTTPSOriginIsTheName`, `::TestHTTPSSetsHSTSAndNoReferrer`, `::TestHTTPSCSPAdmitsOnlyHashedScript`.
- Port 80: `::TestHTTPRedirectsThePageNameToHTTPS` and the existing L6 tests unchanged.
- Resolution: `broker/localui/ap_test.go::TestDnsmasqPinsThePageNameInBothModes`, `::TestNftAdmits443FromTheAPOnly`.
- Passkey gate: `broker/cmd/agentos-localui/main_test.go::TestPasskeyRPIDMustBeThePageNameOverHTTPS` (replaces #2779a's plain-HTTP refusal test if that has merged).
- Fail closed: `broker/cmd/agentos-localui/main_test.go::TestNoAuthorityServesHTTPOnly`.

**Recurring kinds to check (security lens README):** a guard that fails open on a missing value (no sealer, no authority, empty SNI); a root-side file operation that follows a planted link (the sealed authority file); raw error text in a fixed-class log line; a brief scope that omits the test files the change forces.

## ASSUMPTIONS rows to add (`broker/pageca/ASSUMPTIONS.md`)

1. The name is fixed per release and the same on every box; the Owner Card prints it (follow-on row).
2. The authority's NotBefore comes from the image's build time, not the clock.
3. [Inference] Browsers treat an unlisted TLD as a public suffix, so `x.internal` and `y.internal` share no cookie scope; qualification shows it.
4. [Inference] iOS and Android enforce the critical name constraint, including the excluded subdomain subtree, on a user-installed authority, and run WebAuthn with an RP ID under `.internal`; qualification shows it, and a platform that fails never gets the authority (CH-9).
5. Interim sealer: the software key file is a stand-in until STO-2; a box shipped with it is not shippable (CH-9 "kept like a sealed-store secret").

## Dependencies

#2779a's brief (merged) for the gate it changes. STO-2 for the real sealer, at ship time only. Slice (b) waits on Mark's answer to the open point. The serial `cmd/agentosd` chain for the agentosd call site.

**Usage estimate:** about 140k tokens for slice (a), single session. Checkpoint at 90k: `pageca` and `certify` green.
