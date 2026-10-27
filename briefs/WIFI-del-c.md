# WIFI-del-c: the claim sticker and Owner Card name the page by its name

Board section: Identity, onboarding and setup (SPEC §11-12). Work item #3349, a release finding from WIFI-del-a3 (#3350, slice a3 of #3234). D-178: the core runs no access point, so `10.42.0.1` no longer reaches the page. Tier A.

**Depends on a3 (#3350).** a3 serves the page on the core's wired port 1, answering plain HTTP on the page name or the reached address and HTTPS on the page name only. This package uses the page name as a3 uses it, `localui.DefaultPageName` (`agentos.internal`, equal to `pageca.DefaultName`), which is already on main. a3 also drops localui's `TestBoxPageAddressIsShown` check that `card.BoxPage` is the access point address; that check fails on main once `BoxPage` changes, so this PR merges after #3350.

**Design.** The printed link is `https://agentos.internal/`, and the claim QR is `https://agentos.internal/claim?code=CODE`.
- Not plain HTTP: when HTTPS is up, a plain GET on the page name redirects to `https://<name>` plus `safeNext(path)`, which keeps the path only, so a plain claim link would open `/claim` without the code.
- The order holds: §12.1 step 4 has the enforcer's enrolment install the core's certificate (CH-9) before the owner scans the claim QR on the Owner network, and enrollment makes the page authority at first boot (`agentos-enroll`, STO-2c).
- Keeping the query on the redirect instead would change localui's host handling, which a3 owns; no change there is needed.
- `card` keeps the name as its own literal, `card.PageName`, because localui deliberately does not link `pageca` and localui links `card`. A test holds the three names equal. `card.BoxAddr` goes: nothing else uses it.

**Requirement IDs:**
- **HW-10** (§12.1 step 4): the sticker's claim QR and its typed link reach the claim page with the code.
- **HW-1, ONB-7**: the Owner Card and the rotation card print a box page that answers.
- **CH-9**: the page's one name over HTTPS, the name its authority certifies.

**Acceptance tests:**
- HW-1, ONB-7, CH-9: `broker/card/wifidel_test.go::TestCardPrintsThePageByItsName`. `BoxPage` is `https://` + `PageName` + `/`; the Owner Card and the rotation card print it and name no `10.42.0.1` or plain-HTTP box page.
- CH-9: `broker/card/pagename_test.go::TestCardPageNameIsThePageAuthoritysName`. `card.PageName` equals `localui.DefaultPageName` and `pageca.DefaultName`.
- HW-10, CH-9: `broker/cmd/agentos-seller/wifidel_test.go::TestStickerClaimLinkIsThePageName`. The claim link is `https://agentos.internal/claim?code=CODE`; `sticker.html` carries its QR and the typed link, `sticker.txt` the link, and neither names `10.42.0.1`.

**Scope:** `broker/card` (`render.go`, `ASSUMPTIONS.md` C10, `wifidel_test.go`, `pagename_test.go`); `broker/cmd/agentos-seller` (`sticker.go`, `seller_test.go`, `ASSUMPTIONS.md` A8, `wifidel_test.go`). Not in scope: the sticker's step 1 network, which is still the setup network the seller seals rather than the enforcer's (D-178), and the card's Wi-Fi section.

**Gate:** tier A. L3 on the strongest model, and the lens screen. Estimate: under 60k tokens.
