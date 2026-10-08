# P2-2w b: `agentos-localui` command under its own uid

Board section: Backlog refill (2026-10-05).

`agentos-localui` command under its own uid: the page calls agentosd over `localui.sock`, listens on the access point's address only, logs no form field (Security L5); no setup hooks until c, a fixed "not ready" page instead (Security L6 MUST, test every setup route refused); RESUME asks for a code on "code needed" with UX's wording; tries left told only on a signed-in RESUME (Security D1, UX-2wb-2). Carry for P2-1 (Security S1): drop CAP_NET_RAW from the unit if the image's access point allows binding without SO_BINDTODEVICE

**Needs:** P2-2w a

**Gate:** lenses (UX, security)

**State on the board before the 2026-10-08 index split:** in review (#189)
