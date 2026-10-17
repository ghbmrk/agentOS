# NG-LUI-defects: Gateway move from an unknown MAC; sign-out failure is shown

Board row: issue #1725 (tier A, class:release). Requirement IDs: DEV-2, CH-7, CH-12.

**Scope:** `broker/netguard/sources.go`, `broker/netguard/sources_test.go`, `broker/netguard/ASSUMPTIONS.md` (N9), `broker/localui/server.go`, a new `broker/localui/signout_test.go`. No other localui file (open builds touch `pages.go`, `setup.go`, `setuphooks.go`; D-111).

**Gate:** tier A: L3 and security lens on the strongest model.

## Defect 1: netguard (DEV-2)
`Sources.Read` compares the gateway MAC across the NAT-PMP wait only when one was known at the start. With no MAC at the start, a swap from router A to router B at the same address and interface files A's answer under B's key, so B's real external address stops being refused.

Fix: a MAC that was empty at the start and known after the wait is a move (ask the end gateway; a second move returns ErrGatewayMoved). B's cached external address stays.

Acceptance test: `TestUnknownStartMACThenRouterSwapKeepsTheEndRoutersAddress`: B's address cached; a read starting with no MAC gets A's answer while the gateway becomes B; B's confirming request times out; the read returns B's cached address and B's quick read still does.

## Defect 2: localui sign-out (CH-7, CH-12)
The `/signout` handler discards the OpSignOut error, clears the cookie and redirects as if signed out, while the session may still be live in agentosd.

Fix: OpSignOut ok, or refused as unauthorized (the token is already dead), clears the cookie and goes to /status. Any other failure keeps the cookie and shows "Sign-out incomplete" with a same-origin POST retry; a retry is idempotent because a revoked token is refused as unauthorized.

Acceptance tests (`broker/localui/signout_test.go`): refusal before dispatch shows incomplete and keeps the cookie; a retry that succeeds clears it; an unauthorized token is signed out; a lost response after the revocation, then a retry, ends signed out.
