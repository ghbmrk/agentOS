# Setup-wifi-rotate: rotate the setup Wi-Fi password at the claim

**Source:** issue #1692 (Mark, 2026-10-14 18:01:33Z, cmsg_01R63S2yrPkq32thy8WQCuvDBG8j9So4uCVzPNt14ZmBL5: "Yes do all this if prudent but don't freeze PRs mid flight so the work is wasted, freeze after completion"). Risk tier A. **Requirements:** HW-10, CH-7, ARC-1, CRED-1.

## Problem

A preloaded box's setup network keeps the sticker's WPA3 password until the Owner Card confirm, so whoever saw the sticker can join, and impersonate, the setup network for the whole of setup.

## Scope

SPEC.md (HW-10, CH-7, ARC-1, §8.1 step 1, risk 26), broker/claim/ (setup network rotation), broker/localui/claim.go, claimwifi.go and server.go (the claim's Wi-Fi step), broker/localapi/setup.go (the page-mode ops), broker/cmd/agentosd/ (the root-side write), broker/cmd/agentos-localui/main.go (wiring), broker/apnet/apnet.go (shared password check), broker/e2e/boxe2e/ (the image run takes the Wi-Fi step after the claim). agentos-ap needs no change: it already restarts the network when the file's password changes.

## Acceptance tests

**Acceptance tests:** HW-10 and CH-7: `broker/localui` `TestTheClaimRotatesTheSetupWiFi`, `TestTheWiFiStepFailsClosed`; `broker/claim` `TestRotateSetupNet`. ARC-1 and CRED-1: `broker/cmd/agentosd` setup Wi-Fi tests (`setupwifi_test.go`). The SPEC wording is checked by Mark's approval.

1. `TestTheClaimRotatesTheSetupWiFi` (localui): the step-1 claim leads to a page with the new password and its Wi-Fi QR, only for the claimant; setup waits; the commit needs the password's last four characters typed back and writes exactly the shown password, once.
2. `TestTheWiFiStepFailsClosed` (localui): only agentosd's "no setup wifi" skips the step; agentosd failing, a missing op, or a failed rotation keeps setup closed; a lost answer reads as done.
3. `TestRotateSetupNet` (claim) and the agentosd setup Wi-Fi tests: the file is rewritten root 0600 with the same name, rotated once.
4. SPEC HW-10 amended with the seller-hardware trust caveat (L1 spec diff, Mark approves wording).

## Checkpoint

20k tokens of brief, finish under 150k; an estimate, not a ceiling.
